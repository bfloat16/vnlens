//! FFmpeg-backed demuxing and decoding over independent streaming cursors.
//!
//! StreamIo requests the bytes needed by the demuxer; mapped and transformed
//! archive sources do not require a complete encoded buffer. Pictures use
//! swscale BGRA output; audio conversion is shared with the incremental
//! audio decoder, whose resampler is flushed at EOF.

use crate::{
    VideoDecoder,
    model::{AudioStream, Picture, VideoMeta, VideoStream},
};
use ffmpeg_next::{
    self as ffmpeg, ChannelLayout, Packet, codec, decoder,
    ffi::{AV_NOPTS_VALUE, AV_TIME_BASE},
    format::{self, Pixel, Sample, context::Input},
    frame, media,
    software::{resampling, scaling},
    util::error::EAGAIN,
};
use nvlens_core::{Error, Result};
use nvlens_io::{BinaryIo, ReadAt};
use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// A demuxer and decoder for the best video stream of one resource.
///
/// FFmpeg's scaler is thread-bound, so a decoder stays on the thread that
/// opened it; another decoder uses an independent cursor on the same source.
pub(super) struct FfmpegVideo {
    input: Input,
    io: crate::input::IoState,
    decoder: decoder::Video,
    timeline: Timeline,
    meta: VideoMeta,
    frame: frame::Video,
    scaler: Option<(scaling::Context, frame::Video)>,
    /// The picture shown at this time is the first returned after a seek.
    target: f64,
    /// Frame period, or a minimal one when the stream declares no rate.
    period: f64,
    /// Time of the frame most recently received.
    last: f64,
    /// `frame` holds a picture decoded by `seek` that is not yet returned.
    held: bool,
}

/// Absorbs rounding in timestamp-to-seconds conversion.
pub(super) const EPSILON: f64 = 1e-6;

impl fmt::Debug for FfmpegVideo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfmpegVideo")
            .field("meta", &self.meta)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// Inspects stream metadata in an explicitly routed standard media container.
/// This only distinguishes multiplexed video from audio (for example Ogg);
/// it does not select a proprietary format or probe unrelated resources.
pub fn contains_video(source: Arc<dyn ReadAt>, cancelled: Arc<AtomicBool>) -> Result<bool> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let (input, state) = crate::input::open(source, None, cancelled.clone())?;
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let found = input.streams().best(media::Type::Video).is_some();
    state.check()?;
    Ok(found)
}

impl FfmpegVideo {
    /// Opens the container and the decoders it needs. Returns `Ok(None)` when
    /// the container has no video stream, `Unsupported` when FFmpeg has no
    /// demuxer or decoder for it.
    pub fn open(
        source: Arc<dyn ReadAt>,
        name: Option<&str>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        let (input, io) = crate::input::open(source, name, cancelled)?;
        let Some(stream) = input.streams().best(media::Type::Video) else {
            return Ok(None);
        };
        let timeline = Timeline::new(&stream);
        let mut context = codec::Context::from_parameters(stream.parameters()).map_err(error)?;
        context.set_threading(codec::threading::Config {
            kind: codec::threading::Type::Frame,
            ..Default::default()
        });
        let decoder = context.decoder().video().map_err(error)?;
        let frame_rate = [stream.avg_frame_rate(), stream.rate()]
            .into_iter()
            .find(|rate| rate.numerator() > 0 && rate.denominator() > 0)
            .map(f64::from);
        let duration = Some(input.duration())
            .filter(|&duration| duration > 0)
            .map(|duration| duration as f64 / f64::from(AV_TIME_BASE))
            .or_else(|| {
                Some(stream.duration())
                    .filter(|&duration| duration > 0)
                    .map(|duration| duration as f64 * timeline.base)
            });
        let video = VideoStream {
            codec: stream.parameters().id().name(),
            width: decoder.width(),
            height: decoder.height(),
            frame_rate,
        };
        let audio = match input.streams().best(media::Type::Audio) {
            Some(stream) => {
                let decoder = codec::Context::from_parameters(stream.parameters())
                    .map_err(error)?
                    .decoder()
                    .audio()
                    .map_err(error)?;
                Some(AudioStream {
                    codec: stream.parameters().id().name(),
                    channels: decoder.channels(),
                    sample_rate: decoder.rate(),
                })
            }
            None => None,
        };
        let meta = VideoMeta {
            container: input.format().name().to_owned(),
            duration,
            video,
            audio,
        };
        Ok(Some(Self {
            input,
            io,
            decoder,
            timeline,
            meta,
            frame: frame::Video::empty(),
            scaler: None,
            target: 0.,
            period: frame_rate.map_or(EPSILON * 2., |rate| 1. / rate),
            last: 0.,
            held: false,
        }))
    }

    /// Receives the next frame into `self.frame` and returns its time.
    fn decode_frame(&mut self) -> Result<Option<f64>> {
        loop {
            self.io.check()?;
            match self.decoder.receive_frame(&mut self.frame) {
                Ok(()) => {
                    // Frames without a timestamp keep the previous one.
                    self.last = self
                        .frame
                        .timestamp()
                        .map_or(self.last, |ts| self.timeline.seconds(ts));
                    return Ok(Some(self.last));
                }
                Err(ffmpeg::Error::Other { errno: EAGAIN }) => feed(
                    &mut self.input,
                    self.timeline.index,
                    &mut self.decoder,
                    &self.io,
                )?,
                Err(ffmpeg::Error::Eof) => return Ok(None),
                Err(other) => return Err(self.io.error(other)),
            }
        }
    }
}

impl VideoDecoder for FfmpegVideo {
    fn meta(&self) -> &VideoMeta {
        &self.meta
    }

    /// Repositions so the next picture is the one shown at `seconds`. Times
    /// past the end are rejected by some demuxers; callers clamp to the
    /// duration when one is known.
    ///
    /// Demuxers that search by byte position (MPEG-PS) can land after the
    /// requested time, even when asked for the stream start; the seek then
    /// restarts one second earlier, doubling the lead each time, until the
    /// first decoded frame is not later or the request precedes the stream
    /// by more than a second.
    fn seek(&mut self, seconds: f64) -> Result<()> {
        if !seconds.is_finite() {
            return Err(BinaryIo::invalid_input("Video seek time must be finite").into());
        }
        self.io.check()?;
        let seconds = seconds.max(0.);
        self.target = seconds;
        let mut lead = 0.;
        loop {
            let start = seconds - lead;
            let timestamp = ((self.timeline.start + start) * f64::from(AV_TIME_BASE)) as i64;
            self.input
                .seek(timestamp, ..timestamp)
                .map_err(|cause| self.io.error(cause))?;
            self.decoder.flush();
            self.last = start.max(0.);
            match self.decode_frame()? {
                Some(time) if time > seconds + EPSILON && start >= -1. => {
                    lead = if lead == 0. { 1. } else { lead * 2. };
                }
                held => {
                    self.held = held.is_some();
                    return Ok(());
                }
            }
        }
    }

    /// Decodes the next picture in presentation order; `Ok(None)` at the end.
    fn next_picture(&mut self) -> Result<Option<Picture>> {
        loop {
            let time = if std::mem::take(&mut self.held) {
                self.last
            } else {
                match self.decode_frame()? {
                    Some(time) => time,
                    None => return Ok(None),
                }
            };
            // Skip frames that end before the target after a seek.
            if time + self.period > self.target + EPSILON
                && let Some(picture) = picture(&self.frame, &mut self.scaler, time)?
            {
                return Ok(Some(picture));
            }
        }
    }
}

/// Converts a decoded frame, preserving its dimensions and alpha channel.
pub(super) fn picture(
    frame: &frame::Video,
    scaler: &mut Option<(scaling::Context, frame::Video)>,
    time: f64,
) -> Result<Option<Picture>> {
    let (format, width, height) = (frame.format(), frame.width(), frame.height());
    if width == 0 || height == 0 {
        return Ok(None);
    }
    if scaler.as_ref().is_none_or(|(scaler, _)| {
        let input = scaler.input();
        (input.format, input.width, input.height) != (format, width, height)
    }) {
        let context = scaling::Context::get(
            format,
            width,
            height,
            Pixel::BGRA,
            width,
            height,
            scaling::Flags::BILINEAR,
        )
        .map_err(error)?;
        *scaler = Some((context, frame::Video::empty()));
    }
    let Some((scaler, output)) = scaler else {
        return Ok(None);
    };
    scaler.run(frame, output).map_err(error)?;
    let row = usize::try_from(width).map_err(io::Error::other)? * 4;
    let rows = usize::try_from(height).map_err(io::Error::other)?;
    let stride = output.stride(0);
    if stride < row {
        return Err(io::Error::other("swscale returned a short BGRA row").into());
    }
    let mut bgra = Vec::with_capacity(row * rows);
    for line in output.data(0).chunks(stride).take(rows) {
        bgra.extend_from_slice(
            line.get(..row)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?,
        );
    }
    Ok(Some(Picture {
        time,
        width,
        height,
        bgra,
    }))
}

pub(super) fn resample(
    frame: &mut frame::Audio,
    resampler: &mut Option<resampling::Context>,
    meta: &AudioStream,
    samples: &mut Vec<f32>,
) -> Result<()> {
    if frame.samples() == 0 {
        return Ok(());
    }
    if frame.rate() == 0 {
        return Err(Error::Unsupported(
            "Decoded audio frame has no sample rate".into(),
        ));
    }
    // Decoders may report only a channel count; swresample needs an order.
    if frame.channel_layout().is_empty() {
        frame.set_channel_layout(ChannelLayout::default(i32::from(frame.channels())));
    }
    if resampler.as_ref().is_none_or(|resampler| {
        let input = resampler.input();
        (input.format, &input.channel_layout, input.rate)
            != (frame.format(), &frame.channel_layout(), frame.rate())
    }) {
        *resampler = Some(
            resampling::Context::get(
                frame.format(),
                frame.channel_layout(),
                frame.rate(),
                Sample::F32(format::sample::Type::Packed),
                ChannelLayout::default(i32::from(meta.channels)),
                meta.sample_rate,
            )
            .map_err(error)?,
        );
    }
    let Some(resampler) = resampler else {
        return Ok(());
    };
    let capacity = (frame.samples() as u64)
        .checked_mul(u64::from(meta.sample_rate))
        .ok_or_else(|| io::Error::other("PCM resampling size overflow"))?
        .div_ceil(u64::from(frame.rate()));
    let capacity = capacity
        .checked_add(
            resampler
                .delay()
                .map_or(0, |delay| delay.output.max(0) as u64),
        )
        .ok_or_else(|| io::Error::other("PCM resampling size overflow"))?;
    let mut output = frame::Audio::new(
        Sample::F32(format::sample::Type::Packed),
        usize::try_from(capacity).map_err(io::Error::other)?,
        resampler.output().channel_layout,
    );
    resampler.run(frame, &mut output).map_err(error)?;
    if output.planes() > 0 {
        samples.extend_from_slice(output.plane::<f32>(0));
    }
    Ok(())
}

/// Sends the next packet of stream `index`, or end of stream after the last.
/// Damaged packets are skipped as FFmpeg's own players do.
pub(super) fn feed(
    input: &mut Input,
    index: usize,
    decoder: &mut decoder::Opened,
    state: &crate::input::IoState,
) -> Result<()> {
    loop {
        state.check()?;
        let mut packet = Packet::empty();
        match packet.read(input) {
            Ok(()) if packet.stream() == index => match decoder.send_packet(&packet) {
                Err(ffmpeg::Error::InvalidData) => {
                    tracing::warn!(stream = index, "Skipping an undecodable packet");
                }
                result => return result.map_err(|cause| state.error(cause)),
            },
            // The demuxer resynchronizes after invalid data.
            Ok(()) | Err(ffmpeg::Error::InvalidData) => {}
            Err(ffmpeg::Error::Eof) => {
                state.check()?;
                return decoder.send_eof().map_err(|cause| state.error(cause));
            }
            Err(other) => return Err(state.error(other)),
        }
    }
}

/// Maps stream timestamps to seconds from the stream's first presentation.
#[derive(Clone, Copy, Debug)]
pub(super) struct Timeline {
    pub index: usize,
    pub base: f64,
    /// Stream start in seconds on the container timeline.
    pub start: f64,
}
impl Timeline {
    pub fn new(stream: &format::stream::Stream<'_>) -> Self {
        let base = f64::from(stream.time_base());
        let start = Some(stream.start_time()).filter(|&start| start != AV_NOPTS_VALUE);
        Self {
            index: stream.index(),
            base,
            start: start.map_or(0., |start| start as f64 * base),
        }
    }
    pub fn seconds(&self, timestamp: i64) -> f64 {
        timestamp as f64 * self.base - self.start
    }
}

pub(super) fn error(error: ffmpeg::Error) -> Error {
    match error {
        ffmpeg::Error::DecoderNotFound
        | ffmpeg::Error::DemuxerNotFound
        | ffmpeg::Error::StreamNotFound => Error::Unsupported(format!("FFmpeg: {error}")),
        ffmpeg::Error::Exit => Error::Cancelled,
        ffmpeg::Error::InvalidData => io::Error::new(io::ErrorKind::InvalidData, error).into(),
        other => io::Error::other(other).into(),
    }
}

#[cfg(test)]
use crate::{AudioDecoder, Video};

#[cfg(test)]
#[path = "../tests/decoder.rs"]
mod tests;
