//! Independently seekable, incremental audio decoding for movie playback.

use crate::{
    AudioFrame, AudioStream,
    decoder::{EPSILON, Timeline, error, feed, resample},
};
use ffmpeg_next::{
    codec, decoder,
    ffi::AV_TIME_BASE,
    format::{self, context::Input},
    frame, media,
    software::resampling,
    util::error::EAGAIN,
};
use nvlens_core::{Error, Result};
use nvlens_io::ReadAt;
use std::{
    fmt, io,
    sync::{Arc, atomic::AtomicBool},
};

pub struct AudioDecoder {
    input: Input,
    io: crate::input::IoState,
    decoder: decoder::Audio,
    timeline: Timeline,
    meta: AudioStream,
    frame: frame::Audio,
    resampler: Option<resampling::Context>,
    samples: Vec<f32>,
    pending: Option<AudioFrame>,
    target: f64,
    last: f64,
    ended: bool,
}
impl fmt::Debug for AudioDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AudioDecoder")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}
impl AudioDecoder {
    /// Opens a fresh input cursor. No complete audio track is materialized.
    pub fn open(
        source: Arc<dyn ReadAt>,
        name: Option<&str>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        let (input, io) = crate::input::open(source, name, cancelled)?;
        let Some(stream) = input.streams().best(media::Type::Audio) else {
            return Ok(None);
        };
        let mut timeline = Timeline::new(&stream);
        // Both independent decoders use the video's presentation origin.
        if let Some(video) = input.streams().best(media::Type::Video) {
            timeline.start = Timeline::new(&video).start;
        }
        let decoder = codec::Context::from_parameters(stream.parameters())
            .map_err(error)?
            .decoder()
            .audio()
            .map_err(error)?;
        let meta = AudioStream {
            codec: stream.parameters().id().name(),
            channels: decoder.channels(),
            sample_rate: decoder.rate(),
        };
        if meta.channels == 0 || meta.sample_rate == 0 {
            return Err(Error::Unsupported(
                "Audio stream does not declare its output rate/channels".into(),
            ));
        }
        Ok(Some(Self {
            input,
            io,
            decoder,
            timeline,
            meta,
            frame: frame::Audio::empty(),
            resampler: None,
            samples: Vec::new(),
            pending: None,
            target: 0.,
            last: 0.,
            ended: false,
        }))
    }
    #[must_use]
    pub fn meta(&self) -> &AudioStream {
        &self.meta
    }

    /// Seeks and discards PCM before the exact target, including codec preroll.
    pub fn seek(&mut self, seconds: f64) -> Result<()> {
        if !seconds.is_finite() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Audio seek time must be finite",
            )
            .into());
        }
        let seconds = seconds.max(0.);
        let mut lead = 0.;
        loop {
            let start = seconds - lead;
            let timestamp = ((self.timeline.start + start) * f64::from(AV_TIME_BASE)) as i64;
            self.input
                .seek(timestamp, ..timestamp)
                .map_err(|cause| self.io.error(cause))?;
            self.decoder.flush();
            self.resampler = None;
            self.samples.clear();
            self.pending = None;
            self.ended = false;
            self.last = start.max(0.);
            let first = self.decode()?;
            if first
                .as_ref()
                .is_some_and(|frame| frame.time > seconds + EPSILON)
                && start >= -1.
            {
                lead = if lead == 0. { 1. } else { lead * 2. };
                continue;
            }
            self.pending = first;
            self.target = seconds;
            return Ok(());
        }
    }
    /// Produces one packed f32 PCM block, or None after decoder/resampler EOF.
    pub fn next_frame(&mut self) -> Result<Option<AudioFrame>> {
        loop {
            self.io.check()?;
            let frame = match self.pending.take() {
                Some(frame) => Some(frame),
                None => self.decode()?,
            };
            let Some(mut frame) = frame else {
                return Ok(None);
            };
            let channels = usize::from(frame.channels);
            let frames = frame.samples.len() / channels;
            let skip =
                ((self.target - frame.time).max(0.) * f64::from(frame.sample_rate)).ceil() as usize;
            let skip = skip.min(frames);
            if skip == frames {
                continue;
            }
            if skip != 0 {
                frame.samples.drain(..skip * channels);
                frame.time += skip as f64 / f64::from(frame.sample_rate);
            }
            return Ok(Some(frame));
        }
    }
    fn output(&mut self, time: f64) -> AudioFrame {
        let samples = std::mem::take(&mut self.samples);
        self.last = time
            + samples.len() as f64
                / f64::from(self.meta.channels)
                / f64::from(self.meta.sample_rate);
        AudioFrame {
            time,
            channels: self.meta.channels,
            sample_rate: self.meta.sample_rate,
            samples,
        }
    }
    fn decode(&mut self) -> Result<Option<AudioFrame>> {
        loop {
            if self.ended {
                let Some(resampler) = self.resampler.as_mut() else {
                    return Ok(None);
                };
                let delay = resampler.delay().map_or(0, |delay| delay.output.max(0));
                if delay == 0 {
                    return Ok(None);
                }
                let mut output = frame::Audio::new(
                    format::Sample::F32(format::sample::Type::Packed),
                    usize::try_from(delay).map_err(io::Error::other)?,
                    resampler.output().channel_layout,
                );
                resampler.flush(&mut output).map_err(error)?;
                if output.planes() == 0 || output.samples() == 0 {
                    return Ok(None);
                }
                self.samples.extend_from_slice(output.plane::<f32>(0));
                return Ok(Some(self.output(self.last)));
            }
            match self.decoder.receive_frame(&mut self.frame) {
                Ok(()) => {
                    let time = self
                        .frame
                        .timestamp()
                        .map_or(self.last, |timestamp| self.timeline.seconds(timestamp));
                    resample(
                        &mut self.frame,
                        &mut self.resampler,
                        &self.meta,
                        &mut self.samples,
                    )?;
                    if self.samples.is_empty() {
                        continue;
                    }
                    return Ok(Some(self.output(time)));
                }
                Err(ffmpeg_next::Error::Other { errno: EAGAIN }) => feed(
                    &mut self.input,
                    self.timeline.index,
                    &mut self.decoder,
                    &self.io,
                )?,
                Err(ffmpeg_next::Error::Eof) => self.ended = true,
                Err(cause) => return Err(self.io.error(cause)),
            }
        }
    }
}
