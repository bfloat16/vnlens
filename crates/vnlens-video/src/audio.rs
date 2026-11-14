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
use std::{
    fmt, io,
    sync::{Arc, atomic::AtomicBool},
};
use vnlens_core::{Error, Result};
use vnlens_io::ReadAt;

pub(super) struct FfmpegAudioDecoder {
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
impl fmt::Debug for FfmpegAudioDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AudioDecoder")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}
impl FfmpegAudioDecoder {
    /// Replays a fresh input cursor when its directed container cannot seek.
    pub(super) fn replay_to(&mut self, seconds: f64, interrupt: &AtomicBool) -> Result<()> {
        self.target = seconds.max(0.0);
        loop {
            if interrupt.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let Some(frame) = self.decode()? else {
                return Ok(());
            };
            if let Some(frame) = trim_frame(frame, self.target) {
                self.pending = Some(frame);
                return Ok(());
            }
        }
    }
    /// Opens a fresh input cursor. No complete audio track is materialized.
    pub fn open(
        source: Arc<dyn ReadAt>,
        name: Option<&str>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        let (input, io) = crate::input::open(source, name, cancelled)?;
        let Some(stream) = input
            .streams()
            .best(media::Type::Audio)
            .filter(|stream| stream.parameters().id() != codec::Id::None)
        else {
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
    pub fn seek_cancellable(&mut self, seconds: f64, interrupt: &AtomicBool) -> Result<()> {
        if interrupt.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let seconds = seconds.max(0.);
        let mut lead = 0.;
        loop {
            if interrupt.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
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
            let Some(frame) = frame else {
                return Ok(None);
            };
            if let Some(frame) = trim_frame(frame, self.target) {
                return Ok(Some(frame));
            }
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

/// An independent audio cursor selected by the movie's explicit format route.
#[derive(Debug)]
pub struct AudioDecoder {
    kind: AudioKind,
}
#[derive(Debug)]
enum AudioKind {
    Ffmpeg(Box<FfmpegAudioDecoder>),
    Criware(Box<crate::criware::UsmAudio>),
    Erisa(Box<ErisaAudio>),
}
struct ErisaAudio {
    source: Arc<dyn ReadAt>,
    decoder: vnlens_middleware::erisa::SoundDecoder,
    meta: AudioStream,
    sections: Vec<vnlens_middleware::erisa::SoundChunk>,
    cursor: usize,
    samples: u64,
    target: f64,
    cancel: Arc<AtomicBool>,
}
impl std::fmt::Debug for ErisaAudio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErisaAudio")
            .field("meta", &self.meta)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}
impl AudioDecoder {
    pub fn open_source_as(
        tag: &str,
        source: Arc<dyn ReadAt>,
        name: Option<&str>,
        cancel: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        if tag == "cri/usm" {
            return crate::criware::UsmAudio::open(source, cancel).map(|audio| {
                audio.map(|audio| Self {
                    kind: AudioKind::Criware(Box::new(audio)),
                })
            });
        }
        if tag != "mei/entisgls" {
            if tag != "ffmpeg"
                && !vnlens_core::inventory::iter::<crate::VideoRegistration>()
                    .any(|r| (r.0)().tag() == tag)
            {
                return Err(Error::Unsupported(format!(
                    "Video audio route is not registered: {tag}"
                )));
            }
            return FfmpegAudioDecoder::open(source, name, cancel).map(|s| {
                s.map(|s| Self {
                    kind: AudioKind::Ffmpeg(Box::new(s)),
                })
            });
        }
        let file = vnlens_middleware::erisa::MediaFile::open(source.as_ref())?;
        let Some(info) = vnlens_middleware::erisa::SoundInfo::read(&file, source.as_ref())? else {
            return Ok(None);
        };
        let meta = AudioStream {
            codec: "mio",
            channels: info.channels,
            sample_rate: info.sample_rate,
        };
        let sections = vnlens_middleware::erisa::sound_chunks(&file, source.as_ref())?;
        let decoder = vnlens_middleware::erisa::SoundDecoder::new(info)?;
        Ok(Some(Self {
            kind: AudioKind::Erisa(Box::new(ErisaAudio {
                source,
                decoder,
                meta,
                sections,
                cursor: 0,
                samples: 0,
                target: 0.0,
                cancel,
            })),
        }))
    }
    #[must_use]
    pub fn meta(&self) -> &AudioStream {
        match &self.kind {
            AudioKind::Ffmpeg(s) => s.meta(),
            AudioKind::Criware(s) => s.meta(),
            AudioKind::Erisa(s) => &s.meta,
        }
    }
    pub fn seek(&mut self, seconds: f64) -> Result<()> {
        self.seek_cancellable(seconds, &AtomicBool::new(false))
    }
    /// Allows a newer transport request to interrupt a nonseekable replay.
    pub fn seek_cancellable(&mut self, seconds: f64, interrupt: &AtomicBool) -> Result<()> {
        if interrupt.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if !seconds.is_finite() {
            return Err(
                vnlens_io::BinaryIo::invalid_input("Audio seek time must be finite").into(),
            );
        }
        match &mut self.kind {
            AudioKind::Ffmpeg(s) => s.seek_cancellable(seconds, interrupt),
            AudioKind::Criware(s) => s.seek_cancellable(seconds, interrupt),
            AudioKind::Erisa(s) => {
                s.target = seconds.max(0.0);
                let target = (s.target * f64::from(s.meta.sample_rate)) as u64;
                s.cursor = s
                    .sections
                    .partition_point(|c| c.first_sample <= target)
                    .saturating_sub(1);
                while s.cursor > 0 && s.sections[s.cursor].flags & 1 == 0 {
                    s.cursor -= 1;
                }
                s.samples = s.sections.get(s.cursor).map_or(0, |c| c.first_sample);
                s.decoder = vnlens_middleware::erisa::SoundDecoder::new(s.decoder.info.clone())?;
                Ok(())
            }
        }
    }
    pub fn next_frame(&mut self) -> Result<Option<AudioFrame>> {
        match &mut self.kind {
            AudioKind::Ffmpeg(s) => s.next_frame(),
            AudioKind::Criware(s) => s.next_frame(),
            AudioKind::Erisa(s) => loop {
                if s.cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let Some(chunk) = s.sections.get(s.cursor) else {
                    return Ok(None);
                };
                let samples = s
                    .decoder
                    .decode(s.source.as_ref(), &chunk.section, &s.cancel)?;
                s.cursor += 1;
                let count = samples.len() / usize::from(s.meta.channels);
                let time = s.samples as f64 / f64::from(s.meta.sample_rate);
                s.samples += count as u64;
                if let Some(frame) = trim_frame(
                    AudioFrame {
                        time,
                        channels: s.meta.channels,
                        sample_rate: s.meta.sample_rate,
                        samples,
                    },
                    s.target,
                ) {
                    return Ok(Some(frame));
                }
            },
        }
    }
}

fn trim_frame(mut frame: AudioFrame, target: f64) -> Option<AudioFrame> {
    let channels = usize::from(frame.channels);
    let frames = frame.samples.len() / channels;
    let skip = ((target - frame.time).max(0.0) * f64::from(frame.sample_rate)).ceil() as usize;
    if skip >= frames {
        return None;
    }
    if skip != 0 {
        frame.samples.drain(..skip * channels);
        frame.time += skip as f64 / f64::from(frame.sample_rate);
    }
    Some(frame)
}
