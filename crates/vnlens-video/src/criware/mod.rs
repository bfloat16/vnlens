//! CRI USM metadata/framing is shared with middleware; FFmpeg handles the
//! directed USM demuxer and standard elementary video/audio codecs.
use crate::{
    AudioFrame, AudioStream, Picture, VideoDecoder, VideoFormat, VideoMeta, VideoRegistration,
    audio::FfmpegAudioDecoder, decoder::FfmpegVideo,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Format, Result};
use vnlens_io::ReadAt;
use vnlens_middleware::criware::usm::{SeekPoint, Usm};

#[derive(Debug, Default)]
struct UsmFormat;
impl Format for UsmFormat {
    fn tag(&self) -> &'static str {
        "cri/usm"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x44495243]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["usm"]
    }
    fn description(&self) -> &'static str {
        "CRIWARE USM movie"
    }
}
impl VideoFormat for UsmFormat {
    fn decode_source(
        &self,
        source: Arc<dyn ReadAt>,
        _: &str,
        _: &ArchiveOptions,
    ) -> Result<Arc<dyn ReadAt>> {
        Usm::open(source.clone())?;
        Ok(source)
    }
    fn open(
        &self,
        source: Arc<dyn ReadAt>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn VideoDecoder>> {
        let usm = Usm::open(source.clone())?;
        let decoder = FfmpegVideo::open(source.clone(), Some("movie.usm"), cancelled.clone())?
            .ok_or(Error::InvalidFormat)?;
        let mut meta = decoder.meta().clone();
        let mut rate = None;
        let mut seek_points = Vec::new();
        if let Some(header) = usm
            .headers
            .iter()
            .find(|h| h.chunk.id == *b"@SFV" && h.chunk.channel == 0 && h.chunk.kind == 1)
        {
            let frames = header.table.number(0, "total_frames")?;
            let numerator = header.table.number(0, "framerate_n")?;
            let denominator = header.table.number(0, "framerate_d")?;
            if let (Some(frames), Some(numerator), Some(denominator)) =
                (frames, numerator, denominator)
                && numerator != 0
                && denominator != 0
            {
                meta.duration = Some(frames as f64 * denominator as f64 / numerator as f64);
                meta.video.frame_rate = Some(numerator as f64 / denominator as f64);
                rate = meta.video.frame_rate;
            }
            // MPEG / H.264 native seek blocks carry the sequence headers or
            // parameter sets needed for independent decoding.
            if rate.is_some() && matches!(header.table.number(0, "mpeg_codec")?, Some(1 | 5)) {
                seek_points = usm.video_seek_points(0)?;
            }
        }
        Ok(Box::new(UsmVideo {
            source,
            cancelled,
            decoder,
            meta,
            rate,
            next_frame: 0,
            usm,
            seek_points,
        }))
    }
}
vnlens_core::inventory::submit! { VideoRegistration(|| Box::new(UsmFormat)) }

struct UsmVideo {
    source: Arc<dyn ReadAt>,
    cancelled: Arc<AtomicBool>,
    decoder: FfmpegVideo,
    meta: VideoMeta,
    rate: Option<f64>,
    next_frame: u64,
    usm: Usm,
    seek_points: Vec<SeekPoint>,
}
impl std::fmt::Debug for UsmVideo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmVideo")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}
impl VideoDecoder for UsmVideo {
    fn meta(&self) -> &VideoMeta {
        &self.meta
    }
    fn seek(&mut self, seconds: f64) -> Result<()> {
        self.seek_cancellable(seconds, &self.cancelled.clone())
    }
    fn seek_cancellable(&mut self, seconds: f64, interrupt: &AtomicBool) -> Result<()> {
        if interrupt.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if !seconds.is_finite() {
            return Err(vnlens_io::BinaryIo::invalid_input("USM seek time must be finite").into());
        }
        let next = self
            .rate
            .map(|rate| (seconds.max(0.) * rate).floor() as u64);
        let point = next.and_then(|next| {
            self.seek_points
                .iter()
                .rev()
                .find(|point| point.frame <= next && point.skip == 0)
        });
        // FFmpeg cannot seek USM itself. Feed it the original metadata and
        // nearest native random-access block, then decode only the remaining
        // presentation frames. With no usable index, retain exact replay.
        let source = if let Some(point) = point {
            self.usm.video_seek_source(0, point.offset)?
        } else {
            self.source.clone()
        };
        let mut decoder = FfmpegVideo::open(source, Some("movie.usm"), self.cancelled.clone())?
            .ok_or(Error::InvalidFormat)?;
        let next = if let Some(next) = next {
            decoder.replay_to_frame(next - point.map_or(0, |point| point.frame), interrupt)?;
            next
        } else {
            decoder.replay_to(seconds, interrupt)?;
            0
        };
        self.next_frame = next;
        self.decoder = decoder;
        Ok(())
    }
    fn next_picture(&mut self) -> Result<Option<Picture>> {
        if let Some(rate) = self.rate {
            // USM declares a fixed presentation cadence. FFmpeg's demuxer can
            // omit or duplicate MPEG picture timestamps (including the final
            // picture); these must not drive the preview's playback clock.
            let picture = self
                .decoder
                .next_picture_at(self.next_frame as f64 / rate)?;
            if picture.is_some() {
                self.next_frame = self.next_frame.checked_add(1).ok_or_else(|| {
                    vnlens_io::BinaryIo::invalid_input("USM frame position overflow")
                })?;
            }
            Ok(picture)
        } else {
            self.decoder.next_picture()
        }
    }
}

pub(super) struct UsmAudio {
    source: Arc<dyn ReadAt>,
    cancelled: Arc<AtomicBool>,
    decoder: FfmpegAudioDecoder,
}
impl std::fmt::Debug for UsmAudio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmAudio")
            .field("decoder", &self.decoder)
            .finish_non_exhaustive()
    }
}
impl UsmAudio {
    pub(super) fn open(
        source: Arc<dyn ReadAt>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        Usm::open(source.clone())?;
        Ok(
            FfmpegAudioDecoder::open(source.clone(), Some("movie.usm"), cancelled.clone())?.map(
                |decoder| Self {
                    source,
                    cancelled,
                    decoder,
                },
            ),
        )
    }
    pub(super) fn meta(&self) -> &AudioStream {
        self.decoder.meta()
    }
    pub(super) fn seek_cancellable(&mut self, seconds: f64, interrupt: &AtomicBool) -> Result<()> {
        if interrupt.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let mut decoder = FfmpegAudioDecoder::open(
            self.source.clone(),
            Some("movie.usm"),
            self.cancelled.clone(),
        )?
        .ok_or(Error::InvalidFormat)?;
        decoder.replay_to(seconds, interrupt)?;
        self.decoder = decoder;
        Ok(())
    }
    pub(super) fn next_frame(&mut self) -> Result<Option<AudioFrame>> {
        self.decoder.next_frame()
    }
}

#[cfg(test)]
#[path = "../../tests/criware/mod.rs"]
mod tests;
