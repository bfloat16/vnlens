//! MEI movie cursors. Opening reads ERISA section indexes and stream metadata;
//! requested pictures decode from the nearest preceding key frame.
use crate::{
    AudioStream, Picture, VideoDecoder, VideoFormat, VideoMeta, VideoRegistration, VideoStream,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Format, Result};
use vnlens_io::ReadAt;
use vnlens_middleware::erisa::{MediaFile, RasterDecoder, SoundInfo};

#[derive(Debug, Default)]
struct Mei;
impl Format for Mei {
    fn tag(&self) -> &'static str {
        "mei/entisgls"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x6974_6e45]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mei"]
    }
    fn description(&self) -> &'static str {
        "Moving Entis Image movie"
    }
}
impl VideoFormat for Mei {
    fn open(
        &self,
        source: Arc<dyn ReadAt>,
        cancel: Arc<AtomicBool>,
    ) -> Result<Box<dyn VideoDecoder>> {
        let file = MediaFile::open(source.as_ref())?;
        if !file.description.starts_with("Moving Entis Image") {
            return Err(Error::InvalidFormat);
        }
        let image = file
            .image
            .as_ref()
            .ok_or_else(|| bad("MEI has no image metadata"))?;
        let decoder = RasterDecoder::new(&file)?;
        let count = decoder.frame_count();
        if count == 0 {
            return Err(bad("MEI has no image frames"));
        }
        let audio = SoundInfo::read(&file, source.as_ref())?.map(|i| AudioStream {
            codec: "mio",
            channels: i.channels,
            sample_rate: i.sample_rate,
        });
        let duration = f64::from(file.milliseconds) / 1000.0;
        let step = if duration > 0.0 {
            duration / count as f64
        } else {
            0.0
        };
        let meta = VideoMeta {
            container: "mei".into(),
            duration: Some(duration),
            video: VideoStream {
                codec: "eri",
                width: image.width,
                height: image.height,
                frame_rate: (step > 0.0).then_some(1.0 / step),
            },
            audio,
        };
        Ok(Box::new(Movie {
            source,
            decoder,
            meta,
            cursor: 0,
            step,
            cancel,
        }))
    }
}
struct Movie {
    source: Arc<dyn ReadAt>,
    decoder: RasterDecoder,
    meta: VideoMeta,
    cursor: usize,
    step: f64,
    cancel: Arc<AtomicBool>,
}
impl std::fmt::Debug for Movie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Movie")
            .field("meta", &self.meta)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}
impl Movie {
    fn picture(&mut self) -> Result<Option<Picture>> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if self.cursor >= self.decoder.frame_count() {
            return Ok(None);
        }
        let bgra = self
            .decoder
            .decode_at(self.cursor, self.source.as_ref(), &self.cancel)?;
        let picture = Picture {
            time: self.cursor as f64 * self.step,
            width: self.meta.video.width,
            height: self.meta.video.height,
            bgra,
        };
        self.cursor += 1;
        Ok(Some(picture))
    }
}
impl VideoDecoder for Movie {
    fn meta(&self) -> &VideoMeta {
        &self.meta
    }
    fn seek(&mut self, seconds: f64) -> Result<()> {
        self.cursor = if self.step > 0.0 {
            (seconds.max(0.0) / self.step) as usize
        } else {
            0
        }
        .min(self.decoder.frame_count());
        self.decoder.clear();
        Ok(())
    }
    fn next_picture(&mut self) -> Result<Option<Picture>> {
        self.picture()
    }
}
fn bad(reason: &str) -> Error {
    Error::Corrupt {
        offset: 64,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! { VideoRegistration(|| Box::new(Mei)) }

#[cfg(test)]
#[path = "../../tests/entisgls/mod.rs"]
mod tests;
