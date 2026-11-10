//! Playback dispatch for registered proprietary video formats and FFmpeg containers.

use crate::{Picture, VideoMeta, decoder::FfmpegVideo};
use nvlens_core::{ArchiveOptions, Error, Format, Result};
use nvlens_io::{BinaryIo, ReadAt};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// An opened video stream cursor.
pub trait VideoDecoder: fmt::Debug {
    #[must_use]
    fn meta(&self) -> &VideoMeta;
    fn seek(&mut self, seconds: f64) -> Result<()>;
    fn next_picture(&mut self) -> Result<Option<Picture>>;
}

/// Domain registration trait for proprietary video formats.
pub trait VideoFormat: Format + Send + Sync {
    /// Opens logical movie bytes for independent picture/audio cursors and export.
    /// Parameters come from engine identification; ordinary formats borrow the source.
    fn decode_source(
        &self,
        source: Arc<dyn ReadAt>,
        _name: &str,
        _options: &ArchiveOptions,
    ) -> Result<Arc<dyn ReadAt>> {
        Ok(source)
    }
    fn open(
        &self,
        source: Arc<dyn ReadAt>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn VideoDecoder>>;
}

#[derive(Debug)]
pub struct VideoRegistration(pub fn() -> Box<dyn VideoFormat>);
nvlens_core::inventory::collect!(VideoRegistration);

/// Removes only the selected format's envelope without reading the full movie.
/// Call once before handing the logical source to video and audio decoders.
pub fn decode_source_as(
    tag: &str,
    source: Arc<dyn ReadAt>,
    name: &str,
    options: &ArchiveOptions,
) -> Result<Arc<dyn ReadAt>> {
    if tag == "ffmpeg" {
        return Ok(source);
    }
    for registration in nvlens_core::inventory::iter::<VideoRegistration> {
        let format = registration.0();
        if format.tag() == tag {
            return format.decode_source(source, name, options);
        }
    }
    Err(Error::Unsupported(format!(
        "Video route is not registered: {tag}"
    )))
}

/// One movie decoder, kept on the thread that owns its FFmpeg scaler.
#[derive(Debug)]
pub struct Video {
    decoder: Box<dyn VideoDecoder>,
    cancelled: Arc<AtomicBool>,
}

impl Video {
    /// Opens exactly the selected format; the token interrupts reads and decode.
    /// Proprietary formats parse only their index here; payloads decode on access.
    /// Returns `Ok(None)` for containers without a video stream, and errors for
    /// damaged or unsupported movies. The optional name is a container hint.
    /// Encrypted formats require the logical source from decode_source_as.
    pub fn open_source_as(
        tag: &str,
        source: Arc<dyn ReadAt>,
        name: Option<&str>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if tag != "ffmpeg" {
            for registration in nvlens_core::inventory::iter::<VideoRegistration> {
                let format = registration.0();
                if format.tag() == tag {
                    return format
                        .open(source, cancelled.clone())
                        .map(|decoder| Some(Self { decoder, cancelled }));
                }
            }
            return Err(Error::Unsupported(format!(
                "Video route is not registered: {tag}"
            )));
        }
        FfmpegVideo::open(source, name, cancelled.clone()).map(|video| {
            video.map(|video| Self {
                decoder: Box::new(video),
                cancelled,
            })
        })
    }

    #[must_use]
    pub fn meta(&self) -> &VideoMeta {
        self.decoder.meta()
    }

    /// Repositions to the picture displayed at `seconds`. Standard containers
    /// seek through their own index; YSMV selects its independently coded frame.
    pub fn seek(&mut self, seconds: f64) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if !seconds.is_finite() {
            return Err(BinaryIo::invalid_input("Video seek time must be finite").into());
        }
        let result = self.decoder.seek(seconds);
        if self.cancelled.load(Ordering::Relaxed) {
            Err(Error::Cancelled)
        } else {
            result
        }
    }

    /// Returns the next tightly packed BGRA picture, or `Ok(None)` at the end.
    /// YSMV pictures retain their decoded JPEG transparency channel.
    pub fn next_picture(&mut self) -> Result<Option<Picture>> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let result = self.decoder.next_picture();
        if self.cancelled.load(Ordering::Relaxed) {
            Err(Error::Cancelled)
        } else {
            result
        }
    }
}
