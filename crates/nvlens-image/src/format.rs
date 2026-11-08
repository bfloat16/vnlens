//! Image registration and two-stage metadata/pixel decoding.
use crate::{Image, ImageMeta};
use nvlens_core::{Format, Result};

pub trait ImageFormat: Format {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>>;
    fn decode(&self, data: &[u8]) -> Result<Image>;
    /// Counts frames from container metadata without decoding all pixels.
    fn frame_count(&self, _data: &[u8]) -> Result<usize> {
        Ok(1)
    }
    /// Decodes only the requested frame; shared compressed storage may still
    /// require one container-level decompression.
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        if frame != 0 {
            return Err(nvlens_core::Error::Unsupported(
                "Image frame is out of range".into(),
            ));
        }
        self.decode(data)
    }
}
#[derive(Debug)]
pub struct ImageRegistration(pub fn() -> Box<dyn ImageFormat>);
nvlens_core::inventory::collect!(ImageRegistration);

pub fn metadata(data: &[u8]) -> Result<Option<ImageMeta>> {
    for registration in nvlens_core::inventory::iter::<ImageRegistration>() {
        if let Some(meta) = (registration.0)().metadata(data)? {
            return Ok(Some(meta));
        }
    }
    Ok(None)
}
pub fn decode(data: &[u8]) -> Result<Option<Image>> {
    decode_frame(data, 0)
}

pub fn frame_count(data: &[u8]) -> Result<Option<usize>> {
    for registration in nvlens_core::inventory::iter::<ImageRegistration>() {
        let format = (registration.0)();
        if format.metadata(data)?.is_some() {
            return format.frame_count(data).map(Some);
        }
    }
    Ok(None)
}

pub fn decode_frame(data: &[u8], frame: usize) -> Result<Option<Image>> {
    for registration in nvlens_core::inventory::iter::<ImageRegistration>() {
        let format = (registration.0)();
        if format.metadata(data)?.is_some() {
            return format.decode_frame(data, frame).map(Some);
        }
    }
    Ok(None)
}
