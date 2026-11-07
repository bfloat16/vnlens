//! Image registration and two-stage metadata/pixel decoding.
use crate::{Image, ImageMeta};
use nvlens_core::{Format, Result};

pub trait ImageFormat: Format {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>>;
    fn decode(&self, data: &[u8]) -> Result<Image>;
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
    for registration in nvlens_core::inventory::iter::<ImageRegistration>() {
        let format = (registration.0)();
        if format.metadata(data)?.is_some() {
            return format.decode(data).map(Some);
        }
    }
    Ok(None)
}
