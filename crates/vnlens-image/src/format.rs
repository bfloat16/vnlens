//! Image registration and two-stage metadata/pixel decoding.
use crate::{Image, ImageMeta};
use vnlens_core::{Error, Format, ResourceResolver, Result};

pub trait ImageFormat: Format {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>>;
    fn decode(&self, data: &[u8]) -> Result<Image>;
    /// Resolves referenced base images only when the selected image needs them.
    fn decode_with_resources(
        &self,
        data: &[u8],
        _resources: Option<&dyn ResourceResolver>,
    ) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    /// Counts frames from container metadata without decoding all pixels.
    fn frame_count(&self, _data: &[u8]) -> Result<usize> {
        Ok(1)
    }
    /// Decodes only the requested frame; shared compressed storage may still
    /// require one container-level decompression.
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        if frame != 0 {
            return Err(vnlens_core::Error::Unsupported(
                "Image frame is out of range".into(),
            ));
        }
        self.decode(data)
    }
}
#[derive(Debug)]
pub struct ImageRegistration(pub fn() -> Box<dyn ImageFormat>);
vnlens_core::inventory::collect!(ImageRegistration);

fn selected(tag: &str) -> Result<Box<dyn ImageFormat>> {
    for registration in vnlens_core::inventory::iter::<ImageRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return Ok(format);
        }
    }
    Err(Error::Unsupported(format!(
        "Image route is not registered: {tag}"
    )))
}
/// Reads metadata using exactly the selected format; never probes another reader.
pub fn metadata_as(tag: &str, data: &[u8]) -> Result<Option<ImageMeta>> {
    selected(tag)?.metadata(data)
}
pub fn decode_as(tag: &str, data: &[u8]) -> Result<Image> {
    decode_frame_as(tag, data, 0)
}
pub fn decode_with_resources_as(
    tag: &str,
    data: &[u8],
    resources: Option<&dyn ResourceResolver>,
) -> Result<Image> {
    selected(tag)?.decode_with_resources(data, resources)
}
pub fn frame_count_as(tag: &str, data: &[u8]) -> Result<usize> {
    selected(tag)?.frame_count(data)
}
pub fn decode_frame_as(tag: &str, data: &[u8], frame: usize) -> Result<Image> {
    selected(tag)?.decode_frame(data, frame)
}
