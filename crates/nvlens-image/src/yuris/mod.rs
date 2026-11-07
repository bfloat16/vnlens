//! YU-RIS image recognition.
mod ycg;
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration};
use nvlens_core::{Error, Format, Result};
const SIGNATURES: &[u32] = &[0x0047_4359];
#[derive(Debug, Default)]
pub struct YcgImage;
impl Format for YcgImage {
    fn tag(&self) -> &'static str {
        "ycg/yuris"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ycg"]
    }
    fn description(&self) -> &'static str {
        "YU-RIS YCG image"
    }
}
impl ImageFormat for YcgImage {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !data.starts_with(b"YCG\0") {
            return Ok(None);
        }
        Ok(Some(ycg::metadata(data)?))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        if !data.starts_with(b"YCG\0") {
            return Err(Error::InvalidFormat);
        }
        ycg::decode(data)
    }
}
nvlens_core::inventory::submit! {ImageRegistration(||Box::new(YcgImage))}
