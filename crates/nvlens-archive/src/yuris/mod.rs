//! YU-RIS YPF detection and registration. Payloads are opened independently.

mod ypf;

use nvlens_core::{ArcView, Archive, ArchiveFormat, Format, Result};
use std::sync::Arc;

const SIGNATURES: &[u32] = &[0x0046_5059];

#[derive(Debug, Default)]
struct YpfArchiveFormat;

impl Format for YpfArchiveFormat {
    fn tag(&self) -> &'static str {
        "ypf/yuris"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ypf"]
    }
    fn description(&self) -> &'static str {
        "YU-RIS YPF resource archive"
    }
}

impl ArchiveFormat for YpfArchiveFormat {
    fn open(
        &self,
        view: &Arc<ArcView>,
        options: &nvlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let key = options
            .keys
            .get("ystb")
            .and_then(|key| <[u8; 4]>::try_from(key.bytes()).ok())
            .ok_or_else(|| {
                nvlens_core::Error::UnknownScheme(Some("Missing identified YSTB key".into()))
            })?;
        let name_key = options
            .keys
            .get("ypf_name")
            .and_then(|key| {
                if let [byte] = key.bytes() {
                    Some(*byte)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                nvlens_core::Error::UnknownScheme(Some("Missing identified YPF name key".into()))
            })?;
        if view.len() < 4 || view.slice(0, 4)? != b"YPF\0" {
            return Err(nvlens_core::Error::InvalidFormat);
        }
        Ok(Box::new(ypf::YpfArchive::open(
            Arc::clone(view),
            key,
            name_key,
        )?))
    }
}

nvlens_core::register_archive!(YpfArchiveFormat);
