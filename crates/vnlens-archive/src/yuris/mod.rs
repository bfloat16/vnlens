//! YU-RIS YPF detection and registration. Payloads are opened independently.

mod stream;
mod ypf;

use std::sync::Arc;
use vnlens_core::{ArcView, Archive, ArchiveFormat, Format, Result};

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
        options: &vnlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let key = options
            .keys
            .get("ystb")
            .and_then(|key| <[u8; 4]>::try_from(key.bytes()).ok())
            .ok_or_else(|| {
                vnlens_core::Error::UnknownScheme(Some("Missing identified YSTB key".into()))
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
                vnlens_core::Error::UnknownScheme(Some("Missing identified YPF name key".into()))
            })?;
        if view.len() < 4 || view.slice(0, 4)? != b"YPF\0" {
            return Err(vnlens_core::Error::InvalidFormat);
        }
        Ok(Box::new(ypf::YpfArchive::open(
            Arc::clone(view),
            key,
            name_key,
        )?))
    }
}

vnlens_core::register_archive!(YpfArchiveFormat);
