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
        let key = match options.keys.get("ystb") {
            Some(key) => Some(<[u8; 4]>::try_from(key.bytes()).map_err(|_| {
                vnlens_core::Error::UnknownScheme(Some("Invalid identified YSTB key".into()))
            })?),
            None => None,
        };
        let name_key = match options.keys.get("ypf_name") {
            Some(key) => match key.bytes() {
                [byte] => Some(*byte),
                _ => {
                    return Err(vnlens_core::Error::UnknownScheme(Some(
                        "Invalid identified YPF name key".into(),
                    )));
                }
            },
            None => None,
        };
        if view.len() < 4 || view.slice(0, 4)? != b"YPF\0" {
            return Err(vnlens_core::Error::InvalidFormat);
        }
        Ok(Box::new(ypf::YpfArchive::open(
            Arc::clone(view),
            key,
            name_key,
            if options.numbers.get("ypf_snappy") == Some(&1) {
                ypf::Compression::ExternalSnappy
            } else {
                ypf::Compression::Zlib
            },
        )?))
    }
}

vnlens_core::register_archive!(YpfArchiveFormat);
