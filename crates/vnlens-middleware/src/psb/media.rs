//! PSB texture/sound metadata describes raw chunks. On access, lossless DDS
//! and RIFF xWMA headers make those chunks usable by their corresponding domains.
//! BC7 follows DXGI_FORMAT_BC7_UNORM; xWMA retains fmt, dpds and encoded data.
mod canvas;
use super::{ParseOptions, Psb, PsbResource, PsbValue, check_cancelled};
pub(super) use canvas::{Canvas, entries as canvases};
use std::collections::BTreeMap;
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryWriter, ReadAt};
#[derive(Clone, Debug)]
pub(super) enum Encoding {
    Canvas(Canvas),
    Bc7 {
        width: u32,
        height: u32,
    },
    Xwma {
        format: PsbResource,
        dpds: PsbResource,
    },
}
impl Encoding {
    pub(super) fn extension(&self) -> &'static str {
        match self {
            Self::Bc7 { .. } | Self::Canvas(_) => "dds",
            Self::Xwma { .. } => "xwma",
        }
    }
    pub(super) fn wrap(&self, source: &dyn ReadAt, raw: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Canvas(canvas) => canvas.wrap(source),
            Self::Bc7 { width, height } => {
                let expected = bc7_size(*width, *height)?;
                if raw.len() as u64 != expected {
                    return Err(bad("PSB BC7 payload does not match dimensions"));
                }
                let mut bytes = vec![0; 148];
                bytes[..4].copy_from_slice(b"DDS ");
                for (offset, value) in [
                    (4, 124),
                    (8, 0x81007),
                    (12, *height),
                    (16, *width),
                    (
                        20,
                        u32::try_from(expected)
                            .map_err(|_| bad("DDS surface exceeds its size field"))?,
                    ),
                    (76, 32),
                    (80, 4),
                    (108, 0x1000),
                    (128, 98),
                    (132, 3),
                    (140, 1),
                ] {
                    BinaryWriter::u32_le(value, &mut bytes[offset..]);
                }
                bytes[84..88].copy_from_slice(b"DX10");
                bytes.extend_from_slice(raw);
                Ok(bytes)
            }
            Self::Xwma { format, dpds } => {
                let mut bytes = b"RIFF\0\0\0\0XWMA".to_vec();
                for (name, part) in [(b"fmt ", format), (b"dpds", dpds)] {
                    let size = usize::try_from(part.size)
                        .map_err(|_| bad("PSB sound chunk exceeds address space"))?;
                    chunk(&mut bytes, name, &source.read_at(part.offset, size)?)?;
                }
                chunk(&mut bytes, b"data", raw)?;
                let size = u32::try_from(bytes.len() - 8)
                    .map_err(|_| bad("xWMA exceeds its RIFF size field"))?;
                BinaryWriter::u32_le(size, &mut bytes[4..]);
                Ok(bytes)
            }
        }
    }
}
fn bc7_size(width: u32, height: u32) -> Result<u64> {
    u64::from(width.div_ceil(4))
        .checked_mul(u64::from(height.div_ceil(4)))
        .and_then(|blocks| blocks.checked_mul(16))
        .ok_or_else(|| bad("BC7 surface size overflow"))
}

fn chunk(out: &mut Vec<u8>, name: &[u8; 4], data: &[u8]) -> Result<()> {
    out.extend(name);
    let mut length = [0; 4];
    BinaryWriter::u32_le(
        u32::try_from(data.len()).map_err(|_| bad("RIFF chunk exceeds its size field"))?,
        &mut length,
    );
    out.extend(length);
    out.extend_from_slice(data);
    if !data.len().is_multiple_of(2) {
        out.push(0);
    }
    Ok(())
}
fn bad(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
fn resource<'a>(psb: &'a Psb, value: &PsbValue) -> Option<&'a PsbResource> {
    let PsbValue::Resource { index, is_extra } = value else {
        return None;
    };
    if *is_extra {
        &psb.extra_resources
    } else {
        &psb.resources
    }
    .get(*index as usize)
}
pub(super) fn encodings(
    psb: &Psb,
    options: ParseOptions<'_>,
) -> Result<BTreeMap<(u32, bool), Encoding>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![&psb.root];
    while let Some(value) = pending.pop() {
        check_cancelled(options)?;
        match value {
            PsbValue::Object(object) => {
                if object.get("type").and_then(PsbValue::as_str) == Some("BC7")
                    && let Some(pixel) = object.get("pixel").and_then(|v| resource(psb, v))
                {
                    let dimension = |name| {
                        object
                            .get(name)
                            .and_then(PsbValue::as_i64)
                            .and_then(|v| u32::try_from(v).ok())
                            .filter(|&v| v != 0)
                            .ok_or_else(|| bad("Invalid PSB texture dimension"))
                    };
                    result.insert(
                        (pixel.index, pixel.is_extra),
                        Encoding::Bc7 {
                            width: dimension("width")?,
                            height: dimension("height")?,
                        },
                    );
                }
                if let (Some(data), Some(format), Some(dpds)) = (
                    object.get("data").and_then(|v| resource(psb, v)),
                    object.get("fmt").and_then(|v| resource(psb, v)),
                    object.get("dpds").and_then(|v| resource(psb, v)),
                ) {
                    result.insert(
                        (data.index, data.is_extra),
                        Encoding::Xwma {
                            format: format.clone(),
                            dpds: dpds.clone(),
                        },
                    );
                }
                pending.extend(object.values());
            }
            PsbValue::List(values) => pending.extend(values),
            _ => {}
        }
    }
    Ok(result)
}
