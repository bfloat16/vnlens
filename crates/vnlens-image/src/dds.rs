//! Microsoft DDS_HEADER/DDS_HEADER_DXT10, little endian. Supports BC1/2/3/7
//! and byte RGBA/BGRA surfaces. Native mip chains, array items, cube faces and
//! volume slices are exposed as frames in storage order, without discarding
//! the original DDS bytes. Tamlib's DDS arrays require no pixel conversion.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Format, Result};
use vnlens_io::{BinaryIo, BinaryReader, BinaryWriter};

#[derive(Debug, Default)]
struct Dds;
impl Format for Dds {
    fn tag(&self) -> &'static str {
        "dds"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x2053_4444]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dds"]
    }
    fn description(&self) -> &'static str {
        "DDS textures"
    }
}
impl ImageFormat for Dds {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !data.starts_with(b"DDS ") {
            return Ok(None);
        }
        Ok(Some(
            layout(data)?
                .surfaces
                .first()
                .ok_or(Error::InvalidFormat)?
                .meta
                .clone(),
        ))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        Ok(layout(data)?.surfaces.len())
    }
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        let layout = layout(data)?;
        let surface = layout
            .surfaces
            .get(frame)
            .ok_or_else(|| Error::Unsupported("DDS frame is out of range".into()))?;
        let meta = surface.meta.clone();
        let bytes = data
            .get(surface.offset..surface.offset + surface.size)
            .ok_or_else(|| BinaryIo::unexpected_eof("Truncated DDS surface"))?;
        let mut output = vec![0; meta.rgba_size()?];
        match layout.encoding {
            Encoding::Bytes { bgra, opaque } => {
                let row = meta.width as usize * 4;
                for (src, dst) in bytes
                    .chunks_exact(surface.pitch)
                    .zip(output.chunks_exact_mut(row))
                {
                    dst.copy_from_slice(&src[..row]);
                    if bgra {
                        crate::swap_red_blue(dst);
                    }
                    if opaque {
                        for pixel in dst.as_chunks_mut::<4>().0 {
                            pixel[3] = 255;
                        }
                    }
                }
                return Ok(Image {
                    meta,
                    pixels: PixelBuffer::Rgba8(output),
                });
            }
            encoding => {
                if matches!(encoding, Encoding::Bc7)
                    && bytes.as_chunks::<16>().0.iter().any(|b| b[0] == 0)
                {
                    return Err(bad(surface.offset, "Invalid BC7 mode"));
                }
                let mut pixels = vec![0; output.len() / 4];
                let width = meta.width as usize;
                let height = meta.height as usize;
                match encoding {
                    Encoding::Bc1 => {
                        texture2ddecoder::decode_bc1a(bytes, width, height, &mut pixels)
                    }
                    Encoding::Bc2 => {
                        texture2ddecoder::decode_bc2(bytes, width, height, &mut pixels)
                    }
                    Encoding::Bc3 => {
                        texture2ddecoder::decode_bc3(bytes, width, height, &mut pixels)
                    }
                    Encoding::Bc7 => {
                        texture2ddecoder::decode_bc7(bytes, width, height, &mut pixels)
                    }
                    Encoding::Bytes { .. } => return Err(Error::InvalidFormat),
                }
                .map_err(|reason| bad(surface.offset, reason))?;
                for (pixel, out) in pixels.into_iter().zip(output.as_chunks_mut::<4>().0) {
                    BinaryWriter::u32_le(pixel, out);
                }
            }
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(output),
        })
    }
}

#[derive(Clone, Copy)]
enum Encoding {
    Bc1,
    Bc2,
    Bc3,
    Bc7,
    Bytes { bgra: bool, opaque: bool },
}
struct Surface {
    meta: ImageMeta,
    offset: usize,
    size: usize,
    pitch: usize,
}
struct Layout {
    encoding: Encoding,
    surfaces: Vec<Surface>,
}

fn layout(data: &[u8]) -> Result<Layout> {
    let mut reader = BinaryReader::new(data);
    let h = reader.read_bytes(128)?;
    if &h[..4] != b"DDS " {
        return Err(Error::InvalidFormat);
    }
    if BinaryReader::u32_le(&h[4..]) != 124 || BinaryReader::u32_le(&h[76..]) != 32 {
        return Err(bad(4, "Invalid DDS header size"));
    }
    let width = BinaryReader::u32_le(&h[16..]);
    let height = BinaryReader::u32_le(&h[12..]);
    if width == 0 || height == 0 {
        return Err(bad(12, "Empty DDS dimensions"));
    }
    let caps2 = BinaryReader::u32_le(&h[112..]);
    let mut depth = if caps2 & 0x20_0000 != 0 {
        BinaryReader::u32_le(&h[24..])
    } else {
        1
    };
    let mut faces = if caps2 & 0x200 != 0 {
        (caps2 & 0xfc00).count_ones()
    } else {
        1
    };
    let mut items = 1;
    let mut offset = 128u64;
    let fourcc = BinaryReader::u32_le(&h[84..]);
    let encoding = if fourcc == 0x3031_5844 {
        let dx = reader.read_bytes(20)?;
        offset = 148;
        let format = BinaryReader::u32_le(dx);
        let dimension = BinaryReader::u32_le(&dx[4..]);
        items = BinaryReader::u32_le(&dx[12..]);
        match dimension {
            2 if height == 1 => {
                depth = 1;
                faces = 1;
            }
            3 => {
                depth = 1;
                faces = if BinaryReader::u32_le(&dx[8..]) & 4 != 0 {
                    6
                } else {
                    1
                };
            }
            4 if items == 1 => {
                depth = BinaryReader::u32_le(&h[24..]);
                faces = 1;
            }
            _ => return Err(Error::Unsupported("DDS resource dimension".into())),
        }
        match format {
            71 | 72 => Encoding::Bc1,
            74 | 75 => Encoding::Bc2,
            77 | 78 => Encoding::Bc3,
            98 | 99 => Encoding::Bc7,
            28 | 29 => Encoding::Bytes {
                bgra: false,
                opaque: false,
            },
            87 | 91 => Encoding::Bytes {
                bgra: true,
                opaque: false,
            },
            88 | 93 => Encoding::Bytes {
                bgra: true,
                opaque: true,
            },
            _ => return Err(Error::Unsupported(format!("DDS DXGI format {format}"))),
        }
    } else {
        match fourcc {
            0x3154_5844 => Encoding::Bc1,
            0x3354_5844 => Encoding::Bc2,
            0x3554_5844 => Encoding::Bc3,
            0 if BinaryReader::u32_le(&h[88..]) == 32
                && BinaryReader::u32_le(&h[96..]) == 0xff00 =>
            {
                let masks = [
                    BinaryReader::u32_le(&h[92..]),
                    BinaryReader::u32_le(&h[100..]),
                ];
                let bgra = match masks {
                    [0xff, 0xff0000] => false,
                    [0xff0000, 0xff] => true,
                    _ => return Err(Error::Unsupported("DDS channel masks".into())),
                };
                let alpha = BinaryReader::u32_le(&h[104..]);
                if !matches!(alpha, 0 | 0xff00_0000) {
                    return Err(Error::Unsupported("DDS alpha mask".into()));
                }
                Encoding::Bytes {
                    bgra,
                    opaque: alpha == 0,
                }
            }
            _ => return Err(Error::Unsupported(format!("DDS FourCC 0x{fourcc:08x}"))),
        }
    };
    if depth == 0 || faces == 0 || items == 0 {
        return Err(bad(24, "Empty DDS resource"));
    }
    let levels = BinaryReader::u32_le(&h[28..]).max(1);
    let max_levels = 32 - width.max(height).max(depth).leading_zeros();
    if levels > max_levels {
        return Err(bad(28, "DDS mip count exceeds dimensions"));
    }
    let mut surfaces = Vec::new();
    for _ in 0..u64::from(items) * u64::from(faces) {
        let (mut w, mut hgt, mut d) = (width, height, depth);
        for level in 0..levels {
            let (pitch, rows) = match encoding {
                Encoding::Bytes { .. } => {
                    let row = u64::from(w) * 4;
                    let pitch = if level == 0 && BinaryReader::u32_le(&h[8..]) & 8 != 0 {
                        u64::from(BinaryReader::u32_le(&h[20..]))
                    } else {
                        row
                    };
                    if pitch < row {
                        return Err(bad(20, "DDS row pitch is shorter than width"));
                    }
                    (pitch, u64::from(hgt))
                }
                Encoding::Bc1 => (u64::from(w.div_ceil(4)) * 8, u64::from(hgt.div_ceil(4))),
                _ => (u64::from(w.div_ceil(4)) * 16, u64::from(hgt.div_ceil(4))),
            };
            let size = pitch
                .checked_mul(rows)
                .ok_or_else(|| bad(20, "DDS surface size overflow"))?;
            for _ in 0..d {
                let end = offset
                    .checked_add(size)
                    .ok_or_else(|| bad(20, "DDS surface offset overflow"))?;
                if end > data.len() as u64 {
                    return Err(BinaryIo::unexpected_eof("Truncated DDS surface").into());
                }
                surfaces.push(Surface {
                    meta: ImageMeta {
                        width: w,
                        height: hgt,
                        bpp: 32,
                        offset_x: 0,
                        offset_y: 0,
                        offset_unit: OffsetUnit::Pixels,
                    },
                    offset: usize::try_from(offset)
                        .map_err(|_| bad(20, "DDS offset exceeds address space"))?,
                    size: usize::try_from(size)
                        .map_err(|_| bad(20, "DDS size exceeds address space"))?,
                    pitch: usize::try_from(pitch)
                        .map_err(|_| bad(20, "DDS pitch exceeds address space"))?,
                });
                offset = end;
            }
            w = (w / 2).max(1);
            hgt = (hgt / 2).max(1);
            d = (d / 2).max(1);
        }
    }
    if offset != data.len() as u64 {
        return Err(bad(offset as usize, "DDS surface length mismatch"));
    }
    Ok(Layout { encoding, surfaces })
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Dds)) }

#[cfg(test)]
#[path = "../tests/dds.rs"]
mod tests;
