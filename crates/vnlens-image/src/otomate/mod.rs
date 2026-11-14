//! TID texture arrays. Otomate sub_19C130/sub_19CC00/sub_19CED0 define
//! frame counts, dimensions and absolute data offsets. Flag bit 0 selects
//! big-endian headers; bit 7 selects 0x60-byte extended frame descriptors
//! at the +0x14 offset instead of classic 0x40-byte descriptors at +0x20.
//! Extended descriptors use DDS pixel-format flags and FourCC values.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Format, Result};
use vnlens_io::{BinaryIo, BinaryWriter, Endian};

const SIGNATURES: &[u32] = &[0x9044_4954, 0x9144_4954];

#[derive(Debug, Default)]
struct Tid;
impl Format for Tid {
    fn tag(&self) -> &'static str {
        "tid/otomate"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tid"]
    }
    fn description(&self) -> &'static str {
        "Otomate TID textures"
    }
}
impl ImageFormat for Tid {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        Ok(Some(frame(data, 0)?.meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        Ok(layout(data)?.count)
    }
    fn decode_frame(&self, data: &[u8], index: usize) -> Result<Image> {
        let frame = frame(data, index)?;
        let meta = frame.meta;
        let block_size = match frame.fourcc {
            0x3154_5844 => 8,
            0x3254_5844 | 0x3354_5844 | 0x3454_5844 | 0x3554_5844 => 16,
            _ => {
                return Err(Error::Unsupported(format!(
                    "Unsupported TID pixel format 0x{:08x}",
                    frame.fourcc
                )));
            }
        };
        let size = u64::from(meta.width.div_ceil(4))
            .checked_mul(u64::from(meta.height.div_ceil(4)))
            .and_then(|n| n.checked_mul(block_size))
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| bad(frame.offset, "TID surface exceeds address space"))?;
        if size > frame.size {
            return Err(BinaryIo::unexpected_eof("TID surface exceeds stored frame").into());
        }
        let blocks = bytes(data, frame.offset, size)?;
        let width = usize::try_from(meta.width)
            .map_err(|_| bad(frame.offset, "TID width exceeds address space"))?;
        let height = usize::try_from(meta.height)
            .map_err(|_| bad(frame.offset, "TID height exceeds address space"))?;
        let mut pixels = vec![0; meta.rgba_size()? / 4];
        match frame.fourcc {
            0x3154_5844 => texture2ddecoder::decode_bc1a(blocks, width, height, &mut pixels),
            0x3254_5844 | 0x3354_5844 => {
                texture2ddecoder::decode_bc2(blocks, width, height, &mut pixels)
            }
            _ => texture2ddecoder::decode_bc3(blocks, width, height, &mut pixels),
        }
        .map_err(|reason| bad(frame.offset, reason))?;
        let mut output = vec![0; meta.rgba_size()?];
        for (pixel, out) in pixels.into_iter().zip(output.as_chunks_mut::<4>().0) {
            BinaryWriter::u32_le(pixel, out);
            // DXT2/DXT4 store premultiplied color, whereas the image model
            // and PNG export use straight alpha.
            if matches!(frame.fourcc, 0x3254_5844 | 0x3454_5844) && out[3] != 0 {
                for channel in 0..3 {
                    out[channel] = ((u32::from(out[channel]) * 255 + u32::from(out[3]) / 2)
                        / u32::from(out[3]))
                    .min(255) as u8;
                }
            }
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(output),
        })
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Tid)) }

#[derive(Debug)]
struct Layout {
    endian: Endian,
    count: usize,
    table: usize,
    stride: usize,
    extended: bool,
}
fn layout(data: &[u8]) -> Result<Layout> {
    let header = bytes(data, 0, 0x20)?;
    if &header[..3] != b"TID" {
        return Err(Error::InvalidFormat);
    }
    let endian = if header[3] & 1 != 0 {
        Endian::Big
    } else {
        Endian::Little
    };
    let count = endian.read_u32(&header[0xc..]).max(1) as usize;
    let extended = header[3] & 0x80 != 0;
    let (table, stride) = if extended {
        (endian.read_u32(&header[0x14..]) as usize, 0x60usize)
    } else {
        (0x20, 0x40usize)
    };
    bytes(
        data,
        table,
        count
            .checked_mul(stride)
            .ok_or_else(|| bad(0xc, "TID frame table overflow"))?,
    )?;
    Ok(Layout {
        endian,
        count,
        table,
        stride,
        extended,
    })
}
#[derive(Debug)]
struct Frame {
    meta: ImageMeta,
    offset: usize,
    size: usize,
    fourcc: u32,
}
fn frame(data: &[u8], index: usize) -> Result<Frame> {
    let layout = layout(data)?;
    if index >= layout.count {
        return Err(Error::Unsupported("TID frame is out of range".into()));
    }
    let at = layout.table + index * layout.stride;
    let row = bytes(data, at, layout.stride)?;
    let start = if layout.extended { 0x24 } else { 0x14 };
    let width = layout.endian.read_u32(&row[start..]);
    let height = layout.endian.read_u32(&row[start + 4..]);
    if width == 0 || height == 0 {
        return Err(bad(at + start, "Empty TID dimensions"));
    }
    let size = layout.endian.read_u32(&row[start + 0x14..]) as usize;
    let offset = layout.endian.read_u32(&row[start + 0x18..]) as usize;
    bytes(data, offset, size)?;
    let fourcc = if layout.extended && layout.endian.read_u32(&row[0x40..]) & 4 != 0 {
        layout.endian.read_u32(&row[0x44..])
    } else {
        0
    };
    Ok(Frame {
        meta: ImageMeta {
            width,
            height,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        },
        offset,
        size,
        fourcc,
    })
}
fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| bad(offset, "TID range overflow"))?;
    data.get(offset..end)
        .ok_or_else(|| BinaryIo::unexpected_eof("TID range exceeds source").into())
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/otomate/mod.rs"]
mod tests;
