//! DDS_HEADER/DDS_HEADER_DXT10 single-surface BC7 textures (DXGI 98/99).
//! M2 stores these BC7 blocks as PSB chunks; the archive supplies their DDS
//! framing from the PSB dimensions without decoding pixels during mounting.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Format, Result};
use vnlens_io::{BinaryReader, BinaryWriter};
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
        "DDS BC7 texture"
    }
}
impl ImageFormat for Dds {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !data.starts_with(b"DDS ") {
            return Ok(None);
        }
        let mut reader = BinaryReader::new(data);
        let header = reader.read_bytes(148)?;
        if BinaryReader::u32_le(&header[4..]) != 124 || BinaryReader::u32_le(&header[76..]) != 32 {
            return Err(bad(4, "Invalid DDS header size"));
        }
        if &header[84..88] != b"DX10"
            || !matches!(BinaryReader::u32_le(&header[128..]), 98 | 99)
            || BinaryReader::u32_le(&header[132..]) != 3
            || BinaryReader::u32_le(&header[140..]) != 1
            || BinaryReader::u32_le(&header[136..]) & 4 != 0
            || BinaryReader::u32_le(&header[28..]) > 1
        {
            return Err(Error::Unsupported(
                "DDS layout requires a single BC7 texture".into(),
            ));
        }
        let width = BinaryReader::u32_le(&header[16..]);
        let height = BinaryReader::u32_le(&header[12..]);
        if width == 0 || height == 0 {
            return Err(bad(12, "Empty DDS dimensions"));
        }
        Ok(Some(ImageMeta {
            width,
            height,
            bpp: 32,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
        }))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        let size = meta.rgba_size()?;
        let expected = u64::from(meta.width.div_ceil(4)) * u64::from(meta.height.div_ceil(4)) * 16;
        let blocks = &data[148..];
        if blocks.len() as u64 != expected {
            return Err(bad(148, "DDS BC7 surface length mismatch"));
        }
        if let Some(index) = blocks
            .as_chunks::<16>()
            .0
            .iter()
            .position(|block| block[0] == 0)
        {
            return Err(bad(148 + index * 16, "Invalid BC7 mode"));
        }
        let mut words = vec![0; size / 4];
        texture2ddecoder::decode_bc7(
            blocks,
            meta.width as usize,
            meta.height as usize,
            &mut words,
        )
        .map_err(|message| bad(148, message))?;
        let mut bytes = vec![0; size];
        for (word, bytes) in words.into_iter().zip(bytes.as_chunks_mut::<4>().0) {
            BinaryWriter::u32_le(word, bytes);
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(bytes),
        })
    }
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! {ImageRegistration(||Box::new(Dds))}

#[cfg(test)]
#[path = "../tests/dds.rs"]
mod tests;
