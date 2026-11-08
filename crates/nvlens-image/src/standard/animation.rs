//! Standard animation metadata, without decoding pixels merely to count frames.
//! GIF image descriptors, PNG acTL and WebP ANMF follow their container specs.
use image::{AnimationDecoder, ImageDecoder};
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;
use std::io::Cursor;

pub(super) fn count(data: &[u8]) -> Result<usize> {
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        let mut r = BinaryReader::new_at(data, 10)?;
        let flags = r.read_u8()?;
        r.read_bytes(2)?;
        if flags & 0x80 != 0 {
            r.read_bytes(3 * (2usize << (flags & 7)))?;
        }
        let mut frames = 0;
        loop {
            match r.read_u8()? {
                0x3b => return Ok(frames),
                0x21 => {
                    r.read_u8()?;
                    blocks(&mut r)?;
                }
                0x2c => {
                    r.read_bytes(8)?;
                    let flags = r.read_u8()?;
                    if flags & 0x80 != 0 {
                        r.read_bytes(3 * (2usize << (flags & 7)))?;
                    }
                    r.read_u8()?;
                    blocks(&mut r)?;
                    frames += 1;
                }
                _ => {
                    return Err(Error::Corrupt {
                        offset: r.position() as u64 - 1,
                        reason: "Invalid GIF block".into(),
                    });
                }
            }
        }
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut r = BinaryReader::new_at(data, 8)?;
        loop {
            let size = r.read_u32(nvlens_io::Endian::Big)? as usize;
            let tag = r.read_bytes(4)?;
            let body = r.read_bytes(size)?;
            r.read_u32_le()?;
            if tag == b"acTL" {
                return Ok(BinaryReader::new(body).read_u32(nvlens_io::Endian::Big)? as usize);
            }
            if tag == b"IDAT" || tag == b"IEND" {
                return Ok(1);
            }
        }
    }
    if data.get(..4) == Some(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        let mut header = BinaryReader::new_at(data, 4)?;
        let size = header.read_u32_le()?;
        let payload = size.checked_sub(4).ok_or(Error::InvalidFormat)?;
        let mut r = BinaryReader::new_at(data, 12)?;
        let mut r = BinaryReader::new(r.read_bytes(payload as usize)?);
        let mut frames = 0;
        while r.remaining() > 0 {
            let tag = r.read_bytes(4)?;
            let size = r.read_u32_le()? as usize;
            r.read_bytes(size)?;
            if !size.is_multiple_of(2) {
                r.read_u8()?;
            }
            if tag == b"ANMF" {
                frames += 1;
            }
        }
        return Ok(frames.max(1));
    }
    Ok(1)
}
fn blocks(r: &mut BinaryReader<'_>) -> Result<()> {
    loop {
        let size = usize::from(r.read_u8()?);
        if size == 0 {
            return Ok(());
        }
        r.read_bytes(size)?;
    }
}
pub(super) fn decode(data: &[u8], frame: usize) -> Result<Option<Vec<u8>>> {
    let frames = match image::guess_format(data).map_err(super::error)? {
        image::ImageFormat::Gif => {
            let mut decoder =
                image::codecs::gif::GifDecoder::new(Cursor::new(data)).map_err(super::error)?;
            decoder
                .set_limits(image::Limits::no_limits())
                .map_err(super::error)?;
            decoder.into_frames()
        }
        image::ImageFormat::Png => {
            let decoder = image::codecs::png::PngDecoder::with_limits(
                Cursor::new(data),
                image::Limits::no_limits(),
            )
            .map_err(super::error)?;
            if !decoder.is_apng().map_err(super::error)? {
                return Ok(None);
            }
            decoder.apng().map_err(super::error)?.into_frames()
        }
        image::ImageFormat::WebP => {
            let decoder =
                image::codecs::webp::WebPDecoder::new(Cursor::new(data)).map_err(super::error)?;
            if !decoder.has_animation() {
                return Ok(None);
            }
            decoder.into_frames()
        }
        _ => return Ok(None),
    };
    // Disposal/blending can depend on earlier frames; decode those in order,
    // retaining only the requested composited frame.
    for (index, result) in frames.enumerate() {
        let decoded = result.map_err(super::error)?;
        if index == frame {
            return Ok(Some(decoded.into_buffer().into_raw()));
        }
    }
    Err(Error::Unsupported("Image frame is out of range".into()))
}
