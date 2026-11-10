//! Raw BGI bitmaps. Transform 1 is channel-planar delta data traversed in
//! alternating row directions; the accumulator continues across rows.
use super::*;
use vnlens_io::BinaryReader;
pub(super) fn metadata(data: &[u8]) -> Result<Option<ImageMeta>> {
    if data.len() < 16 {
        return Ok(None);
    }
    let mut r = BinaryReader::new(data);
    let width = u32::from(r.read_u16_le()?);
    let height = u32::from(r.read_u16_le()?);
    let bpp = r.read_u16_le()?;
    let transform = r.read_u16_le()?;
    if width == 0
        || height == 0
        || !matches!(bpp, 8 | 24 | 32)
        || transform > 1
        || r.read_u64_le()? != 0
    {
        return Ok(None);
    }
    let length = u64::from(width) * u64::from(height) * u64::from(bpp / 8);
    if length + 16 != data.len() as u64 {
        return Ok(None);
    }
    Ok(Some(ImageMeta {
        width,
        height,
        bpp,
        offset_x: 0,
        offset_y: 0,
        offset_unit: crate::OffsetUnit::Pixels,
    }))
}
pub(super) fn decode(data: &[u8]) -> Result<Image> {
    let meta = metadata(data)?.ok_or(Error::InvalidFormat)?;
    if BinaryReader::u16_le(&data[6..]) == 0 {
        return from_bgr(meta, &data[16..]);
    }
    let stride = meta.width as usize * usize::from(meta.bpp / 8);
    let channels = usize::from(meta.bpp / 8);
    let mut pixels = vec![0; data.len() - 16];
    let mut r = BinaryReader::new_at(data, 16)?;
    for channel in 0..channels {
        let mut value = 0u8;
        for y in 0..meta.height as usize {
            for x in 0..meta.width as usize {
                value = value.wrapping_add(r.read_u8()?);
                let x = if y % 2 == 0 {
                    x
                } else {
                    meta.width as usize - 1 - x
                };
                pixels[y * stride + x * channels + channel] = value;
            }
        }
    }
    from_bgr(meta, &pixels)
}
