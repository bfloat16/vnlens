//! CPicture::sub_4867F0: twenty base-233 integers, EF terminators, FB zero,
//! E9 repeated high digits. Fields 3/8 are dimensions, 13 flags, 17/9/11
//! mask/alpha/pixel lengths. DIB planes are bottom-up; base IDs are b0 ordinals.
use super::*;

pub(super) fn planes(data: &[u8]) -> Result<Planes<'_>> {
    let mut r = BinaryReader::new_at(data, 1)?;
    if r.read_u8()? != 0xef {
        return Err(bad("Invalid C,system picture header delimiter"));
    }
    let mut fields = [0u32; 20];
    for field in &mut fields {
        let low = r.read_u8()?;
        let low = if low == 0xfb { 0 } else { u32::from(low) };
        let mut repeats = 0u32;
        let mut high = 0u32;
        loop {
            match r.read_u8()? {
                0xef => break,
                0xe9 => {
                    repeats = repeats
                        .checked_add(1)
                        .ok_or_else(|| bad("C,system picture integer overflow"))?
                }
                0xfb => high = 0,
                byte => high = u32::from(byte),
            }
        }
        *field = repeats
            .checked_mul(233)
            .and_then(|v| v.checked_add(high))
            .and_then(|v| v.checked_mul(233))
            .and_then(|v| v.checked_add(low))
            .ok_or_else(|| bad("C,system picture integer overflow"))?;
    }
    let mask = r.read_bytes(fields[17] as usize)?;
    let alpha = if fields[13] & 4 != 0 {
        r.read_bytes(fields[9] as usize)?
    } else {
        &[]
    };
    let rgb = r.read_bytes(fields[11] as usize)?;
    if r.remaining() != 0 {
        return Err(bad("Trailing C,system picture data"));
    }
    Ok(Planes {
        base: fields[0],
        width: fields[3],
        height: fields[8],
        flags: fields[13],
        alpha,
        mask,
        rgb,
    })
}

pub(super) fn flip(image: &mut Image) -> Result<()> {
    let stride = usize::try_from(u64::from(image.meta.width) * 4)
        .map_err(|_| bad("C,system row exceeds address space"))?;
    let pixels = match &mut image.pixels {
        PixelBuffer::Bgra8(bytes) | PixelBuffer::Rgba8(bytes) => bytes,
        _ => {
            return Err(Error::Unsupported(
                "C,system picture requires 8-bit pixels".into(),
            ));
        }
    };
    for y in 0..image.meta.height as usize / 2 {
        let bottom = (image.meta.height as usize - 1 - y) * stride;
        let (top, rest) = pixels.split_at_mut(bottom);
        top[y * stride..(y + 1) * stride].swap_with_slice(&mut rest[..stride]);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/csystem/legacy.rs"]
mod tests;
