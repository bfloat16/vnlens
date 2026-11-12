//! PDT control bits are MSB-first and interleaved with literals. PDT10
//! uses three-byte color literals and 12-bit pixel distances; PDT11 uses
//! byte palette indices with a caller-provided 16-entry distance table.
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_io::{BinaryIo, BinaryReader, BitOrder, InterleavedBits};

fn check(cancelled: Option<&AtomicBool>) -> std::io::Result<()> {
    if cancelled.is_some_and(|c| c.load(Ordering::Relaxed)) {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "PDT decoding cancelled",
        ))
    } else {
        Ok(())
    }
}

fn append(
    out: &mut Vec<u8>,
    distance: usize,
    count: usize,
    size: usize,
    zero_history: bool,
) -> std::io::Result<()> {
    if distance == 0 || count > size - out.len() {
        return Err(BinaryIo::invalid_input("Invalid PDT match extent"));
    }
    if distance > out.len() {
        if !zero_history {
            return Err(BinaryIo::invalid_input("PDT match precedes color history"));
        }
        let gap = (distance - out.len()).min(count);
        out.resize(out.len() + gap, 0);
        if gap == count {
            return Ok(());
        }
        super::copy::append(out, distance, count - gap);
    } else {
        super::copy::append(out, distance, count);
    }
    Ok(())
}

/// Decodes PDT10 colors as BGRA, within the declared pixel count.
pub fn colors(
    data: &[u8],
    pixels: usize,
    cancelled: Option<&AtomicBool>,
) -> std::io::Result<Vec<u8>> {
    check(cancelled)?;
    let size = pixels
        .checked_mul(4)
        .ok_or_else(|| BinaryIo::invalid_input("PDT color size overflow"))?;
    let mut input = InterleavedBits::new(data, BitOrder::Msb);
    let mut out = Vec::new();
    while out.len() < size {
        check(cancelled)?;
        if input.bit()? != 0 {
            out.extend([input.byte()?, input.byte()?, input.byte()?, 255]);
        } else {
            let token = usize::from(BinaryReader::u16_le(&[input.byte()?, input.byte()?]));
            append(
                &mut out,
                (1 + (token >> 4)) * 4,
                (1 + (token & 15)) * 4,
                size,
                false,
            )?;
        }
    }
    Ok(out)
}

/// Decodes PDT11 palette indices using the format's explicit distance table.
pub fn indices(
    data: &[u8],
    size: usize,
    distances: &[u32; 16],
    cancelled: Option<&AtomicBool>,
) -> std::io::Result<Vec<u8>> {
    check(cancelled)?;
    let mut input = InterleavedBits::new(data, BitOrder::Msb);
    let mut out = Vec::new();
    while out.len() < size {
        check(cancelled)?;
        if input.bit()? != 0 {
            out.push(input.byte()?);
        } else {
            let token = input.byte()?;
            let distance = usize::try_from(distances[usize::from(token & 15)])
                .map_err(|_| BinaryIo::invalid_input("PDT distance exceeds memory"))?;
            append(&mut out, distance, 2 + usize::from(token >> 4), size, true)?;
        }
    }
    Ok(out)
}

/// Decodes the separate alpha plane. Matches carry count then distance bytes.
pub fn alpha(data: &[u8], size: usize, cancelled: Option<&AtomicBool>) -> std::io::Result<Vec<u8>> {
    check(cancelled)?;
    let mut input = InterleavedBits::new(data, BitOrder::Msb);
    let mut out = Vec::new();
    while out.len() < size {
        check(cancelled)?;
        if input.bit()? != 0 {
            out.push(input.byte()?);
        } else {
            let count = 2 + usize::from(input.byte()?);
            let distance = 1 + usize::from(input.byte()?);
            append(&mut out, distance, count, size, false)?;
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/pdt.rs"]
mod tests;
