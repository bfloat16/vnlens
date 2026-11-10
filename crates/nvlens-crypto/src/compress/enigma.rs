// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Translation of the Enigma LZ stream and E8/E9/FF25 inverse filter.

use nvlens_io::{BinaryIo, BinaryReader, BinaryWriter, BitOrder, InterleavedBits};
use std::io::Result;

fn gamma(input: &mut InterleavedBits<'_>) -> Result<usize> {
    let mut value = 1u32;
    loop {
        let bit = input.bit()?;
        value = value
            .checked_mul(2)
            .and_then(|v| v.checked_add(bit))
            .ok_or_else(|| BinaryIo::invalid_input("LZ gamma code exceeds u32"))?;
        if input.bit()? == 0 {
            return Ok(value as usize);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/compress/enigma.rs"]
mod tests;

fn copy(output: &mut Vec<u8>, distance: usize, length: usize, limit: usize) -> Result<()> {
    if !(distance > 0 && distance <= output.len()) {
        return Err(BinaryIo::invalid_input(format!(
            "invalid LZ distance {distance}"
        )));
    }
    if length > limit - output.len() {
        return Err(BinaryIo::invalid_input("LZ output exceeds declared size"));
    }
    super::copy::append(output, distance, length);
    Ok(())
}

/// Loader streams may contain block padding; configuration/section streams are strict.
pub fn decompress(data: &[u8], expected: usize, strict: bool) -> Result<Vec<u8>> {
    if expected == 0 {
        return Err(BinaryIo::invalid_input("Empty Enigma LZ output"));
    }
    let mut input = InterleavedBits::new(data, BitOrder::Msb);
    let mut output = Vec::with_capacity(expected);
    output.push(input.byte()?);
    let mut lwm = 2usize;
    let mut previous = 0;
    loop {
        if input.bit()? == 0 {
            if output.len() >= expected {
                return Err(BinaryIo::invalid_input("LZ literal exceeds declared size"));
            }
            output.push(input.byte()?);
            lwm = 2;
        } else if input.bit()? == 0 {
            let code = gamma(&mut input)?;
            if code < lwm {
                return Err(BinaryIo::invalid_input("negative LZ distance code"));
            }
            let distance_code = code - lwm;
            lwm = 1;
            if distance_code == 0 {
                let length = gamma(&mut input)?;
                copy(&mut output, previous, length, expected)?;
            } else {
                let distance = ((distance_code - 1) << 8) | input.byte()? as usize;
                let length = gamma(&mut input)?
                    + usize::from(distance >= 0x7d00)
                    + usize::from(distance >= 0x500)
                    + 2 * usize::from(distance < 0x80);
                copy(&mut output, distance, length, expected)?;
                previous = distance;
            }
        } else if input.bit()? == 0 {
            let value = input.byte()? as usize;
            let distance = value >> 1;
            if distance == 0 {
                if output.len() != expected {
                    return Err(BinaryIo::invalid_input(format!(
                        "LZ expanded size mismatch: {} != {expected}",
                        output.len()
                    )));
                }
                if strict && input.position() != data.len() {
                    return Err(BinaryIo::invalid_input(
                        "unconsumed bytes after LZ terminator",
                    ));
                }
                return Ok(output);
            }
            copy(&mut output, distance, 2 + (value & 1), expected)?;
            previous = distance;
            lwm = 1;
        } else {
            let mut distance = 0;
            for _ in 0..4 {
                distance = (distance << 1) | input.bit()? as usize;
            }
            if distance == 0 {
                if output.len() >= expected {
                    return Err(BinaryIo::invalid_input(
                        "LZ zero literal exceeds declared size",
                    ));
                }
                output.push(0);
            } else {
                copy(&mut output, distance, 1, expected)?;
            }
            lwm = 2;
        }
    }
}

pub fn fix_branches(data: &mut [u8]) {
    let mut pos = 0usize;
    let mut counter = 0u32;
    // Preserve the original loop's remaining > 1 after subtracting five.
    while pos + 6 < data.len() {
        if data[pos] == 0xe8 || data[pos] == 0xe9 {
            let old = BinaryReader::u32_le(&data[pos + 1..pos + 5]);
            BinaryWriter::u32_le(old.wrapping_sub(pos as u32), &mut data[pos + 1..pos + 5]);
            pos += 5;
        } else if data[pos..pos + 2] == [0xff, 0x25] {
            let old = BinaryReader::u32_le(&data[pos + 2..pos + 6]);
            BinaryWriter::u32_le(old.wrapping_sub(counter), &mut data[pos + 2..pos + 6]);
            counter = counter.wrapping_sub(4);
            pos += 6;
        } else {
            pos += 1;
        }
    }
}

/// Reject structurally impossible LZ prefixes without expanding data. Exhausting
/// a prefix is inconclusive, never a rejection. Used only as a salt prefilter.
pub fn plausible_prefix(data: &[u8], packed_size: usize, expected: usize) -> bool {
    fn check(data: &[u8], packed_size: usize, expected: usize) -> Option<bool> {
        let mut input = InterleavedBits::new(data, BitOrder::Msb);
        input.byte().ok()?;
        let (mut size, mut lwm, mut previous) = (1usize, 2usize, 0usize);
        loop {
            let (distance, length);
            if input.bit().ok()? == 0 {
                input.byte().ok()?;
                size += 1;
                lwm = 2;
                if size > expected {
                    return Some(false);
                }
                continue;
            } else if input.bit().ok()? == 0 {
                let code = gamma(&mut input).ok()?;
                if code < lwm {
                    return Some(false);
                }
                let d = code - lwm;
                lwm = 1;
                if d == 0 {
                    distance = previous;
                    length = gamma(&mut input).ok()?;
                } else {
                    distance = ((d - 1) << 8) | input.byte().ok()? as usize;
                    length = gamma(&mut input).ok()?
                        + usize::from(distance >= 0x7d00)
                        + usize::from(distance >= 0x500)
                        + 2 * usize::from(distance < 0x80);
                    previous = distance;
                }
            } else if input.bit().ok()? == 0 {
                let value = input.byte().ok()? as usize;
                distance = value >> 1;
                length = 2 + (value & 1);
                if distance == 0 {
                    return Some(size == expected && input.position() == packed_size);
                }
                previous = distance;
                lwm = 1;
            } else {
                let mut d = 0;
                for _ in 0..4 {
                    d = (d << 1) | input.bit().ok()? as usize;
                }
                if d == 0 {
                    size += 1;
                    lwm = 2;
                    if size > expected {
                        return Some(false);
                    }
                    continue;
                }
                distance = d;
                length = 1;
                lwm = 2;
            }
            if distance == 0 || distance > size || length > expected.saturating_sub(size) {
                return Some(false);
            }
            size += length;
        }
    }
    check(data, packed_size, expected).unwrap_or(true)
}
