//! Siglus/RealLive LZ blocks: two LE u32 sizes, LSB-first control bytes,
//! literals and 12-bit backward distances with 4-bit lengths. Verified against
//! SiglusEngine sub_71DD60; G00 type 0 measures both fields in BGR pixels.
use nvlens_io::{BinaryIo, BinaryReader};
use std::io;

/// Decodes one framed block. `unit` and `minimum` are format parameters, not
/// output limits. Overlapping references copy forward, as in the interpreter.
pub fn decode(data: &[u8], minimum: usize, unit: usize) -> io::Result<Vec<u8>> {
    decode_units(data, minimum, unit, unit)
}

/// Siglus G00 type 0 stores three-byte BGR literals but its decoded size and
/// backward references use four-byte BGRA pixels (sub_6DEC30).
pub fn decode_bgr(data: &[u8]) -> io::Result<Vec<u8>> {
    decode_units(data, 1, 4, 3)
}

fn decode_units(data: &[u8], minimum: usize, unit: usize, literal: usize) -> io::Result<Vec<u8>> {
    if unit == 0 || minimum == 0 {
        return Err(BinaryIo::invalid_input("Invalid Siglus LZ parameters"));
    }
    let mut header = BinaryReader::new(data);
    let packed = header.read_u32_le()? as usize;
    let size = header.read_u32_le()? as usize;
    let payload = packed
        .checked_sub(8)
        .ok_or_else(|| BinaryIo::invalid_input("Siglus LZ size excludes header"))?;
    let mut input = BinaryReader::new(header.read_bytes(payload)?);
    let mut output = Vec::new();
    while output.len() < size {
        let control = input.read_u8()?;
        for bit in 0..8 {
            if output.len() == size {
                break;
            }
            if control & (1 << bit) != 0 {
                if unit > size - output.len() {
                    return Err(BinaryIo::invalid_input("Siglus literal exceeds output"));
                }
                output.extend_from_slice(input.read_bytes(literal)?);
                output.extend(std::iter::repeat_n(255, unit - literal));
            } else {
                let token = usize::from(input.read_u16_le()?);
                let distance = (token >> 4)
                    .checked_mul(unit)
                    .ok_or_else(|| BinaryIo::invalid_input("Siglus distance overflow"))?;
                let count = (token & 15)
                    .checked_add(minimum)
                    .and_then(|n| n.checked_mul(unit))
                    .ok_or_else(|| BinaryIo::invalid_input("Siglus length overflow"))?;
                if distance == 0 || distance > output.len() || count > size - output.len() {
                    return Err(BinaryIo::invalid_input("Invalid Siglus backward reference"));
                }
                super::copy::append(&mut output, distance, count);
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
#[path = "../../tests/compress/siglus.rs"]
mod tests;
