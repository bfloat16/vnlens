//! ACP LZW envelope: "acp\0", BE u32 output size, then MSB codes. Codes
//! 0x100/0x101/0x102 mean end, widen and reset; dictionary starts at 0x103.
//! Checked against OpenExpFile/0x4916A0 and decoder 0x491320. Dictionary entries
//! refer to output runs, including the overlapping previous-run special case.
use std::io;
use vnlens_io::{BinaryIo, BinaryReader, BitOrder, BitReader, Endian};

pub fn unpack(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut r = BinaryReader::new(data);
    if r.read_bytes(4)? != b"acp\0" {
        return Err(BinaryIo::invalid_input("Invalid ACP signature"));
    }
    let size = usize::try_from(r.read_u32(Endian::Big)?)
        .map_err(|_| BinaryIo::invalid_input("ACP size exceeds address space"))?;
    let mut bits = BitReader::new(r.read_bytes(r.remaining())?, BitOrder::Msb);
    let mut width = 9;
    let mut dictionary = Vec::<usize>::new();
    let mut out = Vec::new();
    loop {
        let code = bits.read_bits(width)?;
        match code {
            0x100 => break,
            0x101 => {
                width += 1;
                // Native tokens are unsigned 32-bit values.
                if width > 32 {
                    return Err(BinaryIo::invalid_input("ACP token exceeds u32"));
                }
            }
            0x102 => {
                width = 9;
                dictionary.clear();
            }
            _ => {
                dictionary.push(out.len());
                if code < 0x100 {
                    if out.len() == size {
                        return Err(BinaryIo::invalid_input("ACP literal exceeds output size"));
                    }
                    out.push(code as u8);
                } else {
                    let index = usize::try_from(code - 0x103)
                        .map_err(|_| BinaryIo::invalid_input("ACP index exceeds address space"))?;
                    let (&start, &end) = dictionary
                        .get(index)
                        .zip(dictionary.get(index + 1))
                        .ok_or_else(|| {
                            BinaryIo::invalid_input("ACP dictionary reference is undefined")
                        })?;
                    let count = end - start + 1;
                    if start >= out.len() || count > size - out.len() {
                        return Err(BinaryIo::invalid_input(
                            "ACP match exceeds history or output size",
                        ));
                    }
                    let distance = out.len() - start;
                    super::copy::append(&mut out, distance, count);
                }
            }
        }
    }
    if out.len() != size {
        return Err(BinaryIo::unexpected_eof(
            "ACP stream ended before declared output size",
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/acp.rs"]
mod tests;
