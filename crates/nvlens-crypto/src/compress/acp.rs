//! ACP LZW envelope: "acp\0", BE u32 output size, then MSB codes. Codes
//! 0x100/0x101/0x102 mean end, widen and reset; dictionary starts at 0x103.
//! Checked against OpenExpFile/0x4916A0 and decoder 0x491320. Dictionary entries
//! refer to output runs, including the overlapping previous-run special case.
use nvlens_io::{BinaryIo, BinaryReader, BitOrder, BitReader, Endian};
use std::io;

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
                    for at in start..start + count {
                        out.push(out[at]);
                    }
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
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    fn stream(size: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = b"acp\0\0\0\0\0".to_vec();
        BinaryWriter::u32_be(size, &mut out[4..]);
        out.extend_from_slice(payload);
        out
    }
    #[test]
    fn literals_overlap_width_changes_reset_and_empty_output() -> io::Result<()> {
        // 9-bit codes: A, B, dictionary[0], dictionary[2], end.
        assert_eq!(
            unpack(&stream(7, &[0x20, 0x90, 0xa0, 0x70, 0x58, 0x00]))?,
            b"ABABABA"
        );
        assert_eq!(unpack(&stream(0, &[0x80, 0x00]))?, b"");
        // A, widen, B (10 bits), reset (10 bits), C (9 bits), end.
        assert_eq!(
            unpack(&stream(3, &[0x20, 0xc0, 0x44, 0x24, 0x08, 0x87, 0x00]))?,
            b"ABC"
        );
        Ok(())
    }
    #[test]
    fn rejects_undefined_matches_truncation_and_size_mismatch() {
        for data in [
            stream(1, &[0x81, 0x80]),
            stream(1, &[0x80, 0]),
            stream(0, &[0x20, 0xc0, 0]),
            stream(1, &[0x20]),
        ] {
            assert!(unpack(&data).is_err());
        }
        assert!(unpack(b"acp\0").is_err());
    }
}
