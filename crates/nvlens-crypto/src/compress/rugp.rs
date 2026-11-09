//! rUGP LSB class-name code used by its standalone object and script headers.
use nvlens_io::{BitOrder, BitReader};

/// Encodes a standalone class spelling with the native literal escape and
/// terminal code. Used when a class was implicit in its parent object.
pub fn encode_class_name(name: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut writer = nvlens_io::BitWriter::new(BitOrder::Lsb);
    writer.write_bits_le(1, 1)?;
    for &byte in name {
        writer.write_bits_le(1, 1)?;
        writer.write_bits_le(0, 1)?;
        writer.write_bits_le(0, 4)?;
        writer.write_bits_le(u32::from(byte), 8)?;
    }
    writer.write_bits_le(3, 2)?;
    writer.write_bits_le(31, 5)?;
    Ok(writer.into_bytes())
}

pub fn class_name(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut bits = BitReader::new(bytes, BitOrder::Lsb);
    let mut name = Vec::new();
    if bits.read_bit()? == 0 {
        name.push(b'C');
    }
    loop {
        let next = (|| -> std::io::Result<u8> {
            if bits.read_bit()? == 0 {
                Ok(b"eaitrosducmnSglR"[bits.read_bits_le(4)? as usize])
            } else if bits.read_bit()? != 0 {
                Ok(b"EHTDPWXkqvNjwGz02U_K15JQZ467839\0"[bits.read_bits_le(5)? as usize])
            } else {
                let index = bits.read_bits_le(4)? as usize;
                Ok(if index == 0 {
                    bits.read_bits_le(8)? as u8
                } else {
                    b"\x01COFLfBMxphyAVbI"[index]
                })
            }
        })();
        match next {
            // A partial final code is padding in the native class-name codec.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
            Ok(0) => break,
            Ok(byte) => name.push(byte),
        }
    }
    Ok(name)
}
