//! GSS LSD compression, independently reconstructed from sub_4D8C0,
//! sub_4DCC0, sub_4DB30 and sub_4E680. The eight-byte LE framing selects an
//! explicit-code LSB Huffman stream (H) or byte RLE (R), followed by N/B/W/S
//! identity or backward byte/word differencing. D/W bit coders are unsupported.
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_io::{BinaryReader, BinaryWriter, BitOrder, BitReader};

/// Decodes a selected LSD payload (after its four-byte signature). Only the
/// declared logical output is allocated; cancellation is checked per symbol.
pub fn decompress(input: &[u8], size: usize, cancel: &AtomicBool) -> io::Result<Vec<u8>> {
    check(cancel)?;
    let mut reader = BinaryReader::new(input);
    let transform = reader.read_u8()?;
    let coder = reader.read_u8()?;
    let declared = reader.read_u32_le()?;
    reader.read_bytes(2)?;
    if u64::from(declared) != size as u64 {
        return Err(invalid("LSD declared output differs from archive index"));
    }
    let output = match coder {
        b'H' => huffman(reader.read_bytes(reader.remaining())?, size, cancel)?,
        b'R' => rle(reader.read_bytes(reader.remaining())?, size, cancel)?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unsupported LSD bit coder",
            ));
        }
    };
    transform_bytes(output, transform, cancel)
}
#[derive(Default)]
struct Node {
    children: [Option<usize>; 2],
    symbol: Option<u8>,
}
fn huffman(input: &[u8], size: usize, cancel: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut reader = BinaryReader::new(input);
    reader.read_bytes(2)?;
    let mut tree = vec![Node::default()];
    for symbol in 0..=255u8 {
        check(cancel)?;
        let length = reader.read_u8()?;
        if length == 0 {
            continue;
        }
        if length > 23 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unsupported LSD Huffman code length",
            ));
        }
        let code = reader.read_compact_u64(length / 8 + 1, vnlens_io::Endian::Little)?;
        let mut node = 0;
        for bit in 0..length {
            if tree[node].symbol.is_some() {
                return Err(invalid("LSD Huffman prefix conflict"));
            }
            let branch = ((code >> bit) & 1) as usize;
            let next = if let Some(next) = tree[node].children[branch] {
                next
            } else {
                let next = tree.len();
                tree.push(Node::default());
                tree[node].children[branch] = Some(next);
                next
            };
            node = next;
        }
        if tree[node].symbol.is_some() || tree[node].children.iter().any(Option::is_some) {
            return Err(invalid("LSD Huffman code conflict"));
        }
        tree[node].symbol = Some(symbol);
    }
    let mut bits = BitReader::new(reader.read_bytes(reader.remaining())?, BitOrder::Lsb);
    let mut output = Vec::new();
    while output.len() < size {
        check(cancel)?;
        let mut node = 0;
        while tree[node].symbol.is_none() {
            node = tree[node].children[usize::from(bits.read_bit()?)]
                .ok_or_else(|| invalid("Invalid LSD Huffman path"))?;
        }
        if let Some(symbol) = tree[node].symbol {
            output.push(symbol);
        }
    }
    Ok(output)
}
fn rle(input: &[u8], size: usize, cancel: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut reader = BinaryReader::new(input);
    let mut output = Vec::new();
    loop {
        check(cancel)?;
        let control = reader.read_u8()?;
        let class = if control < 0xc0 {
            control & 0xc0
        } else {
            control & 0xf0
        };
        if class == 0xf0 {
            break;
        }
        let count = if control < 0xc0 {
            usize::from(control & 0x3f)
        } else {
            usize::from(control & 15) * 256 + usize::from(reader.read_u8()?)
        };
        if count > size - output.len() {
            return Err(invalid("LSD RLE run exceeds logical size"));
        }
        match class {
            0 | 0xc0 => output.resize(output.len() + count, 0),
            0x40 | 0xd0 => output.extend_from_slice(reader.read_bytes(count)?),
            0x80 | 0xe0 => {
                let byte = reader.read_u8()?;
                output.resize(output.len() + count, byte);
            }
            _ => return Err(invalid("Invalid LSD RLE control")),
        }
    }
    if output.len() != size {
        return Err(invalid("LSD RLE output size mismatch"));
    }
    Ok(output)
}
fn transform_bytes(mut bytes: Vec<u8>, transform: u8, cancel: &AtomicBool) -> io::Result<Vec<u8>> {
    match transform {
        b'N' => {}
        b'B' => {
            for i in (1..bytes.len()).rev() {
                check(cancel)?;
                bytes[i] = bytes[i - 1].wrapping_sub(bytes[i]);
            }
            if let Some(first) = bytes.first_mut() {
                *first = first.wrapping_neg();
            }
        }
        b'W' | b'S' => {
            if !bytes.len().is_multiple_of(2) {
                return Err(invalid("LSD word delta output is not aligned"));
            }
            let mut previous = 0u16;
            for word in bytes.as_chunks_mut::<2>().0 {
                check(cancel)?;
                let current = if transform == b'S' {
                    BinaryReader::u16_be(word)
                } else {
                    BinaryReader::u16_le(word)
                };
                let value = previous.wrapping_sub(current);
                if transform == b'S' {
                    BinaryWriter::u16_be(value, word);
                } else {
                    BinaryWriter::u16_le(value, word);
                }
                previous = current;
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unsupported LSD delta transform",
            ));
        }
    }
    Ok(bytes)
}
fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn check(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "LSD decompression cancelled",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/compress/gss.rs"]
mod tests;
