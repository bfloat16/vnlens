//! LZF byte stream, as used by Stuff's sub_4303C0: literal runs of 1..32
//! bytes, or an 8 KiB backward distance and a length of 3..264 bytes.
use nvlens_io::BinaryReader;

/// Decodes exactly the declared output size, rejecting truncated references.
pub fn decompress(input: &[u8], size: usize) -> std::io::Result<Vec<u8>> {
    decode(input, size, size)
}

/// Reads only the requested output prefix, e.g. a compressed bitmap header.
pub fn prefix(input: &[u8], size: usize, prefix: usize) -> std::io::Result<Vec<u8>> {
    decode(input, size, prefix.min(size))
}

fn decode(input: &[u8], size: usize, end: usize) -> std::io::Result<Vec<u8>> {
    let mut reader = BinaryReader::new(input);
    let mut out = Vec::new();
    while out.len() < end {
        let control = reader.read_u8()?;
        let (count, distance) = if control < 32 {
            (usize::from(control) + 1, None)
        } else {
            let length = usize::from(control >> 5);
            let length = if length == 7 {
                7 + usize::from(reader.read_u8()?)
            } else {
                length
            };
            let distance = usize::from(control & 31) * 256 + usize::from(reader.read_u8()?) + 1;
            (length + 2, Some(distance))
        };
        if count > size - out.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "LZF run exceeds output size",
            ));
        }
        let take = count.min(end - out.len());
        if let Some(distance) = distance {
            if distance > out.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "LZF reference precedes output",
                ));
            }
            for _ in 0..take {
                out.push(out[out.len() - distance]);
            }
        } else {
            out.extend_from_slice(reader.read_bytes(take)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/lzf.rs"]
mod tests;
