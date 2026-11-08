//! CompressedBG header and v1 predictor. Verified against sub_1400BFFB0,
//! sub_1400BF4D0, sub_1400BF6E0 and sub_1400BF8B0. Metadata is encrypted with
//! the header seed; byte sum and XOR are checked before decoding any pixels.
use super::*;
use nvlens_crypto::compress::bgi::{Generator, Huffman, WeightOrder};
use nvlens_io::{BinaryReader, BitOrder, BitReader};

pub(super) struct Header {
    pub(super) meta: ImageMeta,
    intermediate: usize,
    seed: u32,
    encoded: usize,
    sum: u8,
    xor: u8,
    version: u16,
}
impl Header {
    pub(super) fn parse(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        if r.read_bytes(16)? != b"CompressedBG___\0" {
            return Err(Error::InvalidFormat);
        }
        let width = u32::from(r.read_u16_le()?);
        let height = u32::from(r.read_u16_le()?);
        let bpp = r.read_u16_le()?;
        r.read_bytes(10)?;
        let intermediate = r.read_u32_le()? as usize;
        let seed = r.read_u32_le()?;
        let encoded = r.read_u32_le()? as usize;
        let sum = r.read_u8()?;
        let xor = r.read_u8()?;
        let version = r.read_u16_le()?;
        if width == 0 || height == 0 {
            return Err(corrupt(16, "Empty CompressedBG dimensions"));
        }
        if !matches!(bpp, 8 | 24 | 32) || version > 2 {
            return Err(Error::Unsupported(format!(
                "CompressedBG v{version}, {bpp} bits"
            )));
        }
        Ok(Self {
            meta: ImageMeta {
                width,
                height,
                bpp,
                offset_x: 0,
                offset_y: 0,
                offset_unit: crate::OffsetUnit::Pixels,
            },
            intermediate,
            seed,
            encoded,
            sum,
            xor,
            version,
        })
    }
}

pub(super) fn decode(data: &[u8]) -> Result<Image> {
    let header = Header::parse(data)?;
    let mut r = BinaryReader::new_at(data, 48)?;
    let mut encoded = r.read_bytes(header.encoded)?.to_vec();
    let mut generator = Generator::new(header.seed);
    let mut sum = 0u8;
    let mut xor = 0;
    for byte in &mut encoded {
        *byte = byte.wrapping_sub(generator.next_byte());
        sum = sum.wrapping_add(*byte);
        xor ^= *byte;
    }
    if sum != header.sum || xor != header.xor {
        return Err(corrupt(48, "CompressedBG metadata checksum mismatch"));
    }
    let payload = &data[r.position()..];
    if header.version == 2 {
        return super::dct::decode(header.meta, &encoded, payload);
    }
    let mut weights = BinaryReader::new(&encoded);
    let tree = read_tree(&mut weights, 256, WeightOrder::V1)?;
    let mut bits = BitReader::new(payload, BitOrder::Msb);
    let mut runs = Vec::new();
    for _ in 0..header.intermediate {
        runs.push(tree.decode(&mut bits)? as u8);
    }
    let size = header.meta.rgba_size()? / 4 * usize::from(header.meta.bpp / 8);
    let mut pixels = Vec::new();
    let mut runs = BinaryReader::new(&runs);
    let mut zeros = false;
    while runs.remaining() != 0 {
        let count = runs.read_uleb32()? as usize;
        if count > size - pixels.len() {
            return Err(corrupt(
                runs.position(),
                "CompressedBG run exceeds pixel buffer",
            ));
        }
        if zeros {
            pixels.resize(pixels.len() + count, 0);
        } else {
            pixels.extend_from_slice(runs.read_bytes(count)?);
        }
        zeros = !zeros;
    }
    if pixels.len() != size {
        return Err(corrupt(32, "CompressedBG pixel count mismatch"));
    }
    let channels = usize::from(header.meta.bpp / 8);
    let stride = header.meta.width as usize * channels;
    // Remove per-byte divisions from the predictor. Each component depends
    // only on the preceding pixel and the same component in the previous row.
    for index in channels..stride {
        pixels[index] = pixels[index].wrapping_add(pixels[index - channels]);
    }
    for row in 1..header.meta.height as usize {
        let at = row * stride;
        for channel in 0..channels {
            pixels[at + channel] = pixels[at + channel].wrapping_add(pixels[at + channel - stride]);
        }
        for index in at + channels..at + stride {
            let prediction = ((u16::from(pixels[index - channels])
                + u16::from(pixels[index - stride]))
                / 2) as u8;
            pixels[index] = pixels[index].wrapping_add(prediction);
        }
    }
    from_bgr(header.meta, &pixels)
}

pub(super) fn read_tree(
    r: &mut BinaryReader<'_>,
    count: usize,
    order: WeightOrder,
) -> Result<Huffman> {
    let weights = (0..count)
        .map(|_| r.read_uleb32())
        .collect::<std::io::Result<Vec<_>>>()?;
    Ok(Huffman::new(&weights, order)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    #[test]
    fn v1_checksum_huffman_runs_and_predictor() -> Result<()> {
        let mut header = vec![0; 48];
        header[..16].copy_from_slice(b"CompressedBG___\0");
        BinaryWriter::u16_le(2, &mut header[16..]);
        BinaryWriter::u16_le(2, &mut header[18..]);
        BinaryWriter::u16_le(24, &mut header[20..]);
        BinaryWriter::u32_le(13, &mut header[32..]);
        BinaryWriter::u32_le(256, &mut header[40..]);
        BinaryWriter::u16_le(1, &mut header[46..]);
        let mut generator = Generator::new(0);
        for _ in 0..256 {
            header.push(1u8.wrapping_add(generator.next_byte()));
        }
        header.extend([12, 10, 10, 10, 20, 20, 20, 30, 30, 30, 40, 40, 40]);
        let image = decode(&header)?;
        let PixelBuffer::Rgba8(pixels) = image.pixels else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(
            pixels,
            [
                10, 10, 10, 255, 30, 30, 30, 255, 40, 40, 40, 255, 75, 75, 75, 255
            ]
        );
        let mut broken = header.clone();
        broken[48] ^= 1;
        assert!(decode(&broken).is_err());
        for length in [16, 47, 48, 303, 304, header.len() - 1] {
            assert!(decode(&header[..length]).is_err());
        }
        Ok(())
    }
}
