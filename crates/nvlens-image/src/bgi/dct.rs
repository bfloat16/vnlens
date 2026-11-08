//! CompressedBG v2. sub_1401078D0 reads two weighted Huffman trees and row
//! offsets; sub_1401059B0/sub_140105610 decode DC/AC coefficients. The row mask
//! selects present 8x8 blocks. Alpha is separate (sub_1401041C0/1401045F0).
//! Scalar AAN IDCT and YCbCr rounding follow sub_140106880, including its
//! signed-16 saturation before the final arithmetic shift.
use super::cbg::read_tree;
use super::*;
use nvlens_crypto::compress::bgi::WeightOrder;
use nvlens_io::{BinaryReader, BitOrder, BitReader};

const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];
// AAN scale products from the runtime's table at 0x140166150.
const SCALE: [f32; 64] = [
    1.,
    1.3870399,
    1.306563,
    1.1758755,
    1.,
    0.78569496,
    0.5411961,
    0.27589938,
    1.3870399,
    1.9238795,
    1.8122549,
    1.6309863,
    1.3870399,
    1.0897902,
    0.75066054,
    0.38268343,
    1.306563,
    1.8122549,
    1.7071068,
    1.5363555,
    1.306563,
    1.02656,
    0.70710677,
    0.36047992,
    1.1758755,
    1.6309863,
    1.5363555,
    1.3826834,
    1.1758755,
    0.9238795,
    0.6363793,
    0.32442334,
    1.,
    1.3870399,
    1.306563,
    1.1758755,
    1.,
    0.78569496,
    0.5411961,
    0.27589938,
    0.78569496,
    1.0897902,
    1.02656,
    0.9238795,
    0.78569496,
    0.61731654,
    0.42521504,
    0.21677275,
    0.5411961,
    0.75066054,
    0.70710677,
    0.6363793,
    0.5411961,
    0.42521504,
    0.29289323,
    0.14931567,
    0.27589938,
    0.38268343,
    0.36047992,
    0.32442334,
    0.27589938,
    0.21677275,
    0.14931567,
    0.076120466,
];

pub(super) fn decode(meta: ImageMeta, encoded: &[u8], data: &[u8]) -> Result<Image> {
    let mut quant = BinaryReader::new(encoded);
    let factors = quant.read_bytes(128)?;
    let tables: [[f32; 64]; 2] =
        std::array::from_fn(|c| std::array::from_fn(|i| f32::from(factors[c * 64 + i]) * SCALE[i]));
    let width = meta.width as usize;
    let height = meta.height as usize;
    let blocks_x = width.div_ceil(8);
    let rows = height.div_ceil(8);
    let components = if meta.bpp == 8 { 1 } else { 3 };
    let mut r = BinaryReader::new(data);
    let dc = read_tree(&mut r, 16, WeightOrder::V2)?;
    let ac = read_tree(&mut r, 176, WeightOrder::V2)?;
    let mut offsets = (0..rows + usize::from(meta.bpp == 32))
        .map(|_| r.read_u32_le().map(|v| v as usize))
        .collect::<std::io::Result<Vec<_>>>()?;
    // Opaque images have no alpha-offset slot; their last row ends at EOF.
    if meta.bpp != 32 {
        offsets.push(data.len());
    }
    if offsets[0] < r.position()
        || offsets.windows(2).any(|pair| pair[0] > pair[1])
        || offsets[rows] > data.len()
    {
        return Err(corrupt(r.position(), "Invalid CompressedBG row offsets"));
    }
    let mut pixels = vec![0; meta.rgba_size()?];
    if meta.bpp != 32 {
        for pixel in pixels.as_chunks_mut::<4>().0 {
            pixel[3] = 255;
        }
    }
    for row in 0..rows {
        let mut r = BinaryReader::new(&data[offsets[row]..offsets[row + 1]]);
        let mask = r.read_bytes(blocks_x.div_ceil(8))?;
        let count = r.read_uleb32()? as usize;
        let present = (0..blocks_x)
            .filter(|&x| mask[x / 8] & (1 << (x % 8)) != 0)
            .count();
        if count != present * 64 * components {
            return Err(corrupt(
                offsets[row],
                "CompressedBG coefficient count disagrees with block mask",
            ));
        }
        let mut values = vec![0i16; count];
        let mut bits = BitReader::new(r.read_bytes(r.remaining())?, BitOrder::Msb);
        let mut accumulator = 0i16;
        for block in values.as_chunks_mut::<64>().0 {
            let width = dc.decode(&mut bits)? as u8;
            accumulator = accumulator.wrapping_add(signed(&mut bits, width)?);
            block[0] = accumulator;
        }
        bits.align_byte();
        for block in values.as_chunks_mut::<64>().0 {
            let mut index = 1;
            while index < 64 {
                let code = ac.decode(&mut bits)?;
                if code == 0 {
                    break;
                }
                if code == 15 {
                    index += 16;
                    if index > 64 {
                        return Err(corrupt(offsets[row], "AC zero run exceeds block"));
                    }
                    continue;
                }
                index += code & 15;
                if index >= 64 {
                    return Err(corrupt(offsets[row], "AC coefficient exceeds block"));
                }
                block[ZIGZAG[index]] = signed(&mut bits, (code >> 4) as u8)?;
                index += 1;
            }
        }
        let mut present_index = 0;
        for x in 0..blocks_x {
            if mask[x / 8] & (1 << (x % 8)) == 0 {
                continue;
            }
            let mut planes = [[0u8; 64]; 3];
            for component in 0..components {
                let start = (component * present + present_index) * 64;
                planes[component] = inverse(
                    &values.as_chunks::<64>().0[start / 64],
                    &tables[usize::from(component != 0)],
                );
            }
            for y in 0..8.min(height - row * 8) {
                for column in 0..8.min(width - x * 8) {
                    let at = ((row * 8 + y) * width + x * 8 + column) * 4;
                    let index = y * 8 + column;
                    let luma = f32::from(planes[0][index]);
                    if components == 1 {
                        pixels[at..at + 3].fill(planes[0][index]);
                    } else {
                        let cb = f64::from(planes[1][index]) - 128.;
                        let cr = f64::from(planes[2][index]) - 128.;
                        // The interpreter builds these f32 lookup tables from
                        // f64 expressions before adding the integer luma.
                        pixels[at] = (luma + (cr * 1.402 + 0.5) as f32).clamp(0., 255.) as u8;
                        pixels[at + 1] = ((luma + (cb * -0.34414) as f32)
                            + (0.5 - cr * 0.71414) as f32)
                            .clamp(0., 255.) as u8;
                        pixels[at + 2] = (luma + (cb * 1.772 + 0.5) as f32).clamp(0., 255.) as u8;
                    }
                }
            }
            present_index += 1;
        }
    }
    if meta.bpp == 32 {
        alpha(&data[offsets[rows]..], &mut pixels, width, height)?;
    }
    Ok(Image {
        meta,
        pixels: PixelBuffer::Rgba8(pixels),
    })
}
fn signed(bits: &mut BitReader<'_>, width: u8) -> Result<i16> {
    if width == 0 {
        return Ok(0);
    }
    let value = bits.read_bits(width)? as i32;
    Ok(if value < (1 << (width - 1)) {
        value + 1 - (1 << width)
    } else {
        value
    } as i16)
}
fn inverse(data: &[i16; 64], quant: &[f32; 64]) -> [u8; 64] {
    #[cfg(target_arch = "x86_64")]
    {
        super::simd::inverse(data, quant)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        inverse_scalar(data, quant)
    }
}
#[cfg(any(test, not(target_arch = "x86_64")))]
pub(super) fn inverse_scalar(data: &[i16; 64], quant: &[f32; 64]) -> [u8; 64] {
    let mut intermediate = [[0.; 8]; 8];
    for x in 0..8 {
        let column = aan(std::array::from_fn(|y| {
            f32::from(data[y * 8 + x]) * quant[y * 8 + x]
        }));
        for y in 0..8 {
            intermediate[y][x] = column[y];
        }
    }
    let mut output = [0; 64];
    for (y, row) in intermediate.into_iter().enumerate() {
        for (x, value) in aan(row).into_iter().enumerate() {
            let integer = (value as i32).clamp(i32::from(i16::MIN), i32::from(i16::MAX));
            output[y * 8 + x] = ((integer >> 3) + 128).clamp(0, 255) as u8;
        }
    }
    output
}
#[cfg(any(test, not(target_arch = "x86_64")))]
fn aan(input: [f32; 8]) -> [f32; 8] {
    let even_sum = input[0] + input[4];
    let even_difference = input[0] - input[4];
    let diagonal_sum = input[2] + input[6];
    let diagonal_difference = (input[2] - input[6]) * std::f32::consts::SQRT_2 - diagonal_sum;
    let even = [
        even_sum + diagonal_sum,
        even_difference + diagonal_difference,
        even_difference - diagonal_difference,
        even_sum - diagonal_sum,
    ];
    let outer_sum = input[1] + input[7];
    let outer_difference = input[1] - input[7];
    let inner_sum = input[5] + input[3];
    let inner_difference = input[5] - input[3];
    let odd_sum = outer_sum + inner_sum;
    let rotation = (outer_difference + inner_difference) * 1.847759;
    let odd1 = (-2.613126 * inner_difference + rotation) - odd_sum;
    let odd2 = (outer_sum - inner_sum) * std::f32::consts::SQRT_2 - odd1;
    let odd3 = odd2 + (1.0823922 * outer_difference - rotation);
    [
        even[0] + odd_sum,
        even[1] + odd1,
        even[2] + odd2,
        even[3] - odd3,
        even[3] + odd3,
        even[2] - odd2,
        even[1] - odd1,
        even[0] - odd_sum,
    ]
}
fn alpha(data: &[u8], pixels: &mut [u8], width: usize, height: usize) -> Result<()> {
    let stride = width.div_ceil(8) * 8;
    let padded_height = height.div_ceil(8) * 8;
    let mut alpha = vec![0; stride * padded_height];
    let mut r = BinaryReader::new(data);
    match r.read_u32_le()? {
        1 => {
            let mut at = 0;
            while at < alpha.len() {
                let flags = r.read_u8()?;
                for bit in 0..8 {
                    if at == alpha.len() {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        alpha[at] = r.read_u8()?;
                        at += 1;
                    } else {
                        let token = r.read_u16_le()?;
                        let x = i32::from(token & 63);
                        let x = if x > 31 { x - 64 } else { x };
                        let y = i32::from((token >> 6) & 7);
                        let y = if y != 0 { y - 8 } else { y };
                        let distance = -(i64::from(x) + i64::from(y) * stride as i64);
                        let count = usize::from(token >> 9) + 3;
                        if distance <= 0 || distance as usize > at || count > alpha.len() - at {
                            return Err(corrupt(
                                r.position(),
                                "Invalid CompressedBG alpha reference",
                            ));
                        }
                        for _ in 0..count {
                            alpha[at] = alpha[at - distance as usize];
                            at += 1;
                        }
                    }
                }
            }
        }
        2 => {
            let length = r.read_u32_le()? as usize;
            let tree = read_tree(&mut r, 256, WeightOrder::V2)?;
            let mut bits = BitReader::new(r.read_bytes(r.remaining())?, BitOrder::Msb);
            let mut decoded = Vec::new();
            for _ in 0..length {
                decoded.push(tree.decode(&mut bits)? as u8);
            }
            let mut r = BinaryReader::new(&decoded);
            let blocks_x = width.div_ceil(8);
            let blocks = blocks_x * height.div_ceil(8);
            let mask = r.read_bytes(blocks.div_ceil(8))?;
            for block in 0..blocks {
                if mask[block / 8] & (1 << (block % 8)) == 0 {
                    continue;
                }
                let x = block % blocks_x * 8;
                let y = block / blocks_x * 8;
                let columns = 8;
                for row in 0..8 {
                    alpha[(y + row) * stride + x..(y + row) * stride + x + columns]
                        .copy_from_slice(r.read_bytes(columns)?);
                }
            }
            if r.remaining() != 0 {
                return Err(corrupt(r.position(), "Trailing CompressedBG alpha samples"));
            }
        }
        mode => {
            return Err(Error::Unsupported(format!(
                "CompressedBG alpha mode {mode}"
            )));
        }
    }
    for y in 0..height {
        for x in 0..width {
            pixels[(y * width + x) * 4 + 3] = alpha[y * stride + x];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    #[test]
    fn opaque_v2_has_no_alpha_slot_and_handles_partial_blocks() -> Result<()> {
        let mut bytes = vec![0; 16 + 176];
        bytes[0] = 1;
        bytes[16] = 1;
        let offset = bytes.len() + 4;
        let mut word = [0; 4];
        BinaryWriter::u32_le(offset as u32, &mut word);
        bytes.extend(word);
        // One present color block: 192 coefficients, three zero DC and AC codes.
        bytes.extend([1, 0xc0, 1, 0, 0]);
        let meta = ImageMeta {
            width: 3,
            height: 5,
            bpp: 24,
            offset_x: 0,
            offset_y: 0,
            offset_unit: crate::OffsetUnit::Pixels,
        };
        let image = decode(meta, &[1; 128], &bytes)?;
        let PixelBuffer::Rgba8(pixels) = image.pixels else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(pixels.len(), 3 * 5 * 4);
        assert!(
            pixels
                .as_chunks::<4>()
                .0
                .iter()
                .all(|pixel| *pixel == [128, 128, 128, 255])
        );
        Ok(())
    }
    #[test]
    fn alpha_uses_padded_storage_and_crops_to_visible_pixels() -> Result<()> {
        let mut data = vec![0; 4];
        BinaryWriter::u32_le(1, &mut data);
        for row in 0..8 {
            data.push(0);
            data.extend((0..8).map(|column| (row * 8 + column) as u8));
        }
        let mut pixels = vec![0; 3 * 5 * 4];
        alpha(&data, &mut pixels, 3, 5)?;
        for y in 0..5 {
            for x in 0..3 {
                assert_eq!(pixels[(y * 3 + x) * 4 + 3], (y * 8 + x) as u8);
            }
        }
        data[4] = 1;
        assert!(alpha(&data, &mut pixels, 3, 5).is_err());
        Ok(())
    }
}
