//! Native ERISA integer 8x8 inverse DCT/LOT. Coefficients are the verified
//! matrix used by SGLImageDecoder sub_6BE550; the two passes shift by 14
//! and 16, with signed 16-bit saturation matching the native SSE2 path.
const MATRIX: [i16; 64] = [
    16385, 16069, 15137, 13623, 11585, 9103, 6271, 3197, 16385, 13623, 6271, -3196, -11585, -16069,
    -15137, -9102, 16385, 9103, -6270, -16069, -11585, 3197, 15137, 13623, 16385, 3197, -15137,
    -9102, 11585, 13623, -6270, -16069, 16385, -3196, -15137, 9103, 11585, -13623, -6270, 16069,
    16385, -9102, -6270, 16069, -11585, -3196, 15137, -13623, 16385, -13623, 6271, 3197, -11585,
    16069, -15137, 9103, 16385, -16069, 15137, -13623, 11585, -9102, 6271, -3196,
];

pub fn idct(block: &mut [i16; 64]) {
    let mut temp = [0i16; 64];
    for row in 0..8 {
        for column in 0..8 {
            let value = (0..8).fold(0i32, |sum, k| {
                sum.wrapping_add(i32::from(block[row * 8 + k]) * i32::from(MATRIX[column * 8 + k]))
            });
            temp[column * 8 + row] = (value >> 14).clamp(-32768, 32767) as i16;
        }
    }
    for row in 0..8 {
        for column in 0..8 {
            let value = (0..8).fold(0i32, |sum, k| {
                sum.wrapping_add(i32::from(temp[row * 8 + k]) * i32::from(MATRIX[column * 8 + k]))
            });
            block[column * 8 + row] = (value >> 16).clamp(-32768, 32767) as i16;
        }
    }
}
fn rotate(block: &mut [i16; 64], a: usize, b: usize, cos: i32, sin: i32) {
    let x = i32::from(block[a]);
    let y = i32::from(block[b]);
    block[a] = ((x * cos + y * sin) >> 14) as i16;
    block[b] = ((y * cos - x * sin) >> 14) as i16;
}
pub fn ilot(block: &mut [i16; 64], horizontal: &mut [i16; 64], vertical: &mut [i16; 64]) {
    for x in 0..8 {
        rotate(block, 40 + x, 56 + x, 0xf7d, 0x3e19);
        rotate(block, 24 + x, 40 + x, 0x1d80, 0x38cc);
        rotate(block, 8 + x, 24 + x, 0x2b6e, 0x2f02);
    }
    for y in (0..8).step_by(2) {
        for x in 0..8 {
            let a = y * 8 + x;
            let b = a + 8;
            let prior = i32::from(vertical[a]);
            let diff = i32::from(block[a]) - i32::from(block[b]);
            vertical[a] = block[a].wrapping_add(block[b]);
            vertical[b] = diff as i16;
            block[a] = ((prior + diff) >> 1) as i16;
            block[b] = ((prior - diff) >> 1) as i16;
        }
    }
    for y in 0..8 {
        rotate(block, y * 8 + 5, y * 8 + 7, 0xf7d, 0x3e19);
        rotate(block, y * 8 + 3, y * 8 + 5, 0x1d80, 0x38cc);
        rotate(block, y * 8 + 1, y * 8 + 3, 0x2b6e, 0x2f02);
        for x in (0..8).step_by(2) {
            let a = y * 8 + x;
            let b = a + 1;
            let prior = i32::from(horizontal[a]);
            let diff = i32::from(block[a]) - i32::from(block[b]);
            horizontal[a] = block[a].wrapping_add(block[b]);
            horizontal[b] = diff as i16;
            block[a] = ((prior + diff) >> 1) as i16;
            block[b] = ((prior - diff) >> 1) as i16;
        }
    }
    idct(block);
}

#[cfg(test)]
#[path = "../../../tests/compress/erisa/integer.rs"]
mod tests;
