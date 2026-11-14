//! CRI UTF table obfuscation: multiplicative byte stream, seed 0x655f,
//! multiplier 0x4115. Random reads jump to their stream position modulo 2^32.
pub fn apply_utf(offset: u64, bytes: &mut [u8]) {
    let mut exponent = offset;
    let mut factor = 0x4115u32;
    let mut state = 0x655fu32;
    while exponent != 0 {
        if exponent & 1 != 0 {
            state = state.wrapping_mul(factor);
        }
        factor = factor.wrapping_mul(factor);
        exponent >>= 1;
    }
    for byte in bytes {
        *byte ^= state as u8;
        state = state.wrapping_mul(0x4115);
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/criware.rs"]
mod tests;
