//! C,system movie obfuscation (sub_41DFB0): starting at logical byte 0x800,
//! XOR keys 1..127, advancing by the next key. The position period is 8128.

/// Transforms a byte window at its absolute logical movie offset. Sparse byte
/// updates avoid rewriting the other 98% of the stream; no mutable state is shared.
pub fn movie(data: &mut [u8], offset: u64) {
    const START: u64 = 0x800;
    const PERIOD: u64 = 127 * 128 / 2;
    let end = offset.saturating_add(data.len() as u64);
    if end <= START {
        return;
    }
    let mut cycle = offset.saturating_sub(START) / PERIOD;
    while let Some(base) = cycle.checked_mul(PERIOD).and_then(|v| v.checked_add(START)) {
        if base >= end {
            break;
        }
        for key in 1..=127u64 {
            let Some(at) = base.checked_add(key * (key + 1) / 2 - 1) else {
                break;
            };
            if at >= end {
                break;
            }
            if at >= offset {
                data[(at - offset) as usize] ^= key as u8;
            }
        }
        cycle += 1;
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/csystem.rs"]
mod tests;
