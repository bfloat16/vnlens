//! Fixed-width repeating XOR, restarting at the start of each supplied slice.

pub fn apply_u32_key(data: &mut [u8], key: &[u8; 4]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index & 3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeats_and_handles_a_partial_word() {
        let mut bytes = [0, 1, 2, 3, 4, 5, 6];
        apply_u32_key(&mut bytes, &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(bytes, [0x10, 0x21, 0x32, 0x43, 0x14, 0x25, 0x36]);
        apply_u32_key(&mut bytes, &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(bytes, [0, 1, 2, 3, 4, 5, 6]);
    }
}
