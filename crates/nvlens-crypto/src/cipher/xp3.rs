//! XP3 extraction filters. The xp3dec V2Link callback constructs 31 key
//! bytes from the entry hash, then XORs at (logical offset + index) % 31.
//! Its 32-bit shift/mask recurrence is kept verbatim, including bit 31.

/// Applies the xp3dec 31-byte hash filter to a logical slice, in place.
/// The same operation encrypts and decrypts; independent slices need no
/// mutable shared state, including offsets beyond 4 GiB.
pub fn xor31(hash: u32, offset: u64, bytes: &mut [u8]) {
    let mut state = (hash << 31) | (hash & 0x7fff_ffff);
    let mut key = [0; 31];
    for byte in &mut key {
        *byte = state as u8;
        state = ((state & 0xffff_fffe) << 23) | (state >> 8);
    }
    let mut index = (offset % 31) as usize;
    for byte in bytes {
        *byte ^= key[index];
        index += 1;
        if index == key.len() {
            index = 0;
        }
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/xp3.rs"]
mod tests;
