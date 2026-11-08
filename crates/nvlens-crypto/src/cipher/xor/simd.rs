//! SSE2 repeating XOR. Only whole 16-byte key periods enter this module.
use std::arch::x86_64::*;

pub(super) fn apply(data: &mut [u8], key: &[u8]) {
    // SAFETY: x86-64 guarantees SSE2. The caller supplies a nonempty key whose
    // size is a multiple of 16. Mutable data cannot alias the immutable key.
    unsafe {
        xor(data, key);
    }
}
#[target_feature(enable = "sse2")]
unsafe fn xor(data: &mut [u8], key: &[u8]) {
    let whole = data.len() / 16 * 16;
    let mut at = 0;
    let mut key_at = 0;
    // SAFETY: at+16<=whole<=data.len(); key_at is a multiple of 16 below
    // key.len(), so both loads and the store are in bounds. Unaligned accesses
    // are intentional; every output byte was initialized by the caller.
    unsafe {
        while at < whole {
            let input = _mm_loadu_si128(data.as_ptr().add(at).cast());
            let mask = _mm_loadu_si128(key.as_ptr().add(key_at).cast());
            _mm_storeu_si128(data.as_mut_ptr().add(at).cast(), _mm_xor_si128(input, mask));
            at += 16;
            key_at += 16;
            if key_at == key.len() {
                key_at = 0;
            }
        }
    }
    for byte in &mut data[whole..] {
        *byte ^= key[key_at];
        key_at += 1;
    }
}
