//! AES-128 CTR with AES-NI and eight independent counter lanes. Key expansion
//! follows FIPS 197 Algorithm 2; CTR byte order is supplied by binary I/O.
//! SSE2 is baseline on x86-64; AES is checked before entering the kernel.
use std::arch::x86_64::*;
use vnlens_io::BinaryWriter;

pub(super) fn apply(key: &[u8; 16], upper: u64, offset: u64, data: &mut [u8]) -> bool {
    if !std::is_x86_feature_detected!("aes") {
        return false;
    }
    // SAFETY: runtime detection guarantees AES, and x86-64 guarantees SSE2.
    // key has 16 initialized bytes; data is exclusively borrowed and cannot
    // alias key. The kernel uses unaligned loads/stores within checked slices.
    unsafe {
        ctr(key, upper, offset, data);
    }
    true
}

#[target_feature(enable = "aes")]
unsafe fn ctr(key: &[u8; 16], upper: u64, offset: u64, data: &mut [u8]) {
    // SAFETY: caller guarantees AES/SSE2. Every load/store below addresses a
    // complete 16-byte array, one of eight lanes of a 128-byte array, or a
    // complete data chunk. No pointers escape or cross slice boundaries.
    unsafe {
        let k0 = _mm_loadu_si128(key.as_ptr().cast());
        macro_rules! expand {
            ($previous:expr, $rcon:literal) => {{
                let mut value = $previous;
                let assist = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<$rcon>(value));
                value = _mm_xor_si128(value, _mm_slli_si128::<4>(value));
                value = _mm_xor_si128(value, _mm_slli_si128::<8>(value));
                _mm_xor_si128(value, assist)
            }};
        }
        let k1 = expand!(k0, 0x01);
        let k2 = expand!(k1, 0x02);
        let k3 = expand!(k2, 0x04);
        let k4 = expand!(k3, 0x08);
        let k5 = expand!(k4, 0x10);
        let k6 = expand!(k5, 0x20);
        let k7 = expand!(k6, 0x40);
        let k8 = expand!(k7, 0x80);
        let k9 = expand!(k8, 0x1b);
        let k10 = expand!(k9, 0x36);
        macro_rules! encrypt {
            ($value:expr) => {{
                let mut value = _mm_xor_si128($value, k0);
                value = _mm_aesenc_si128(value, k1);
                value = _mm_aesenc_si128(value, k2);
                value = _mm_aesenc_si128(value, k3);
                value = _mm_aesenc_si128(value, k4);
                value = _mm_aesenc_si128(value, k5);
                value = _mm_aesenc_si128(value, k6);
                value = _mm_aesenc_si128(value, k7);
                value = _mm_aesenc_si128(value, k8);
                value = _mm_aesenc_si128(value, k9);
                _mm_aesenclast_si128(value, k10)
            }};
        }
        let mut position = offset / 16;
        let skip = (offset % 16) as usize;
        let mut remaining = data;
        if skip != 0 && !remaining.is_empty() {
            let mut stream = [0; 16];
            BinaryWriter::u64_be(upper, &mut stream[..8]);
            BinaryWriter::u64_be(position, &mut stream[8..]);
            let value = encrypt!(_mm_loadu_si128(stream.as_ptr().cast()));
            _mm_storeu_si128(stream.as_mut_ptr().cast(), value);
            let count = remaining.len().min(16 - skip);
            super::super::xor::apply_stream(&mut remaining[..count], &stream[skip..]);
            remaining = &mut remaining[count..];
            position = position.wrapping_add(1);
        }
        let (chunks, tail) = remaining.as_chunks_mut::<128>();
        let mut counters = [[0; 16]; 8];
        for chunk in chunks {
            for counter in &mut counters {
                BinaryWriter::u64_be(upper, &mut counter[..8]);
                BinaryWriter::u64_be(position, &mut counter[8..]);
                position = position.wrapping_add(1);
            }
            let mut a = _mm_xor_si128(_mm_loadu_si128(counters[0].as_ptr().cast()), k0);
            let mut b = _mm_xor_si128(_mm_loadu_si128(counters[1].as_ptr().cast()), k0);
            let mut c = _mm_xor_si128(_mm_loadu_si128(counters[2].as_ptr().cast()), k0);
            let mut d = _mm_xor_si128(_mm_loadu_si128(counters[3].as_ptr().cast()), k0);
            let mut e = _mm_xor_si128(_mm_loadu_si128(counters[4].as_ptr().cast()), k0);
            let mut f = _mm_xor_si128(_mm_loadu_si128(counters[5].as_ptr().cast()), k0);
            let mut g = _mm_xor_si128(_mm_loadu_si128(counters[6].as_ptr().cast()), k0);
            let mut h = _mm_xor_si128(_mm_loadu_si128(counters[7].as_ptr().cast()), k0);
            macro_rules! round {
                ($key:expr) => {
                    a = _mm_aesenc_si128(a, $key);
                    b = _mm_aesenc_si128(b, $key);
                    c = _mm_aesenc_si128(c, $key);
                    d = _mm_aesenc_si128(d, $key);
                    e = _mm_aesenc_si128(e, $key);
                    f = _mm_aesenc_si128(f, $key);
                    g = _mm_aesenc_si128(g, $key);
                    h = _mm_aesenc_si128(h, $key);
                };
            }
            round!(k1);
            round!(k2);
            round!(k3);
            round!(k4);
            round!(k5);
            round!(k6);
            round!(k7);
            round!(k8);
            round!(k9);
            macro_rules! store {
                ($lane:expr, $at:literal) => {{
                    let pointer = chunk.as_mut_ptr().add($at);
                    let value = _mm_xor_si128(
                        _mm_aesenclast_si128($lane, k10),
                        _mm_loadu_si128(pointer.cast()),
                    );
                    _mm_storeu_si128(pointer.cast(), value);
                }};
            }
            store!(a, 0);
            store!(b, 16);
            store!(c, 32);
            store!(d, 48);
            store!(e, 64);
            store!(f, 80);
            store!(g, 96);
            store!(h, 112);
        }
        for chunk in tail.chunks_mut(16) {
            let mut stream = [0; 16];
            BinaryWriter::u64_be(upper, &mut stream[..8]);
            BinaryWriter::u64_be(position, &mut stream[8..]);
            let value = encrypt!(_mm_loadu_si128(stream.as_ptr().cast()));
            _mm_storeu_si128(stream.as_mut_ptr().cast(), value);
            super::super::xor::apply_stream(chunk, &stream);
            position = position.wrapping_add(1);
        }
    }
}
