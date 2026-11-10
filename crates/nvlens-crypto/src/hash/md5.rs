//! MD5 (RFC 1321), with bounded block buffering.

use nvlens_io::{BinaryReader, BinaryWriter};

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// MD5 digest of `msg`, using constant auxiliary memory.
#[must_use]
pub fn digest(msg: &[u8]) -> [u8; 16] {
    digest_parts(&[msg])
}

/// Hashes consecutive byte slices without allocating a concatenated buffer.
#[must_use]
pub fn digest_parts(parts: &[&[u8]]) -> [u8; 16] {
    let mut state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut tail = [0u8; 64];
    let mut used = 0usize;
    let mut bitlen = 0u64;
    for &part in parts {
        bitlen = bitlen.wrapping_add((part.len() as u64).wrapping_mul(8));
        let mut remaining = part;
        if used != 0 {
            let take = (64 - used).min(remaining.len());
            tail[used..used + take].copy_from_slice(&remaining[..take]);
            used += take;
            remaining = &remaining[take..];
            if used == 64 {
                compress(&mut state, &tail);
            } else {
                continue;
            }
        }
        let (chunks, rest) = remaining.as_chunks::<64>();
        for chunk in chunks {
            compress(&mut state, chunk);
        }
        tail[..rest.len()].copy_from_slice(rest);
        used = rest.len();
    }
    tail[used] = 0x80;
    tail[used + 1..].fill(0);
    if used >= 56 {
        compress(&mut state, &tail);
        tail.fill(0);
    }
    BinaryWriter::u64_le(bitlen, &mut tail[56..]);
    compress(&mut state, &tail);
    let mut out = [0u8; 16];
    for (word, bytes) in state.into_iter().zip(out.as_chunks_mut::<4>().0) {
        BinaryWriter::u32_le(word, bytes);
    }
    out
}

fn compress(state: &mut [u32; 4], chunk: &[u8]) {
    let mut m = [0u32; 16];
    for (i, word) in m.iter_mut().enumerate() {
        *word = BinaryReader::u32_le(&chunk[i * 4..i * 4 + 4]);
    }
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | (!b & d), i),
            16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(f.rotate_left(S[i]));
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[cfg(test)]
#[path = "../../tests/hash/md5.rs"]
mod tests;

/// Four independent scramble digests share a prefix and have distinct salts.
/// Complete prefix blocks are hashed once; SSE2 handles the final blocks in
/// parallel without changing the serial dependency between blocks of a hash.
pub(crate) fn digest_four_suffix(prefix: &[u8], suffixes: &[[u8; 4]; 4]) -> [[u8; 16]; 4] {
    #[cfg(target_arch = "x86_64")]
    {
        let mut state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        let (blocks, tail) = prefix.as_chunks::<64>();
        for block in blocks {
            compress(&mut state, block);
        }
        let mut last = [[0; 128]; 4];
        for (bytes, suffix) in last.iter_mut().zip(suffixes) {
            bytes[..tail.len()].copy_from_slice(tail);
            bytes[tail.len()..tail.len() + 4].copy_from_slice(suffix);
            bytes[tail.len() + 4] = 0x80;
            let end = if tail.len() + 4 < 56 { 64 } else { 128 };
            let length = (prefix.len() as u64).wrapping_add(4).wrapping_mul(8);
            BinaryWriter::u64_le(length, &mut bytes[end - 8..end]);
        }
        simd::finish(state, &last, tail.len() + 4 >= 56)
    }
    #[cfg(not(target_arch = "x86_64"))]
    std::array::from_fn(|i| digest_parts(&[prefix, &suffixes[i]]))
}
