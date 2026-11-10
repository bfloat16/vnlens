//! SSE2 XOR kernels. x86-64 guarantees SSE2 on every operating system.
use nvlens_io::{BinaryReader, BinaryWriter};
use std::arch::x86_64::*;

pub(super) fn apply(data: &mut [u8], key: &[u8]) {
    // Small periods are expanded to a multiple of 16, avoiding per-vector
    // shuffles. Sixteen repetitions fit here for every period below 16.
    let mut expanded = [0; 240];
    let key = if key.len() < 16 {
        let expanded = &mut expanded[..key.len() * 16];
        for (byte, mask) in expanded.iter_mut().zip(key.iter().cycle()) {
            *byte = *mask;
        }
        &*expanded
    } else {
        key
    };
    if key.len().is_multiple_of(16) {
        for block in data.chunks_mut(key.len()) {
            let processed = stream(block, key);
            for (byte, mask) in block[processed..].iter_mut().zip(&key[processed..]) {
                *byte ^= mask;
            }
        }
        return;
    }
    let mut position = 0;
    for block in data.as_chunks_mut::<16>().0 {
        let mut wrapped = [0; 16];
        let mask = if let Some(mask) = key.get(position..position + 16) {
            mask
        } else {
            let tail = &key[position..];
            wrapped[..tail.len()].copy_from_slice(tail);
            wrapped[tail.len()..].copy_from_slice(&key[..16 - tail.len()]);
            &wrapped
        };
        // SAFETY: SSE2 is baseline on x86-64. block and mask contain 16
        // initialized bytes, do not alias, and loadu/storeu allow any alignment.
        unsafe {
            let value = _mm_loadu_si128(block.as_ptr().cast());
            let mask = _mm_loadu_si128(mask.as_ptr().cast());
            _mm_storeu_si128(block.as_mut_ptr().cast(), _mm_xor_si128(value, mask));
        }
        position += 16;
        if position >= key.len() {
            position -= key.len();
        }
    }
    for byte in data.as_chunks_mut::<16>().1 {
        *byte ^= key[position];
        position += 1;
        if position == key.len() {
            position = 0;
        }
    }
}

pub(super) fn stream(data: &mut [u8], key: &[u8]) -> usize {
    let count = data.len().min(key.len()) / 16 * 16;
    for (block, mask) in data[..count]
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(key[..count].as_chunks::<16>().0)
    {
        // SAFETY: both arrays contain 16 bytes. Mutable data cannot alias key;
        // unaligned accesses are supported and x86-64 guarantees SSE2.
        unsafe {
            let value = _mm_loadu_si128(block.as_ptr().cast());
            let mask = _mm_loadu_si128(mask.as_ptr().cast());
            _mm_storeu_si128(block.as_mut_ptr().cast(), _mm_xor_si128(value, mask));
        }
    }
    count
}

pub(super) fn chained(words: &mut [[u8; 4]]) {
    let mut previous = BinaryReader::u32_le(&words[0]);
    let (blocks, tail) = words[1..].as_chunks_mut::<4>();
    for block in blocks {
        // SAFETY: the four consecutive words contain 16 initialized bytes.
        // Loads precede stores; only this exclusive array is written. SSE2
        // shifts preserve the original ciphertext needed by the next lane.
        unsafe {
            let encoded = _mm_loadu_si128(block.as_ptr().cast());
            let preceding = _mm_or_si128(
                _mm_slli_si128::<4>(encoded),
                _mm_cvtsi32_si128(previous as i32),
            );
            previous = _mm_cvtsi128_si32(_mm_srli_si128::<12>(encoded)) as u32;
            _mm_storeu_si128(block.as_mut_ptr().cast(), _mm_xor_si128(encoded, preceding));
        }
    }
    for word in tail {
        let encoded = BinaryReader::u32_le(word);
        BinaryWriter::u32_le(encoded ^ previous, word);
        previous = encoded;
    }
}
