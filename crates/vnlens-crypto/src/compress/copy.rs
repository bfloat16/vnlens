//! Forward LZ match expansion, shared by codecs with output-relative history.
//! A match repeats its history period even when source and destination overlap.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

pub(super) fn append(out: &mut Vec<u8>, distance: usize, count: usize) {
    #[cfg(target_arch = "x86_64")]
    if count >= 16 {
        simd::append(out, distance, count);
        return;
    }
    scalar(out, distance, count);
}

fn scalar(out: &mut Vec<u8>, distance: usize, count: usize) {
    for _ in 0..count {
        out.push(out[out.len() - distance]);
    }
}

/// Expands a match from the codecs' 4096-byte circular dictionaries.
pub(super) fn ring(
    dictionary: &mut [u8; 4096],
    position: &mut usize,
    source: usize,
    count: usize,
    out: &mut Vec<u8>,
) {
    #[cfg(target_arch = "x86_64")]
    if count >= 16 && (position.wrapping_sub(source) & 4095) >= 16 {
        simd::ring(dictionary, position, source, count, out);
        return;
    }
    ring_scalar(dictionary, position, source, count, out);
}

fn ring_scalar(
    dictionary: &mut [u8; 4096],
    position: &mut usize,
    source: usize,
    count: usize,
    out: &mut Vec<u8>,
) {
    for i in 0..count {
        let byte = dictionary[(source + i) & 4095];
        dictionary[*position & 4095] = byte;
        *position = (*position + 1) & 4095;
        out.push(byte);
    }
}

#[cfg(test)]
#[path = "../../tests/compress/copy.rs"]
mod tests;
