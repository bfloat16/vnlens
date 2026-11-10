//! SSE2 forward LZ copying; no speculative reads or writes beyond a match.
use std::arch::x86_64::*;

pub(super) fn append(out: &mut Vec<u8>, mut distance: usize, mut count: usize) {
    // Validate the source through a safe access before any pointer operation.
    let first = out[out.len() - distance];
    out.reserve(count);
    if distance == 1 {
        out.resize(out.len() + count, first);
        return;
    }
    if distance < 16 {
        let seed = count.min(16);
        super::scalar(out, distance, seed);
        count -= seed;
        // An integral number of periods preserves phase while ensuring every
        // vector load reads only bytes written before that iteration.
        distance *= 16usize.div_ceil(distance);
    }
    let start = out.len();
    let whole = count / 16 * 16;
    // SAFETY: the safe source access establishes 0 < distance <= old length.
    // After seeding, distance >= 16 and <= start. reserve(count) guarantees
    // capacity through start+count; each unaligned load reads 16 initialized
    // bytes and precedes its disjoint store. Only this Vec owns the allocation.
    // Length is advanced only after every corresponding byte is initialized.
    // x86-64 guarantees SSE2, independently of the OS.
    unsafe {
        let ptr = out.as_mut_ptr();
        for at in (start..start + whole).step_by(16) {
            let value = _mm_loadu_si128(ptr.add(at - distance).cast());
            _mm_storeu_si128(ptr.add(at).cast(), value);
        }
        out.set_len(start + whole);
    }
    super::scalar(out, distance, count - whole);
}

pub(super) fn ring(
    dictionary: &mut [u8; 4096],
    position: &mut usize,
    mut source: usize,
    mut count: usize,
    out: &mut Vec<u8>,
) {
    source &= 4095;
    *position &= 4095;
    out.reserve(count);
    while count != 0 {
        let contiguous = count.min(4096 - source).min(4096 - *position);
        let whole = contiguous / 16 * 16;
        let start = out.len();
        // SAFETY: the caller selects this path only for a cyclic backward
        // distance >= 16. Each complete vector reads existing dictionary
        // bytes before updating either destination. contiguous prevents ring
        // wrap in all loads/stores; reserve(count) covers the output writes.
        // The Vec and dictionary are disjoint exclusive references. x86-64
        // guarantees SSE2, and unaligned instructions impose no alignment.
        unsafe {
            let history = dictionary.as_mut_ptr();
            let output = out.as_mut_ptr();
            for i in (0..whole).step_by(16) {
                let value = _mm_loadu_si128(history.add(source + i).cast());
                _mm_storeu_si128(history.add(*position + i).cast(), value);
                _mm_storeu_si128(output.add(start + i).cast(), value);
            }
            out.set_len(start + whole);
        }
        source = (source + whole) & 4095;
        *position = (*position + whole) & 4095;
        let tail = contiguous - whole;
        super::ring_scalar(dictionary, position, source, tail, out);
        source = (source + tail) & 4095;
        count -= contiguous;
    }
}
