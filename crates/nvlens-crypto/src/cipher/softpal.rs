//! Softpal list cipher (sub_4C6CA0): rotate the low byte of each LE word by
//! 4 + word index, then XOR 0x084df873 and 0xff987dee. Partial words are plain.
use nvlens_io::{BinaryReader, BinaryWriter};

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

pub fn decrypt(data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        simd::decrypt(data);
    }
    #[cfg(not(target_arch = "x86_64"))]
    scalar(data);
}
fn scalar(data: &mut [u8]) {
    for (index, word) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        word[0] = word[0].rotate_left((index as u32).wrapping_add(4));
        BinaryWriter::u32_le(BinaryReader::u32_le(word) ^ 0x084d_f873 ^ 0xff98_7dee, word);
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/softpal.rs"]
mod tests;
