use super::*;
use nvlens_io::BinaryReader;

#[test]
fn legacy_mt_permutation_vector() {
    let mut bytes: Vec<_> = (0..32).collect();
    unscramble(&mut bytes, 1);
    assert_eq!(
        bytes,
        [
            0, 1, 2, 9, 4, 23, 6, 31, 8, 3, 16, 11, 12, 17, 14, 15, 10, 21, 19, 18, 20, 28, 22, 5,
            24, 30, 26, 27, 25, 29, 13, 7
        ]
    );
}

#[test]
fn rld_word_vector_repeat_and_native_encrypted_boundary() {
    let mut bytes = vec![0; 0x3ff0 * 4 + 7];
    apply_rld(&mut bytes, 1);
    let words: Vec<_> = bytes[..20]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| BinaryReader::u32_le(word))
        .collect();
    assert_eq!(
        words,
        [3556162020, 4012392790, 221657542, 586320574, 3355844479]
    );
    assert_eq!(&bytes[..1024], &bytes[1024..2048]);
    assert_eq!(&bytes[0x3ff0 * 4..], &[0; 7]);
    apply_rld(&mut bytes, 1);
    assert!(bytes.iter().all(|&b| b == 0));
}
