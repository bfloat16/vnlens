use super::*;

#[test]
fn known_vector_and_unaligned_tails() {
    let mut zero = [0; 9];
    decrypt(&mut zero);
    assert_eq!(zero, [0x9d, 0x85, 0xd5, 0xf7, 0x9d, 0x85, 0xd5, 0xf7, 0]);
    for offset in 0..32 {
        for len in 0..257 {
            let mut actual: Vec<u8> = (0..offset + len + 17)
                .map(|i| (i * 113 + 19) as u8)
                .collect();
            let mut expected = actual.clone();
            scalar(&mut expected[offset..offset + len]);
            decrypt(&mut actual[offset..offset + len]);
            assert_eq!(actual, expected, "offset {offset}, length {len}");
        }
    }
}
