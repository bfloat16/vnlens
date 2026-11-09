use super::*;

#[test]
fn hash_recurrence_vector() {
    let mut bytes = [0; 31];
    xor31(0x91e6_0399, 0, &mut bytes);
    assert_eq!(
        bytes,
        [
            0x99, 0x03, 0xe6, 0x91, 0xcc, 0x01, 0xf3, 0x48, 0xe6, 0x80, 0x79, 0x24, 0x73, 0xc0,
            0x3c, 0x92, 0x39, 0x60, 0x1e, 0xc9, 0x1c, 0x30, 0x8f, 0x64, 0x0e, 0x98, 0x47, 0x32,
            0x07, 0xcc, 0x23,
        ]
    );
}

#[test]
fn zero_hash_identity_and_split_reads() {
    let source: Vec<_> = (0..251).cycle().take(1000).collect();
    let mut plain = source.clone();
    xor31(0, 0, &mut plain);
    assert_eq!(plain, source);
    for offset in [0, 30, 31, (1 << 32) + 19, u64::MAX - 1000] {
        let mut whole = source.clone();
        xor31(0x91e6_0399, offset, &mut whole);
        let mut split = source.clone();
        for (i, chunk) in split.chunks_mut(17).enumerate() {
            xor31(0x91e6_0399, offset + (i * 17) as u64, chunk);
        }
        assert_eq!(whole, split);
        xor31(0x91e6_0399, offset, &mut whole);
        assert_eq!(whole, source);
    }
}
