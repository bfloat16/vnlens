use super::*;

#[test]
fn applies_known_keystream() {
    let mut out = [0u8; 8];
    PsbStream::new(0x1234_5678).apply(&mut out);
    assert_eq!(out, [0x4E, 0x02, 0xDE, 0xCB, 0xAD, 0x53, 0x2C, 0x0C]);
}

#[test]
fn random_access_skips_match_sequential_stream_including_zero_high_bytes() {
    for key in [0, 1, 0x1234_5678, u32::MAX] {
        let mut expected = vec![0; 8192];
        PsbStream::new(key).apply(&mut expected);
        for skip in [0, 1, 3, 4, 5, 31, 129, 4097, 8000] {
            let mut stream = PsbStream::new(key);
            stream.skip(skip as u64);
            let mut actual = [0; 32];
            stream.apply(&mut actual[..3]);
            stream.apply(&mut actual[3..]);
            assert_eq!(actual, expected[skip..skip + 32]);
        }
    }
}
