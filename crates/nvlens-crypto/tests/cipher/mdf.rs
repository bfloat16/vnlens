use super::*;

#[test]
fn matches_mt19937_array_seed_vector() {
    let mut mt = Mt19937::from_slice(&[0x123, 0x234, 0x345, 0x456]);
    let first = [
        mt.next_u32(),
        mt.next_u32(),
        mt.next_u32(),
        mt.next_u32(),
        mt.next_u32(),
    ];
    assert_eq!(
        first,
        [
            1_067_595_299,
            955_945_823,
            477_289_528,
            4_107_218_783,
            4_228_976_476
        ]
    );
}

#[test]
fn mdf_keystream_matches_known_vector() {
    let mut encoded = [0u8; 16];
    MdfStream::new("demo_info.psb.m", Some(131)).apply(&mut encoded);
    assert_eq!(
        encoded,
        [
            0x62, 0x72, 0xA2, 0x03, 0x3D, 0xF1, 0xBC, 0x5D, 0x2A, 0xA5, 0xD6, 0x49, 0x26, 0x4C,
            0x93, 0xE4
        ]
    );
}

#[test]
fn streaming_matches_partial_repeated_words() {
    let mut whole = [0u8; 300];
    MdfStream::new("demo_info.psb.m", Some(131)).apply(&mut whole);
    let mut split = [0u8; 300];
    let mut stream = MdfStream::new("demo_info.psb.m", Some(131));
    for chunk in split.chunks_mut(7) {
        stream.apply(chunk);
    }
    assert_eq!(whole, split);
    assert_eq!(&whole[..131], &whole[131..262]);
}
