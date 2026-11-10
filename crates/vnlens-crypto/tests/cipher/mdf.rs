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

#[test]
fn word_batches_match_bytewise_stream_at_every_period_boundary() {
    for period in [
        None,
        Some(0),
        Some(1),
        Some(2),
        Some(3),
        Some(4),
        Some(5),
        Some(15),
        Some(16),
        Some(17),
        Some(131),
        Some(2495),
        Some(2496),
        Some(2497),
    ] {
        let source: Vec<_> = (0..10_000).map(|i| (i * 31 + 17) as u8).collect();
        let mut expected = source.clone();
        let mut state = MdfStream::new("demo_info.psb.m", period);
        if period != Some(0) {
            for byte in &mut expected {
                if state.key_len == Some(state.position) {
                    state.current = state.initial.clone();
                    state.position = 0;
                }
                if state.position.is_multiple_of(4) {
                    BinaryWriter::u32_le(state.current.next_u32(), &mut state.word);
                }
                *byte ^= state.word[state.position % 4];
                state.position = state.position.wrapping_add(1);
            }
        }
        for step in [1, 2, 3, 4, 5, 15, 16, 17, 111, 2495, 10_000] {
            let mut actual = source.clone();
            let mut state = MdfStream::new("demo_info.psb.m", period);
            for part in actual.chunks_mut(step) {
                state.apply(part);
            }
            assert_eq!(actual, expected, "period={period:?}, step={step}");
        }
    }
}
