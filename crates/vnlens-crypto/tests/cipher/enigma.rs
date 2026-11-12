use super::*;

#[test]
fn section_vector_and_interleaved_candidates() -> std::io::Result<()> {
    let seed = [
        0x0d, 0x96, 0x1f, 0x37, 0x42, 0xa2, 0x64, 0x75, 0x4b, 0x33, 0xb1, 0x50, 0x78, 0xac, 0x40,
        0xe4,
    ];
    let key = section_key(&seed, 0x17e9532f);
    assert_eq!(
        &key[16..],
        &[
            0x9e, 0x8b, 0xd3, 0x81, 0xa2, 0x81, 0xe4, 0xfd, 0x0c, 0x93, 0x4d, 0xc3, 0x6f, 0xb7,
            0x38, 0xe6
        ]
    );
    let plain = decipher(
        &[0x55, 0x96, 0xb7, 0xf6, 0x44, 0x8a, 0x8a, 0xeb, 0xd6],
        &key,
    )?;
    assert_eq!(plain, [0x00, 0xa4, 0x01, 0x70, 0x80, 0x8f, 0xf7, 0xec, 0]);
    let probe = SectionProbe::new(seed);
    for start in [0, 127, 0x7ffffffe, u32::MAX - 3] {
        for (lane, mut cipher) in probe.ciphers(start).into_iter().enumerate() {
            let salt = start.wrapping_add(lane as u32);
            let expected = decipher(&[0; 1031], &section_key(&seed, salt))?;
            let mut actual = [0; 1031];
            cipher.apply(&mut actual);
            assert_eq!(actual.as_slice(), expected);
        }
    }
    assert!(Rc4::new(&[]).is_err());
    Ok(())
}
