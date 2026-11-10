use super::*;
#[test]
fn prefix_period_and_music_envelope() -> Result<()> {
    let mut plain: Vec<u8> = (0..5000).map(|i| (i * 53) as u8).collect();
    plain[..4].copy_from_slice(b"OggS");
    let mut encrypted = plain.clone();
    encrypted[..4].copy_from_slice(b"Tink");
    let key = [71, 34, 96, 0];
    let mut at = 0;
    for byte in &mut encrypted[4..0xe1f] {
        *byte ^= key[at];
        at += 1;
        if at == key.len() {
            at = 1;
        }
    }
    assert_eq!(&*decode_envelope(&encrypted, &key)?, &plain);
    let mut music = vec![0; 12];
    music.extend(&encrypted);
    assert_eq!(&*decode_envelope(&music, &key)?, &plain);
    assert!(decode_envelope(&encrypted, &[]).is_err());
    assert!(matches!(decode_envelope(&plain, &[])?, Cow::Borrowed(_)));
    music[12..].copy_from_slice(&plain);
    assert_eq!(&*decode_envelope(&music, &[])?, &plain);
    Ok(())
}
