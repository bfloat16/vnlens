use super::*;

#[test]
fn applies_known_keystream() {
    let mut out = [0u8; 8];
    PsbStream::new(0x1234_5678).apply(&mut out);
    assert_eq!(out, [0x4E, 0x02, 0xDE, 0xCB, 0xAD, 0x53, 0x2C, 0x0C]);
}
