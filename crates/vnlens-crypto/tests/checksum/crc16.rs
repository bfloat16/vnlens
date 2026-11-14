use super::*;
#[test]
fn crc16_8005_known_vector() {
    assert_eq!(crc16_8005(b"123456789"), 0xfee8);
    assert_eq!(crc16_8005(b""), 0);
}
