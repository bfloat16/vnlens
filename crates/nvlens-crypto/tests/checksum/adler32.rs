use super::*;

#[test]
fn standard_vectors() {
    assert_eq!(checksum(b""), 0x0000_0001);
    assert_eq!(checksum(b"Wikipedia"), 0x11E6_0398);
}
