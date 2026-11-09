use super::*;

#[test]
fn standard_vectors() {
    // Standard CRC-32 (seed 0) of well-known inputs.
    assert_eq!(ieee(0, b""), 0x0000_0000);
    assert_eq!(ieee(0, b"123456789"), 0xCBF4_3926);
}
