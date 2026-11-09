use super::*;

#[test]
fn standard_vectors() {
    assert_eq!(checksum(b""), 0x0000_0001);
    assert_eq!(checksum(b"Wikipedia"), 0x11E6_0398);

    let data: Vec<u8> = (0..=255).cycle().take(12000).collect();
    let mut state = Adler32::default();
    for chunk in data.chunks(1117) {
        state.update(chunk);
    }
    assert_eq!(state.checksum(), checksum(&data));
}
