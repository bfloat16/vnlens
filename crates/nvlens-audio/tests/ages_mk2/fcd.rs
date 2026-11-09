#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn distinguishes_unencrypted_data_from_truncated_chunk_tables() {
    let mut plain = [0u8; HEADER_SIZE];
    plain[..4].copy_from_slice(MAGIC);
    assert!(!is_encrypted(&plain).unwrap());
    assert!(
        decrypt_payload_if_encrypted(&plain, &[], &[])
            .unwrap()
            .is_none()
    );
    plain[7] = 1;
    assert!(is_encrypted(&plain).is_err());
}
