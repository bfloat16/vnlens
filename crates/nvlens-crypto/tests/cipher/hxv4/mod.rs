#![allow(clippy::unwrap_used)]

use super::*;
fn wide(s: &str) -> Vec<u8> {
    let mut out = vec![0; s.encode_utf16().count() * 2];
    for (w, b) in s.encode_utf16().zip(out.as_chunks_mut::<2>().0.iter_mut()) {
        BinaryWriter::u16_le(w, b);
    }
    out
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
#[test]
fn synthetic_bootstrap_vector() {
    let params = [
        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 1, 2, 0, 1, 0x34, 0x12, 0x78, 0x56,
    ];
    let keys = derive(
        &params,
        &wide("Synthetic Bootstrap (C) Test.Warning! synthetic author rights."),
        &wide("{SyntheticUnique}"),
        &[1, 2, 3, 4, 5, 6, 7, 8],
    )
    .unwrap();
    assert_eq!(
        hex(&keys.index),
        "354bb298eaeb75f75ab6df8d841048d55521bee04f3dd693b05cbc927066aa6a"
    );
    assert_eq!(
        hex(&keys.nonce0),
        "cc5306ef36018797a6227da78d6a9b1dff9648ee4d40f089"
    );
    assert_eq!(
        hex(&keys.nonce1),
        "58aec2a530568ea05441a827570ec3e4b1acd53f954306f1"
    );
    assert_eq!(format!("{keys:?}"), "Hxv4Keys([redacted])");
}
#[test]
fn tag_is_verified_before_plaintext_is_released() {
    let key = [3; 32];
    let nonce = [7; 24];
    let mut bytes = b"authenticated index".to_vec();
    let tag = XChaCha20Poly1305::new((&key).into())
        .encrypt_in_place_detached((&nonce).into(), b"", &mut bytes)
        .unwrap();
    let mut blob = tag.to_vec();
    blob.extend(bytes);
    assert_eq!(
        authenticate(&blob, &key, &nonce).unwrap(),
        b"authenticated index"
    );
    blob[0] ^= 1;
    assert!(authenticate(&blob, &key, &nonce).is_err());
}
