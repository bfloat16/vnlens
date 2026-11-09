#![allow(clippy::unwrap_used)]

use super::*;
use crate::keys;

#[test]
fn repeated_loads_share_the_cached_arc() {
    let a = load(keys::ages_mk2::EPK_BLOWFISH_DATAS).unwrap();
    let b = load(keys::ages_mk2::EPK_BLOWFISH_DATAS).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(a.len(), 4168);
}

#[test]
fn compiled_sidecar_contains_all_keys_without_source_fallback() {
    let exe = std::env::current_exe().unwrap();
    let profile = exe.parent().unwrap().parent().unwrap();
    for name in [
        keys::ages_mk2::SCRAMBLE_BASE,
        keys::ages_mk2::EPK_BLOWFISH_DATAS,
        keys::ages_mk2::SOUND_BLOWFISH_DATAS,
        keys::ages_mk2::SOUND_MD5_SALT,
    ]
    .into_iter()
    .chain(keys::rugp::VORBIS_SETUPS)
    {
        let bytes = std::fs::read(profile.join("bin").join(name)).unwrap();
        assert_eq!(bytes.as_slice(), load(name).unwrap().as_ref());
    }
}

#[test]
fn rejects_key_path_traversal() {
    for name in [
        "../key.bin",
        "/engine/key.bin",
        "C:/key.bin",
        "engine/../key.bin",
    ] {
        assert_eq!(load(name).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
