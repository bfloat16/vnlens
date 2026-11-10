#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn defers_tail_validation_and_can_restart_backward_reads() {
    let dir = std::env::temp_dir().join(format!(
        "nvlens-mdf-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let payload: Vec<_> = (0..131_072usize)
        .map(|i| (i.wrapping_mul(37) ^ (i >> 7)) as u8)
        .collect();
    let mut bytes = mdf::tests::encode_fixture(&payload);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let path = dir.join("lazy.m");
    fs::write(&path, bytes).unwrap();
    let source = MdfSource::new(Arc::new(ArcView::open(&path).unwrap()), None).unwrap();
    assert_eq!(source.read_at(0, 16).unwrap().as_ref(), &payload[..16]);
    assert_eq!(
        source.read_at(100, 32).unwrap().as_ref(),
        &payload[100..132]
    );
    assert_eq!(source.read_at(2, 8).unwrap().as_ref(), &payload[2..10]);
    assert!(source.read_at(payload.len() as u64 - 1, 1).is_err());
    drop(source);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mzs_stream_restarts_without_retaining_decoded_body() {
    let dir = std::env::temp_dir().join(format!(
        "nvlens-mzs-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let bytes: Vec<_> = (0..8192).map(|i| (i * 37) as u8).collect();
    let path = dir.join("fixture.m");
    fs::write(&path, mdf::tests::mzs_fixture(&bytes)).unwrap();
    let source = MdfSource::new(Arc::new(ArcView::open(&path).unwrap()), None).unwrap();
    for (at, size) in [(0, 13), (4096, 32), (5, 19), (8191, 1)] {
        assert_eq!(
            &*source.read_at(at, size).unwrap(),
            &bytes[at as usize..at as usize + size]
        );
    }
    assert!(source.read_at(8192, 1).is_err());
    drop(source);
    fs::remove_dir_all(dir).unwrap();
}
