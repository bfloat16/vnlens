#![allow(clippy::unwrap_used)]

use super::*;
#[test]
fn float_wav_roundtrip_and_truncation() {
    let pcm = Pcm {
        meta: AudioMeta {
            codec: "test",
            channels: 2,
            sample_rate: 48000,
            frames: Some(2),
        },
        samples: vec![0., -1., 0.5, 1.].into(),
    };
    let wav = pcm.to_wav().unwrap();
    let decoded = decode(&wav, &AtomicBool::new(false)).unwrap();
    assert_eq!(&*decoded.samples, &*pcm.samples);
    assert_eq!(decoded.meta.frames, Some(2));
    for end in 0..wav.len() {
        assert!(decode(&wav[..end], &AtomicBool::new(false)).is_err());
    }
}
