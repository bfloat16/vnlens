use super::*;
use nvlens_audio::AudioMeta;

#[test]
fn seeking_uses_frames_and_keeps_stereo_channels_aligned() -> Result<()> {
    let mut source = PcmSource::new(Pcm {
        meta: AudioMeta {
            codec: "test",
            channels: 2,
            sample_rate: 4,
            frames: Some(4),
        },
        samples: vec![0., 1., 2., 3., 4., 5., 6., 7.].into(),
    })?;
    assert_eq!(source.total_duration(), Some(Duration::from_secs(1)));
    source.try_seek(Duration::from_millis(500))?;
    assert_eq!(source.next(), Some(4.));
    assert_eq!(source.next(), Some(5.));
    source.try_seek(Duration::from_secs(10))?;
    assert_eq!(source.next(), None);
    source.try_seek(Duration::ZERO)?;
    assert_eq!(source.next(), Some(0.));
    Ok(())
}
