use super::*;
use crate::AudioMeta;

fn pcm(channels: u16, samples: Vec<f32>) -> Pcm {
    Pcm {
        meta: AudioMeta {
            codec: "test",
            channels,
            sample_rate: 1000,
            frames: None,
        },
        samples: samples.into(),
    }
}

#[test]
fn stereo_dbfs_and_partial_block_rms_use_actual_frames() -> Result<()> {
    let pcm = pcm(
        2,
        (0..25)
            .flat_map(|i| [if i == 24 { -1. } else { 0. }, 0.5])
            .collect(),
    );
    let envelope = LevelEnvelope::new(&pcm, &AtomicBool::new(false))?;
    let levels = envelope.read(Duration::from_millis(20), Duration::from_millis(24));
    assert_eq!(levels[0].peak_dbfs, 0.);
    assert!((levels[0].rms_dbfs - 10. * (1_f32 / 5.).log10()).abs() < 1e-5);
    assert!((levels[1].peak_dbfs + 6.0206).abs() < 1e-4);
    assert_eq!(levels[1].rms_dbfs, levels[1].peak_dbfs);
    let all = envelope.read(Duration::ZERO, Duration::from_millis(24));
    assert!((all[0].rms_dbfs - 10. * (1_f32 / 25.).log10()).abs() < 1e-5);
    assert_eq!(
        envelope.read(Duration::from_millis(25), Duration::from_secs(1)),
        vec![Level::default(); 2]
    );
    Ok(())
}

#[test]
fn full_scale_sine_is_minus_three_db_rms_and_transients_survive_skipped_ticks() -> Result<()> {
    let samples = (0..1000)
        .map(|i| (std::f64::consts::TAU * i as f64 / 4.).sin() as f32)
        .collect();
    let envelope = LevelEnvelope::new(&pcm(1, samples), &AtomicBool::new(false))?;
    let level = envelope.read(Duration::ZERO, Duration::from_secs(1))[0];
    assert_eq!(level.peak_dbfs, 0.);
    assert!((level.rms_dbfs + 3.0103).abs() < 1e-4);
    let mut samples = vec![0.; 1000];
    samples[201] = 1.25;
    let envelope = LevelEnvelope::new(&pcm(1, samples), &AtomicBool::new(false))?;
    assert_eq!(
        envelope.read(Duration::from_millis(300), Duration::from_millis(300)),
        vec![Level::default()]
    );
    assert!(
        envelope.read(Duration::from_millis(100), Duration::from_millis(300))[0].peak_dbfs > 0.
    );
    Ok(())
}

#[test]
fn empty_silent_cancelled_and_invalid_pcm() -> Result<()> {
    for samples in [vec![], vec![0.; 41]] {
        let envelope = LevelEnvelope::new(&pcm(1, samples), &AtomicBool::new(false))?;
        assert_eq!(
            envelope.read(Duration::ZERO, Duration::from_secs(1)),
            vec![Level::default()]
        );
    }
    assert!(matches!(
        LevelEnvelope::new(&pcm(1, vec![]), &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    for invalid in [pcm(0, vec![]), pcm(2, vec![1.]), pcm(1, vec![f32::NAN])] {
        assert!(matches!(
            LevelEnvelope::new(&invalid, &AtomicBool::new(false)),
            Err(Error::Corrupt { .. })
        ));
    }
    Ok(())
}
