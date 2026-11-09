use super::*;
use crate::AudioMeta;

fn pcm(channels: u16, samples: Vec<f32>) -> Pcm {
    Pcm {
        meta: AudioMeta {
            codec: "test",
            channels,
            sample_rate: 48000,
            frames: None,
        },
        samples: samples.into(),
    }
}

#[test]
fn tone_frequency_stereo_levels_and_all_time_columns() -> Result<()> {
    let rate = 48000.;
    let frequency = 1500.;
    let samples = (0..24000)
        .flat_map(|frame| {
            let sample = (TAU * frequency * frame as f64 / rate).sin() as f32;
            [sample, sample * 0.1]
        })
        .collect();
    let mel = MelSpectrogram::new(&pcm(2, samples), 77, 192, &AtomicBool::new(false))?;
    assert_eq!(mel.columns, 77);
    for column in mel.channels[0].chunks(mel.bands) {
        assert!(column.iter().copied().fold(f32::NEG_INFINITY, f32::max) > -7.);
    }
    let middle = &mel.channels[0][38 * mel.bands..39 * mel.bands];
    let strongest = middle
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map_or(0, |(i, _)| i);
    let center = mel_to_hz(hz_to_mel(rate / 2.) * (strongest + 1) as f64 / (mel.bands + 1) as f64);
    assert!((center - frequency).abs() < 50., "Peak at {center} Hz");
    for (left, right) in mel.channels[0].iter().zip(&mel.channels[1]) {
        if *left > -50. {
            assert!((left - right - 20.).abs() < 0.001);
        }
    }
    Ok(())
}

#[test]
fn silence_empty_and_subwindow_audio() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let empty = MelSpectrogram::new(&pcm(3, vec![]), 50, 32, &cancel)?;
    assert_eq!(empty.columns, 0);
    assert_eq!(empty.channels.len(), 3);
    let silence = MelSpectrogram::new(&pcm(1, vec![0.; 9000]), 11, 32, &cancel)?;
    assert!(silence.channels[0].iter().all(|&n| n == f32::NEG_INFINITY));
    let impulse = MelSpectrogram::new(&pcm(1, vec![1.]), 50, 32, &cancel)?;
    assert_eq!(impulse.columns, 1);
    assert!(
        impulse.channels[0]
            .iter()
            .all(|n| n.is_finite() && *n <= 0.)
    );
    // A one-sample impulse has a flat power spectrum. Summing the triangle
    // weights independently predicts its band levels, including bandwidth.
    let max_mel = 2595. * (1_f64 + 24000. / 700.).log10();
    let mut expected = Vec::new();
    for band in 0..32 {
        let edge: Vec<_> = (band..band + 3)
            .map(|i| 700. * (10_f64.powf(max_mel * i as f64 / 33. / 2595.) - 1.))
            .collect();
        let power: f64 = (0..=2048)
            .map(|bin| {
                let hz = bin as f64 * 48000. / 4096.;
                if hz <= edge[0] || hz >= edge[2] {
                    0.
                } else if hz < edge[1] {
                    (hz - edge[0]) / (edge[1] - edge[0])
                } else {
                    (edge[2] - hz) / (edge[2] - edge[1])
                }
            })
            .sum();
        expected.push(power);
    }
    let peak = expected.iter().copied().fold(0_f64, f64::max);
    for (actual, power) in impulse.channels[0].iter().zip(expected) {
        assert!((f64::from(*actual) - 10. * (power / peak).log10()).abs() < 0.00001);
    }
    Ok(())
}

#[test]
fn overview_preserves_short_events_and_the_final_sample() -> Result<()> {
    let mut samples = vec![0.; 100_003];
    samples[37001] = 1.;
    samples[100002] = 1.;
    let mel = MelSpectrogram::new(&pcm(1, samples), 10, 32, &AtomicBool::new(false))?;
    assert!(mel.channels[0][..32].iter().all(|n| n.is_infinite()));
    for column in [3, 9] {
        assert!(
            mel.channels[0][column * 32..(column + 1) * 32]
                .iter()
                .any(|n| *n > -6.)
        );
    }
    Ok(())
}

#[test]
fn cancelled_and_invalid_pcm() {
    let valid = pcm(1, vec![0.; 8]);
    assert!(matches!(
        MelSpectrogram::new(&valid, 10, 10, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    for invalid in [
        pcm(0, vec![]),
        pcm(2, vec![1.]),
        pcm(1, vec![f32::NAN]),
        pcm(1, vec![f32::INFINITY]),
    ] {
        assert!(matches!(
            MelSpectrogram::new(&invalid, 10, 10, &AtomicBool::new(false)),
            Err(Error::Corrupt { .. })
        ));
    }
}
