//! Mel power overview: periodic Hann STFT, triangular HTK Mel filter bank
//! (2595 * log10(1 + Hz / 700)), and 10*log10 power relative to the shared peak.
//! Every channel and analysis window is included. Windows sharing a display
//! column use their maximum power so short events survive overview reduction.
//! The 4096-sample window and maximum 1024-sample hop are analysis resolution,
//! not input limits. Memory depends on the requested display dimensions.

use std::{
    f64::consts::TAU,
    sync::atomic::{AtomicBool, Ordering},
};

use nvlens_core::{Error, Result};
use rustfft::{Fft, FftDirection, algorithm::Radix4, num_complex::Complex};

use crate::Pcm;

const WINDOW: usize = 4096;
const HOP: usize = WINDOW / 4;

/// Per-channel, column-major Mel powers in dB relative to the loudest cell
/// across all channels. Silence is negative infinity; values are not clipped.
#[derive(Debug)]
pub struct MelSpectrogram {
    pub columns: usize,
    pub bands: usize,
    pub channels: Vec<Vec<f32>>,
}

#[must_use]
pub fn hz_to_mel(hz: f64) -> f64 {
    2595. * (1. + hz / 700.).log10()
}

fn mel_to_hz(mel: f64) -> f64 {
    700. * (10_f64.powf(mel / 2595.) - 1.)
}

impl MelSpectrogram {
    /// Analyzes borrowed PCM without modifying it. Dimensions are the desired
    /// overview resolution, not audio limits. Empty PCM produces zero columns.
    /// Returns Cancelled between windows; invalid PCM or dimensions are errors.
    pub fn new(pcm: &Pcm, columns: usize, bands: usize, cancelled: &AtomicBool) -> Result<Self> {
        check_cancel(cancelled)?;
        let channels = usize::from(pcm.meta.channels);
        if channels == 0 || pcm.meta.sample_rate == 0 || !pcm.samples.len().is_multiple_of(channels)
        {
            return Err(Error::Corrupt {
                offset: 0,
                reason: "Invalid spectrogram PCM layout".into(),
            });
        }
        if columns == 0 || bands == 0 {
            return Err(Error::Unsupported(
                "Spectrogram dimensions must be nonzero".into(),
            ));
        }
        let frames = pcm.samples.len() / channels;
        let columns = columns.min(frames);
        let cells = columns.checked_mul(bands).ok_or_else(|| {
            Error::Unsupported("Spectrogram dimensions exceed address space".into())
        })?;
        let mut powers = vec![vec![0_f64; cells]; channels];
        if frames != 0 {
            let filters = filters(pcm.meta.sample_rate, bands)?;
            let window: Vec<_> = (0..WINDOW)
                .map(|i| 0.5 - 0.5 * (TAU * i as f64 / WINDOW as f64).cos())
                .collect();
            // Radix4's fixed power-of-two size, exact buffer length and queried
            // scratch length satisfy its checked safe API's buffer contracts.
            let fft = Radix4::new(WINDOW, FftDirection::Forward);
            let mut buffer = vec![Complex::default(); WINDOW];
            let mut scratch = vec![Complex::default(); fft.get_inplace_scratch_len()];
            let mut spectrum = vec![0.; WINDOW / 2 + 1];
            let hop = (frames / columns).min(HOP);
            for (channel, output) in powers.iter_mut().enumerate() {
                for center in (0..frames).step_by(hop) {
                    check_cancel(cancelled)?;
                    for (i, value) in buffer.iter_mut().enumerate() {
                        let frame = center
                            .checked_add(i)
                            .and_then(|n| n.checked_sub(WINDOW / 2));
                        let sample = frame
                            .filter(|&n| n < frames)
                            .map_or(0., |n| pcm.samples[n * channels + channel]);
                        if !sample.is_finite() {
                            return Err(Error::Corrupt {
                                offset: 0,
                                reason: "Non-finite PCM sample".into(),
                            });
                        }
                        *value = Complex::new(f64::from(sample) * window[i], 0.);
                    }
                    fft.process_with_scratch(&mut buffer, &mut scratch);
                    for (power, value) in spectrum.iter_mut().zip(&buffer) {
                        *power = value.norm_sqr();
                    }
                    let column = (center as u128 * columns as u128 / frames as u128) as usize;
                    for (band, filter) in filters.iter().enumerate() {
                        let power = filter
                            .iter()
                            .map(|&(bin, weight)| spectrum[bin] * weight)
                            .sum::<f64>();
                        let cell = &mut output[column * bands + band];
                        *cell = cell.max(power);
                    }
                }
            }
        }
        let peak = powers.iter().flatten().copied().fold(0_f64, f64::max);
        let mut result = Vec::with_capacity(channels);
        for channel in powers {
            let mut db = Vec::with_capacity(cells);
            for column in channel.chunks(bands) {
                check_cancel(cancelled)?;
                db.extend(column.iter().map(|&power| {
                    if power == 0. {
                        f32::NEG_INFINITY
                    } else {
                        (10. * (power / peak).log10()) as f32
                    }
                }));
            }
            result.push(db);
        }
        Ok(Self {
            columns,
            bands,
            channels: result,
        })
    }
}

fn filters(rate: u32, bands: usize) -> Result<Vec<Vec<(usize, f64)>>> {
    let edges = bands
        .checked_add(2)
        .ok_or_else(|| Error::Unsupported("Mel band count exceeds address space".into()))?;
    let maximum = hz_to_mel(f64::from(rate) / 2.);
    let frequencies: Vec<_> = (0..edges)
        .map(|i| mel_to_hz(maximum * i as f64 / (edges - 1) as f64))
        .collect();
    Ok(frequencies
        .windows(3)
        .map(|edge| {
            (0..=WINDOW / 2)
                .filter_map(|bin| {
                    let hz = bin as f64 * f64::from(rate) / WINDOW as f64;
                    let weight = ((hz - edge[0]) / (edge[1] - edge[0]))
                        .min((edge[2] - hz) / (edge[2] - edge[1]));
                    (weight > 0.).then_some((bin, weight))
                })
                .collect()
        })
        .collect())
}

fn check_cancel(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    fn mel_scale_matches_htk_reference() {
        assert!((hz_to_mel(1000.) - 999.985537).abs() < 0.000001);
        for hz in [0., 100., 1000., 8000., 24000.] {
            assert!((mel_to_hz(hz_to_mel(hz)) - hz).abs() < 1e-8);
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
        let center =
            mel_to_hz(hz_to_mel(rate / 2.) * (strongest + 1) as f64 / (mel.bands + 1) as f64);
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
}
