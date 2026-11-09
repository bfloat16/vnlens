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
#[path = "../tests/spectrogram.rs"]
mod tests;
