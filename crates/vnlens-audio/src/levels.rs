//! Per-channel sample peak and RMS envelopes, referenced to digital full scale
//! (amplitude 1). Twenty-millisecond blocks cover every PCM frame, including the
//! final partial block. Queries aggregate blocks without scanning PCM on the UI.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use vnlens_core::{Error, Result};

use crate::Pcm;

/// Unclipped dBFS values. Silence is negative infinity; samples above full
/// scale produce positive readings. Peak is sample peak, not intersample peak.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Level {
    pub peak_dbfs: f32,
    pub rms_dbfs: f32,
}

impl Default for Level {
    fn default() -> Self {
        Self {
            peak_dbfs: f32::NEG_INFINITY,
            rms_dbfs: f32::NEG_INFINITY,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Power {
    peak: f64,
    sum_squares: f64,
}

#[derive(Debug)]
pub struct LevelEnvelope {
    channels: usize,
    sample_rate: u32,
    frames: usize,
    block_frames: usize,
    blocks: Vec<Power>,
}

impl LevelEnvelope {
    /// Borrows PCM, rejecting invalid layouts and non-finite samples. Responds
    /// to cancellation between blocks. No audio data is retained or modified.
    pub fn new(pcm: &Pcm, cancelled: &AtomicBool) -> Result<Self> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let channels = usize::from(pcm.meta.channels);
        if channels == 0 || pcm.meta.sample_rate == 0 || !pcm.samples.len().is_multiple_of(channels)
        {
            return Err(Error::Corrupt {
                offset: 0,
                reason: "Invalid level meter PCM layout".into(),
            });
        }
        let block_frames = usize::try_from(pcm.meta.sample_rate.div_ceil(50))
            .map_err(|_| Error::Unsupported("PCM sample rate exceeds address space".into()))?;
        let block_samples = block_frames
            .checked_mul(channels)
            .ok_or_else(|| Error::Unsupported("PCM block exceeds address space".into()))?;
        let mut blocks = Vec::new();
        for samples in pcm.samples.chunks(block_samples) {
            if cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let offset = blocks.len();
            blocks.resize(offset + channels, Power::default());
            for frame in samples.chunks_exact(channels) {
                for (channel, &sample) in frame.iter().enumerate() {
                    if !sample.is_finite() {
                        return Err(Error::Corrupt {
                            offset: 0,
                            reason: "Non-finite PCM sample".into(),
                        });
                    }
                    let value = f64::from(sample);
                    let power = &mut blocks[offset + channel];
                    power.peak = power.peak.max(value.abs());
                    power.sum_squares += value * value;
                }
            }
        }
        Ok(Self {
            channels,
            sample_rate: pcm.meta.sample_rate,
            frames: pcm.samples.len() / channels,
            block_frames,
            blocks,
        })
    }

    /// Aggregates all blocks touched by the inclusive time interval. Endpoints
    /// are rounded outward to block boundaries (at most 20ms at normal rates).
    /// Equal endpoints read the current block; empty or reversed ranges are
    /// silent. RMS uses the actual frame count, including the final short block.
    #[must_use]
    pub fn read(&self, start: Duration, end: Duration) -> Vec<Level> {
        let frame = |time: Duration| {
            let index = u128::from(time.as_secs()) * u128::from(self.sample_rate)
                + u128::from(time.subsec_nanos()) * u128::from(self.sample_rate) / 1_000_000_000;
            usize::try_from(index).unwrap_or(usize::MAX)
        };
        let first_frame = frame(start);
        if start > end || first_frame >= self.frames {
            return vec![Level::default(); self.channels];
        }
        let first = first_frame / self.block_frames;
        let last = frame(end).min(self.frames - 1) / self.block_frames;
        let mut powers = vec![Power::default(); self.channels];
        let mut frames = 0;
        for block in first..=last {
            frames += (self.frames - block * self.block_frames).min(self.block_frames);
            for (sum, power) in powers
                .iter_mut()
                .zip(&self.blocks[block * self.channels..][..self.channels])
            {
                sum.peak = sum.peak.max(power.peak);
                sum.sum_squares += power.sum_squares;
            }
        }
        powers
            .into_iter()
            .map(|power| Level {
                peak_dbfs: (20. * power.peak.log10()) as f32,
                rms_dbfs: (10. * (power.sum_squares / frames as f64).log10()) as f32,
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../tests/levels.rs"]
mod tests;
