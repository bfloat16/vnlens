//! Native playback for the PCM produced by vnlens-audio.
use anyhow::{Result, anyhow};
use rodio::{DeviceSinkBuilder, MixerDeviceSink, Player, Source};
use std::num::NonZero;
use std::sync::Arc;
use std::time::Duration;
use vnlens_audio::Pcm;

pub struct Playback {
    pub player: Player,
    _device: MixerDeviceSink,
}
impl Playback {
    pub fn new(pcm: Pcm, position: Duration) -> Result<Self> {
        let mut source = PcmSource::new(pcm)?;
        source.try_seek(position)?;
        let device = DeviceSinkBuilder::open_default_sink()?;
        let player = Player::connect_new(device.mixer());
        player.append(source);
        Ok(Self {
            player,
            _device: device,
        })
    }
}

// Shared samples avoid copying an already-decoded entry into the player.
// Duration uses division first so long sources do not overflow nanoseconds.
struct PcmSource {
    samples: Arc<[f32]>,
    position: usize,
    channels: NonZero<u16>,
    rate: NonZero<u32>,
}
impl PcmSource {
    fn new(pcm: Pcm) -> Result<Self> {
        let channels =
            NonZero::new(pcm.meta.channels).ok_or_else(|| anyhow!("Zero audio channels"))?;
        let rate =
            NonZero::new(pcm.meta.sample_rate).ok_or_else(|| anyhow!("Zero audio sample rate"))?;
        Ok(Self {
            samples: pcm.samples,
            position: 0,
            channels,
            rate,
        })
    }
}
impl Iterator for PcmSource {
    type Item = f32;
    fn next(&mut self) -> Option<f32> {
        let sample = *self.samples.get(self.position)?;
        self.position += 1;
        Some(sample)
    }
}
impl Source for PcmSource {
    fn current_span_len(&self) -> Option<usize> {
        Some(self.samples.len() - self.position)
    }
    fn channels(&self) -> NonZero<u16> {
        self.channels
    }
    fn sample_rate(&self) -> NonZero<u32> {
        self.rate
    }
    fn total_duration(&self) -> Option<Duration> {
        let frames = self.samples.len() as u64 / u64::from(self.channels.get());
        Some(Duration::new(
            frames / u64::from(self.rate.get()),
            ((frames % u64::from(self.rate.get())) * 1_000_000_000 / u64::from(self.rate.get()))
                as u32,
        ))
    }
    fn try_seek(
        &mut self,
        position: Duration,
    ) -> std::result::Result<(), rodio::source::SeekError> {
        let frames = position
            .as_secs()
            .saturating_mul(u64::from(self.rate.get()))
            + u64::from(position.subsec_nanos()) * u64::from(self.rate.get()) / 1_000_000_000;
        self.position = usize::try_from(frames.saturating_mul(u64::from(self.channels.get())))
            .unwrap_or(usize::MAX)
            .min(self.samples.len());
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/playback.rs"]
mod tests;
