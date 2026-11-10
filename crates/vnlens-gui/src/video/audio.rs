//! Bounded PCM delivery to the output device. Demuxing, seeking and resampling
//! stay on the worker thread; the device callback never waits for decoding.

use anyhow::{Result, anyhow};
use rodio::{DeviceSinkBuilder, MixerDeviceSink, Player, Source};
use std::{
    collections::VecDeque,
    num::NonZero,
    sync::{
        Arc, Condvar, Mutex, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use vnlens_video::{AudioDecoder, AudioFrame, AudioStream};

// Playback watermarks, not limits on codec frame sizes. A complete decoded
// block is always accepted; consumption wakes the producer at the low end.
const PCM_QUEUE_SECONDS: f64 = 0.25;
const PCM_START_SECONDS: f64 = 0.1;

struct Buffer {
    target: f64,
    frames: VecDeque<AudioFrame>,
    seconds: f64,
    ended: bool,
    error: Option<String>,
}
struct Shared {
    buffer: Mutex<Buffer>,
    changed: Condvar,
    generation: AtomicU64,
    base: AtomicU64,
    consumed: AtomicU64,
    finished: AtomicBool,
    cancelled: Arc<AtomicBool>,
}
pub struct AudioOutput {
    pub player: Player,
    shared: Arc<Shared>,
    rate: NonZero<u32>,
    _device: MixerDeviceSink,
}
impl AudioOutput {
    pub fn new(
        input: crate::resource::VideoInput,
        meta: &AudioStream,
        position: f64,
    ) -> Result<Self> {
        let rate = NonZero::new(meta.sample_rate)
            .ok_or_else(|| anyhow!("Zero video audio sample rate"))?;
        let channels =
            NonZero::new(meta.channels).ok_or_else(|| anyhow!("Zero video audio channels"))?;
        let device = DeviceSinkBuilder::open_default_sink()?;
        let player = Player::connect_new(device.mixer());
        let shared = Arc::new(Shared {
            buffer: Mutex::new(Buffer {
                target: position,
                frames: VecDeque::new(),
                seconds: 0.,
                ended: false,
                error: None,
            }),
            changed: Condvar::new(),
            generation: AtomicU64::new(0),
            base: AtomicU64::new((position.max(0.) * f64::from(rate.get())).ceil() as u64),
            consumed: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let worker = shared.clone();
        std::thread::Builder::new()
            .name("video audio decoder".into())
            .spawn(move || decode(input, worker))?;
        player.append(PcmStream {
            shared: shared.clone(),
            channels,
            rate,
            generation: 0,
            samples: Vec::new().into_iter(),
            gap: 0,
            phase: 0,
            buffering: true,
            align: true,
        });
        Ok(Self {
            player,
            shared,
            rate,
            _device: device,
        })
    }
    pub fn seek(&self, position: f64) {
        if let Ok(mut buffer) = self.shared.buffer.lock() {
            buffer.target = position;
            buffer.frames.clear();
            buffer.seconds = 0.;
            buffer.ended = false;
            buffer.error = None;
            self.shared.base.store(
                (position.max(0.) * f64::from(self.rate.get())).ceil() as u64,
                Ordering::Release,
            );
            self.shared.consumed.store(0, Ordering::Release);
            self.shared.finished.store(false, Ordering::Release);
            self.shared.generation.fetch_add(1, Ordering::AcqRel);
        }
        self.shared.changed.notify_all();
    }
    pub fn position(&self) -> f64 {
        self.shared.base.load(Ordering::Acquire) as f64 / f64::from(self.rate.get())
            + self.shared.consumed.load(Ordering::Acquire) as f64 / f64::from(self.rate.get())
    }
    pub fn finished(&self) -> bool {
        self.shared.finished.load(Ordering::Acquire)
    }
    pub fn error(&self) -> Option<String> {
        self.shared
            .buffer
            .lock()
            .ok()
            .and_then(|mut buffer| buffer.error.take())
    }
}
impl Drop for AudioOutput {
    fn drop(&mut self) {
        self.shared.cancelled.store(true, Ordering::Relaxed);
        self.shared.changed.notify_all();
    }
}

fn decode(input: crate::resource::VideoInput, shared: Arc<Shared>) {
    // Retain a nested archive until the audio input has been destroyed.
    let _archive = input.archive;
    let opened = AudioDecoder::open(input.source, Some(&input.name), shared.cancelled.clone());
    let mut decoder = match opened {
        Ok(Some(decoder)) => decoder,
        result => {
            if let Ok(mut buffer) = shared.buffer.lock() {
                buffer.ended = true;
                buffer.error = result
                    .err()
                    .map(|error| format!("Video audio open: {error}"));
            }
            return;
        }
    };
    let mut generation = u64::MAX;
    let mut ended = false;
    loop {
        if shared.cancelled.load(Ordering::Relaxed) {
            return;
        }
        let current = shared.generation.load(Ordering::Acquire);
        if current != generation {
            let target = match shared.buffer.lock() {
                Ok(buffer) => buffer.target,
                Err(_) => return,
            };
            if generation != u64::MAX || target > 0. {
                let result = decoder.seek(target);
                let mut buffer = match shared.buffer.lock() {
                    Ok(buffer) => buffer,
                    Err(_) => return,
                };
                if shared.generation.load(Ordering::Acquire) != current {
                    continue;
                }
                if let Err(error) = result {
                    buffer.ended = true;
                    buffer.error = Some(format!("Video audio seek: {error}"));
                    ended = true;
                } else {
                    ended = false;
                }
            }
            generation = current;
        }
        let mut buffer = match shared.buffer.lock() {
            Ok(buffer) => buffer,
            Err(_) => return,
        };
        if ended || buffer.seconds >= PCM_QUEUE_SECONDS {
            match shared
                .changed
                .wait_timeout(buffer, Duration::from_millis(20))
            {
                Ok(_) => continue,
                Err(_) => return,
            }
        }
        drop(buffer);
        let frame = decoder.next_frame();
        buffer = match shared.buffer.lock() {
            Ok(buffer) => buffer,
            Err(_) => return,
        };
        if shared.cancelled.load(Ordering::Relaxed) {
            return;
        }
        if shared.generation.load(Ordering::Acquire) != generation {
            continue;
        }
        match frame {
            Ok(Some(frame)) => {
                buffer.seconds += frame_duration(&frame);
                buffer.frames.push_back(frame);
            }
            result => {
                ended = true;
                buffer.ended = true;
                buffer.error = result
                    .err()
                    .map(|error| format!("Video audio decode: {error}"));
            }
        }
    }
}

struct PcmStream {
    shared: Arc<Shared>,
    channels: NonZero<u16>,
    rate: NonZero<u32>,
    generation: u64,
    samples: std::vec::IntoIter<f32>,
    gap: u64,
    phase: u16,
    buffering: bool,
    /// Align the first PCM block after opening/seeking, then play continuously.
    align: bool,
}
impl PcmStream {
    fn advance(&mut self, media: bool) {
        self.phase += 1;
        if self.phase == self.channels.get() {
            self.phase = 0;
            if media && self.shared.generation.load(Ordering::Acquire) == self.generation {
                self.shared.consumed.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Called only between complete interleaved channel frames, including
    /// silence. The audio callback must never wait for a producer or seek lock.
    fn prepare(&mut self) -> Option<()> {
        let generation = self.shared.generation.load(Ordering::Acquire);
        if generation != self.generation {
            self.samples = Vec::new().into_iter();
            self.gap = 0;
            self.generation = generation;
            self.buffering = true;
            self.align = true;
        }
        loop {
            if self.gap != 0 || !self.samples.as_slice().is_empty() {
                return Some(());
            }
            let frame = match self.shared.buffer.try_lock() {
                Ok(mut buffer) => {
                    if self.shared.generation.load(Ordering::Acquire) != self.generation {
                        return Some(());
                    }
                    if self.buffering && !buffer.ended && buffer.seconds < PCM_START_SECONDS {
                        return Some(());
                    }
                    let frame = buffer.frames.pop_front();
                    if let Some(frame) = &frame {
                        buffer.seconds = (buffer.seconds - frame_duration(frame)).max(0.);
                    }
                    if buffer.frames.is_empty() {
                        buffer.seconds = 0.;
                    }
                    self.shared
                        .finished
                        .store(frame.is_none() && buffer.ended, Ordering::Release);
                    self.buffering = frame.is_none() && !buffer.ended;
                    frame
                }
                Err(TryLockError::WouldBlock) => return Some(()),
                Err(TryLockError::Poisoned(_)) => return None,
            };
            self.shared.changed.notify_one();
            let Some(mut frame) = frame else {
                return Some(());
            };
            if self.align {
                let start = (frame.time.max(0.) * f64::from(self.rate.get())).round() as u64;
                let current = self.shared.base.load(Ordering::Acquire);
                let channels = usize::from(self.channels.get());
                if start < current {
                    let skip = usize::try_from(current - start)
                        .unwrap_or(usize::MAX)
                        .min(frame.samples.len() / channels);
                    frame.samples.drain(..skip * channels);
                } else {
                    self.gap = (start - current).saturating_mul(u64::from(self.channels.get()));
                }
                self.align = frame.samples.is_empty();
            }
            // Packet timestamps (notably WMA superframes in ASF) can overlap
            // or jitter. They must not splice silence into or cut decoded PCM.
            self.samples = frame.samples.into_iter();
        }
    }
}

impl Iterator for PcmStream {
    type Item = f32;
    fn next(&mut self) -> Option<f32> {
        if self.shared.cancelled.load(Ordering::Relaxed) {
            return None;
        }
        if self.phase == 0 {
            self.prepare()?;
        }
        if self.gap != 0 {
            self.gap -= 1;
            self.advance(true);
            return Some(0.);
        }
        if let Some(sample) = self.samples.next() {
            self.advance(true);
            return Some(sample);
        }
        // Finish a whole silent channel frame even if PCM arrives meanwhile.
        // Underrun silence does not advance the presentation clock.
        self.advance(false);
        Some(0.)
    }
}

fn frame_duration(frame: &AudioFrame) -> f64 {
    frame.samples.len() as f64 / f64::from(frame.channels) / f64::from(frame.sample_rate)
}
impl Source for PcmStream {
    fn current_span_len(&self) -> Option<usize> {
        None
    }
    fn channels(&self) -> NonZero<u16> {
        self.channels
    }
    fn sample_rate(&self) -> NonZero<u32> {
        self.rate
    }
    fn total_duration(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
#[path = "../../tests/video/audio.rs"]
mod tests;
