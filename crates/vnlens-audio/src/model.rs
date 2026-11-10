//! Interleaved floating-point PCM and WAV/RF64 export.
use std::sync::Arc;
use vnlens_core::{Error, Result};
use vnlens_io::BinaryWriter;

#[derive(Clone, Debug)]
pub struct AudioMeta {
    pub codec: &'static str,
    pub channels: u16,
    pub sample_rate: u32,
    pub frames: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Pcm {
    pub meta: AudioMeta,
    pub samples: Arc<[f32]>,
}
impl Pcm {
    /// Exports IEEE float WAV; RF64 carries sizes exceeding RIFF's 32-bit fields.
    pub fn to_wav(&self) -> Result<Vec<u8>> {
        if self.meta.channels == 0
            || self.meta.sample_rate == 0
            || !self
                .samples
                .len()
                .is_multiple_of(usize::from(self.meta.channels))
        {
            return Err(Error::Corrupt {
                offset: 0,
                reason: "Invalid PCM channel/frame layout".into(),
            });
        }
        let data_size = (self.samples.len() as u64)
            .checked_mul(4)
            .ok_or_else(|| Error::Unsupported("PCM size overflow".into()))?;
        let rf64 = data_size + 48 > u64::from(u32::MAX);
        let header_size = if rf64 { 92 } else { 56 };
        let mut bytes = vec![0; header_size];
        bytes[..4].copy_from_slice(if rf64 { b"RF64" } else { b"RIFF" });
        BinaryWriter::u32_le(
            if rf64 {
                u32::MAX
            } else {
                (data_size + header_size as u64 - 8) as u32
            },
            &mut bytes[4..],
        );
        bytes[8..12].copy_from_slice(b"WAVE");
        let frames = self.samples.len() as u64 / u64::from(self.meta.channels);
        let mut at = 12;
        if rf64 {
            bytes[at..at + 4].copy_from_slice(b"ds64");
            BinaryWriter::u32_le(28, &mut bytes[at + 4..]);
            BinaryWriter::u64_le(data_size + header_size as u64 - 8, &mut bytes[at + 8..]);
            BinaryWriter::u64_le(data_size, &mut bytes[at + 16..]);
            BinaryWriter::u64_le(frames, &mut bytes[at + 24..]);
            at += 36;
        }
        bytes[at..at + 4].copy_from_slice(b"fmt ");
        BinaryWriter::u32_le(16, &mut bytes[at + 4..]);
        BinaryWriter::u16_le(3, &mut bytes[at + 8..]);
        BinaryWriter::u16_le(self.meta.channels, &mut bytes[at + 10..]);
        BinaryWriter::u32_le(self.meta.sample_rate, &mut bytes[at + 12..]);
        let align = self.meta.channels.checked_mul(4).ok_or_else(|| {
            Error::Unsupported("WAV channel alignment exceeds format field".into())
        })?;
        let rate = self
            .meta
            .sample_rate
            .checked_mul(u32::from(align))
            .ok_or_else(|| Error::Unsupported("WAV byte rate exceeds format field".into()))?;
        BinaryWriter::u32_le(rate, &mut bytes[at + 16..]);
        BinaryWriter::u16_le(align, &mut bytes[at + 20..]);
        BinaryWriter::u16_le(32, &mut bytes[at + 22..]);
        at += 24;
        bytes[at..at + 4].copy_from_slice(b"fact");
        BinaryWriter::u32_le(4, &mut bytes[at + 4..]);
        BinaryWriter::u32_le(frames.min(u64::from(u32::MAX)) as u32, &mut bytes[at + 8..]);
        at += 12;
        bytes[at..at + 4].copy_from_slice(b"data");
        BinaryWriter::u32_le(
            if rf64 { u32::MAX } else { data_size as u32 },
            &mut bytes[at + 4..],
        );
        for &sample in &*self.samples {
            let mut encoded = [0; 4];
            BinaryWriter::f32_le(sample, &mut encoded);
            bytes.extend(encoded);
        }
        Ok(bytes)
    }
}
