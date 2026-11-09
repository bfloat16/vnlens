//! RFC 7845 Ogg Opus. Decode at the mandated 48 kHz granule clock, apply the
//! header gain, discard pre-skip and trim the final page. Ogg CRC/lacing is
//! handled by the existing ogg crate; opus1 decodes packets entirely in Rust.
use crate::{AudioMeta, Pcm};
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;
use ogg::reading::PacketReader;
use opus1::{SampleRate, multistream::MultistreamDecoder};
use std::{
    io::Cursor,
    sync::atomic::{AtomicBool, Ordering},
};
fn error(e: impl std::fmt::Display) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: format!("Ogg Opus: {e}"),
    }
}
fn cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
pub(super) fn recognizes(bytes: &[u8]) -> Result<bool> {
    let mut reader = PacketReader::new(Cursor::new(bytes));
    Ok(reader
        .read_packet_expected()
        .map_err(error)?
        .data
        .starts_with(b"OpusHead"))
}
struct Head {
    channels: u8,
    pre_skip: u16,
    gain: i16,
    streams: u8,
    coupled: u8,
    mapping: Vec<u8>,
}
impl Head {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(bytes);
        if r.read_bytes(8)? != b"OpusHead" {
            return Err(error("Missing identification header"));
        }
        let version = r.read_u8()?;
        if version == 0 || version & 0xf0 != 0 {
            return Err(Error::Unsupported("OpusHead major version".into()));
        }
        let channels = r.read_u8()?;
        let pre_skip = r.read_u16_le()?;
        r.read_u32_le()?;
        let gain = r.read_u16_le()? as i16;
        let family = r.read_u8()?;
        if channels == 0 {
            return Err(error("Zero channel count"));
        }
        let (streams, coupled, mapping) = match family {
            0 if channels <= 2 => (1, channels - 1, (0..channels).collect()),
            0 => return Err(error("Mapping family zero requires mono or stereo")),
            1 | 255 => {
                let streams = r.read_u8()?;
                let coupled = r.read_u8()?;
                let mapping = r.read_bytes(usize::from(channels))?.to_vec();
                let coded = u16::from(streams) + u16::from(coupled);
                if streams == 0
                    || coupled > streams
                    || coded > 255
                    || mapping.iter().any(|&n| n != 255 && u16::from(n) >= coded)
                {
                    return Err(error("Invalid channel mapping"));
                }
                (streams, coupled, mapping)
            }
            _ => return Err(Error::Unsupported("Opus channel mapping family".into())),
        };
        Ok(Self {
            channels,
            pre_skip,
            gain,
            streams,
            coupled,
            mapping,
        })
    }
}
pub(super) fn metadata(data: &[u8]) -> Result<AudioMeta> {
    read(data, &AtomicBool::new(false), false).map(|(meta, _)| meta)
}
pub(super) fn decode(data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
    let (meta, samples) = read(data, cancel, true)?;
    Ok(Pcm {
        meta,
        samples: samples.into(),
    })
}
fn read(data: &[u8], cancel: &AtomicBool, decode: bool) -> Result<(AudioMeta, Vec<f32>)> {
    cancelled(cancel)?;
    let mut reader = PacketReader::new(Cursor::new(data));
    let mut samples = Vec::new();
    let mut channels = None;
    let mut total_frames = 0u64;
    while let Some(first) = reader.read_packet().map_err(error)? {
        cancelled(cancel)?;
        if !first.first_in_stream() {
            return Err(error("Missing stream beginning"));
        }
        let head = Head::parse(&first.data)?;
        if channels.is_some_and(|n| n != head.channels) {
            return Err(Error::Unsupported(
                "Chained Opus streams change channel layout".into(),
            ));
        }
        channels = Some(head.channels);
        let count = usize::from(head.channels);
        let serial = first.stream_serial();
        let tags = reader.read_packet_expected().map_err(error)?;
        if tags.stream_serial() != serial || !tags.data.starts_with(b"OpusTags") {
            return Err(error("Missing comment header"));
        }
        let mut comments = BinaryReader::new_at(&tags.data, 8)?;
        let vendor = comments.read_u32_le()? as usize;
        comments.read_bytes(vendor)?;
        let comment_count = comments.read_u32_le()?;
        for _ in 0..comment_count {
            let size = comments.read_u32_le()? as usize;
            comments.read_bytes(size)?;
        }
        let mut decoder = if decode {
            let mut d = MultistreamDecoder::new(
                SampleRate::Hz48000,
                count,
                usize::from(head.streams),
                usize::from(head.coupled),
                &head.mapping,
            )
            .map_err(error)?;
            d.set_gain(head.gain);
            Some(d)
        } else {
            None
        };
        // RFC 6716 permits at most 120 ms per packet (5760 frames at 48 kHz).
        let mut block = if decode {
            vec![0.; 5760 * count]
        } else {
            Vec::new()
        };
        let start = samples.len();
        let mut decoded = 0u64;
        let mut origin = None;
        let mut final_frames = None;
        while let Some(packet) = reader.read_packet().map_err(error)? {
            cancelled(cancel)?;
            if packet.stream_serial() != serial {
                return Err(Error::Unsupported("Multiplexed Opus streams".into()));
            }
            if packet.data.is_empty() {
                return Err(error("Empty audio packet"));
            }
            let frames = if let Some(d) = &mut decoder {
                d.decode(&packet.data, 5760, &mut block).map_err(error)?
            } else {
                opus1::packet::nb_samples(&packet.data, SampleRate::Hz48000).map_err(error)?
            };
            if decode {
                let skip = u64::from(head.pre_skip)
                    .saturating_sub(decoded)
                    .min(frames as u64) as usize;
                samples.extend_from_slice(&block[skip * count..frames * count]);
            }
            decoded = decoded
                .checked_add(frames as u64)
                .ok_or_else(|| error("Frame count overflow"))?;
            if packet.last_in_page() && packet.absgp_page() != u64::MAX && origin.is_none() {
                origin = Some(if packet.last_in_stream() {
                    0
                } else {
                    packet
                        .absgp_page()
                        .checked_sub(decoded)
                        .ok_or_else(|| error("Invalid first granule position"))?
                });
            }
            if packet.last_in_stream() {
                let end = packet
                    .absgp_page()
                    .checked_sub(origin.unwrap_or(0))
                    .ok_or_else(|| error("Granule position before origin"))?;
                if end > decoded || end < u64::from(head.pre_skip) {
                    return Err(error("Invalid final granule position"));
                }
                let frames = end - u64::from(head.pre_skip);
                if decode {
                    let length = usize::try_from(frames)
                        .ok()
                        .and_then(|n| n.checked_mul(count))
                        .and_then(|n| start.checked_add(n))
                        .ok_or_else(|| error("PCM length overflow"))?;
                    samples.truncate(length);
                }
                final_frames = Some(frames);
                break;
            }
        }
        let frames =
            final_frames.unwrap_or_else(|| decoded.saturating_sub(u64::from(head.pre_skip)));
        total_frames = total_frames
            .checked_add(frames)
            .ok_or_else(|| error("Frame count overflow"))?;
    }
    let channels = u16::from(channels.ok_or_else(|| error("Empty Ogg stream"))?);
    Ok((
        AudioMeta {
            codec: "Ogg Opus",
            channels,
            sample_rate: 48000,
            frames: Some(total_frames),
        },
        samples,
    ))
}

#[cfg(test)]
#[path = "../../tests/standard/opus.rs"]
mod tests;
