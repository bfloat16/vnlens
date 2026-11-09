//! Ogg Vorbis metadata and decoding. YU-RIS stores these streams unchanged.
use crate::{AudioMeta, Pcm};
use lewton::inside_ogg::OggStreamReader;
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};

fn reader(data: &[u8]) -> Result<OggStreamReader<Cursor<&[u8]>>> {
    OggStreamReader::new(Cursor::new(data)).map_err(|e| corrupt(&e.to_string()))
}
pub(crate) fn metadata(data: &[u8]) -> Result<AudioMeta> {
    let reader = reader(data)?;
    let channels = u16::from(reader.ident_hdr.audio_channels);
    let sample_rate = reader.ident_hdr.audio_sample_rate;
    if channels == 0 || sample_rate == 0 {
        return Err(corrupt("Invalid Vorbis channel count or sample rate"));
    }
    let mut pages = BinaryReader::new(data);
    let mut frames = None;
    let mut serial = None;
    while pages.remaining() != 0 {
        if pages.read_bytes(4)? != b"OggS" || pages.read_u8()? != 0 {
            return Err(corrupt("Invalid Ogg page"));
        }
        let flags = pages.read_u8()?;
        let granule = pages.read_u64_le()?;
        let page_serial = pages.read_u32_le()?;
        pages.read_bytes(8)?;
        let count = usize::from(pages.read_u8()?);
        let size: usize = pages
            .read_bytes(count)?
            .iter()
            .map(|&n| usize::from(n))
            .sum();
        pages.read_bytes(size)?;
        if serial.is_none() {
            serial = Some(page_serial);
        }
        if serial == Some(page_serial) && flags & 4 != 0 && granule != u64::MAX {
            frames = Some(granule);
        }
    }
    Ok(AudioMeta {
        codec: "Ogg Vorbis",
        channels,
        sample_rate,
        frames,
    })
}
pub(crate) fn decode(data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let mut meta = metadata(data)?;
    let mut reader = reader(data)?;
    let mut samples = Vec::new();
    while let Some(packet) = reader
        .read_dec_packet_itl()
        .map_err(|e| corrupt(&e.to_string()))?
    {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        samples.extend(packet.into_iter().map(|sample| f32::from(sample) / 32768.));
    }
    if !samples.len().is_multiple_of(usize::from(meta.channels)) {
        return Err(corrupt("Vorbis decoder returned incomplete frames"));
    }
    meta.frames = Some(samples.len() as u64 / u64::from(meta.channels));
    Ok(Pcm {
        meta,
        samples: samples.into(),
    })
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: format!("Ogg Vorbis: {reason}"),
    }
}
