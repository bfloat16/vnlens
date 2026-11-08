//! BGI BW/HW wave boxes. The 0x40-byte little-endian header selects codec at
//! 0x30 and payload offset at 0. sub_140113870 dispatches codec 3 to the Ogg
//! decoder; the embedded stream retains its own rate/channel/granule metadata.

use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;
use std::sync::atomic::AtomicBool;

#[derive(Debug, Default)]
struct BgiAudio;

#[derive(Debug)]
struct Header {
    offset: usize,
    size: usize,
    codec: u32,
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        let offset = r.read_u32_le()? as usize;
        if !matches!(r.read_bytes(4)?, b"bw  " | b"hw  ") {
            return Err(Error::InvalidFormat);
        }
        let size = r.read_u32_le()? as usize;
        r.read_bytes(36)?;
        let codec = r.read_u32_le()?;
        r.read_bytes(12)?;
        if offset < r.position() {
            return Err(Error::Corrupt {
                offset: 0,
                reason: "BW payload overlaps header".into(),
            });
        }
        Ok(Self {
            offset,
            size,
            codec,
        })
    }
}

/// Returns the original Ogg payload without transcoding. Called on demand by
/// archive extraction and by this decoder. Non-BW data is left to the caller.
pub fn ogg_payload(data: &[u8]) -> Result<Option<&[u8]>> {
    if !matches!(data.get(4..8), Some(b"bw  " | b"hw  ")) {
        return Ok(None);
    }
    let header = Header::parse(data)?;
    if header.codec != 3 {
        return Err(Error::Unsupported(format!(
            "BGI wave codec {}",
            header.codec
        )));
    }
    let mut r = BinaryReader::new_at(data, header.offset)?;
    Ok(Some(r.read_bytes(header.size)?))
}

impl Format for BgiAudio {
    fn tag(&self) -> &'static str {
        "bw/bgi"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bw", "hw", "_bw"]
    }
    fn description(&self) -> &'static str {
        "BGI BW/HW Ogg Vorbis audio"
    }
}
impl AudioFormat for BgiAudio {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        ogg_payload(data)?
            .map(crate::standard::ogg::metadata)
            .transpose()
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
        crate::standard::ogg::decode(ogg_payload(data)?.ok_or(Error::InvalidFormat)?, cancelled)
    }
}
nvlens_core::inventory::submit! {AudioRegistration(|| Box::new(BgiAudio))}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    #[test]
    fn wave_box_preserves_ogg_payload_and_checks_header_bounds() -> Result<()> {
        let mut bytes = vec![0; 64];
        BinaryWriter::u32_le(64, &mut bytes);
        bytes[4..8].copy_from_slice(b"bw  ");
        BinaryWriter::u32_le(4, &mut bytes[8..]);
        BinaryWriter::u32_le(3, &mut bytes[48..]);
        bytes.extend(b"OggS");
        assert_eq!(ogg_payload(&bytes)?, Some(b"OggS".as_slice()));
        for length in [8, 47, 63, 67] {
            assert!(ogg_payload(&bytes[..length]).is_err());
        }
        BinaryWriter::u32_le(1, &mut bytes[48..]);
        assert!(matches!(ogg_payload(&bytes), Err(Error::Unsupported(_))));
        assert!(ogg_payload(b"unrelated")?.is_none());
        Ok(())
    }
}
