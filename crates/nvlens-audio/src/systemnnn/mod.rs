//! NNN VAW/WGQ envelopes: PACKTYPE at +48 selects PCM RIFF (0), Ogg
//! after a RIFF/fmt/data header (2), or direct Ogg (6). NNNLib advances by
//! fmt's declared size; the common 108-byte prefix is not a fixed offset.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm, standard::StandardAudio};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;
use std::sync::atomic::AtomicBool;

const SIGNATURES: &[u32] = &[0x5020_4649, 0x2020_2020];
#[derive(Debug, Default)]
struct Vaw;
impl Format for Vaw {
    fn tag(&self) -> &'static str {
        "vaw/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vaw", "wgq"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN VAW/WGQ PCM and Ogg audio"
    }
}
fn payload(data: &[u8]) -> Result<Option<&[u8]>> {
    if !((data.starts_with(b"IF PACKTYPE==")
        && matches!(data.get(44..48), Some(b"WAV " | b"OGG ")))
        || data.get(..20) == Some(b"                OGG "))
    {
        return Ok(None);
    }
    let mut r = BinaryReader::new(data);
    r.read_bytes(48)?;
    let kind = r.read_bytes(16)?.trim_ascii();
    match kind {
        b"PACKTYPE=0" => {
            if r.read_bytes(4)? != b"RIFF" {
                return Err(Error::InvalidFormat);
            }
            Ok(Some(&data[64..]))
        }
        b"PACKTYPE=2" => {
            if r.read_bytes(4)? != b"RIFF" {
                return Err(Error::InvalidFormat);
            }
            r.read_u32_le()?; // Original PCM length, not the stored Ogg size.
            if r.read_bytes(8)? != b"WAVEfmt " {
                return Err(Error::InvalidFormat);
            }
            let size = r.read_u32_le()? as usize;
            r.read_bytes(size)?;
            if r.read_bytes(4)? != b"data" {
                return Err(Error::InvalidFormat);
            }
            r.read_u32_le()?; // Original PCM data length.
            let offset = r.position();
            if r.read_bytes(4)? != b"OggS" {
                return Err(Error::InvalidFormat);
            }
            Ok(Some(&data[offset..]))
        }
        b"PACKTYPE=6" => {
            if r.read_bytes(4)? != b"OggS" {
                return Err(Error::InvalidFormat);
            }
            Ok(Some(&data[64..]))
        }
        _ => Err(Error::Unsupported("SystemNNN audio packing method".into())),
    }
}
impl AudioFormat for Vaw {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        let Some(data) = payload(data)? else {
            return Ok(None);
        };
        StandardAudio.metadata(data)
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
        StandardAudio.decode_cancellable(payload(data)?.ok_or(Error::InvalidFormat)?, cancelled)
    }
}
nvlens_core::inventory::submit! { AudioRegistration(||Box::new(Vaw)) }

#[cfg(test)]
#[path = "../../tests/systemnnn/mod.rs"]
mod tests;
