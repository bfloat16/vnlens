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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    fn wrapped(wav: &[u8], kind: u8) -> Vec<u8> {
        let mut data = b"IF PACKTYPE==0  CUT THIS 64 BYTETHEN REMAKE WAV PACKTYPE=0      ".to_vec();
        data[13] = b'0' + kind;
        data[57] = b'0' + kind;
        data.extend_from_slice(wav);
        data
    }
    #[test]
    fn wrapped_pcm_matches_standard_decoder_and_cancels() {
        let pcm = Pcm {
            meta: AudioMeta {
                codec: "WAV PCM",
                channels: 1,
                sample_rate: 22050,
                frames: Some(3),
            },
            samples: vec![0.0, 0.5, -0.5].into(),
        };
        let wav = pcm.to_wav().unwrap();
        let bytes = wrapped(&wav, 0);
        let decoded = Vaw.decode(&bytes).unwrap();
        assert_eq!(&*decoded.samples, &*pcm.samples);
        assert_eq!(decoded.meta.frames, Some(3));
        for len in 0..bytes.len() {
            assert!(Vaw.decode(&bytes[..len]).is_err());
        }
        assert!(matches!(
            Vaw.decode_cancellable(&bytes, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
    }
    #[test]
    fn ogg_prefix_uses_declared_format_size_not_a_fixed_offset() {
        for fmt_size in [16usize, 40, 64] {
            let mut wav = vec![0; 20 + fmt_size + 8];
            wav[..4].copy_from_slice(b"RIFF");
            wav[8..16].copy_from_slice(b"WAVEfmt ");
            BinaryWriter::u32_le(fmt_size as u32, &mut wav[16..]);
            wav[20 + fmt_size..24 + fmt_size].copy_from_slice(b"data");
            wav.extend_from_slice(b"OggSsynthetic packet");
            let bytes = wrapped(&wav, 2);
            assert_eq!(payload(&bytes).unwrap().unwrap(), b"OggSsynthetic packet");
            for len in 0..bytes.len() - 16 {
                assert!(
                    payload(&bytes[..len]).is_err() || payload(&bytes[..len]).unwrap().is_none()
                );
            }
        }
        let mut direct = vec![b' '; 64];
        direct[16..20].copy_from_slice(b"OGG ");
        direct[48..58].copy_from_slice(b"PACKTYPE=6");
        direct.extend_from_slice(b"OggS");
        assert_eq!(payload(&direct).unwrap().unwrap(), b"OggS");
        assert!(payload(b"OggS").unwrap().is_none());
    }
}
