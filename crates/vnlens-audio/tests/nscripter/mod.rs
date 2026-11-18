use super::*;
use vnlens_io::BinaryWriter;

#[test]
fn nbz_preserves_wave_rate_channels_and_samples() -> Result<()> {
    // Two signed 16-bit PCM samples in a complete little-endian RIFF/WAVE.
    let mut wav = vec![0; 48];
    wav[..4].copy_from_slice(b"RIFF");
    BinaryWriter::u32_le(40, &mut wav[4..]);
    wav[8..16].copy_from_slice(b"WAVEfmt ");
    BinaryWriter::u32_le(16, &mut wav[16..]);
    BinaryWriter::u16_le(1, &mut wav[20..]);
    BinaryWriter::u16_le(1, &mut wav[22..]);
    BinaryWriter::u32_le(22050, &mut wav[24..]);
    BinaryWriter::u32_le(44100, &mut wav[28..]);
    BinaryWriter::u16_le(2, &mut wav[32..]);
    BinaryWriter::u16_le(16, &mut wav[34..]);
    wav[36..40].copy_from_slice(b"data");
    BinaryWriter::u32_le(4, &mut wav[40..]);
    BinaryWriter::u16_le(0x8000, &mut wav[44..]);
    BinaryWriter::u16_le(0x4000, &mut wav[46..]);
    // bzip2-compressed fixtures are shared through a format-independent helper
    // in this test only; no game material is embedded.
    let compressed = fixture(&wav)?;
    let meta = Nbz.metadata(&compressed)?.ok_or(Error::InvalidFormat)?;
    assert_eq!((meta.channels, meta.sample_rate), (1, 22050));
    let pcm = Nbz.decode(&compressed)?;
    assert_eq!(pcm.samples.as_ref(), [-1.0, 0.5]);
    assert!(crate::metadata_as("audio/mpeg", &wav).is_err());
    assert!(Nbz.decode(&compressed[..compressed.len() - 4]).is_err());
    assert!(matches!(
        Nbz.decode_cancellable(&compressed, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}

fn fixture(wav: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut compressor = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
    compressor.write_all(wav)?;
    let mut out = vec![0; 4];
    BinaryWriter::u32_be(wav.len() as u32, &mut out);
    out.extend(compressor.finish()?);
    Ok(out)
}
