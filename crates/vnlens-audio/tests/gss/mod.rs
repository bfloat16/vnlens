use super::*;
use vnlens_io::BinaryWriter;
fn sample(channels: u8) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    for (at, value) in [
        (0, 0x8000_0001),
        (4, 0x18),
        (12, 48000),
        (16, 32),
        (32, 0x8000_0004),
        (36, 33),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    bytes[9] = channels;
    BinaryWriter::u16_le(120, &mut bytes[10..]);
    for _ in 0..3 {
        let mut header = [0; 8];
        BinaryWriter::u32_be(3, &mut header);
        bytes.extend(header);
        bytes.extend([0xf8, 0xff, 0xfe]);
    }
    bytes
}
#[test]
fn mono_stereo_packets_preskip_and_silence_match_golden_pcm() -> Result<()> {
    for channels in [1, 2] {
        let data = sample(channels);
        let meta = Opu.metadata(&data)?.ok_or(Error::InvalidFormat)?;
        assert_eq!(
            (meta.channels, meta.sample_rate, meta.frames),
            (u16::from(channels), 48000, Some(2760))
        );
        let pcm = Opu.decode(&data)?;
        assert_eq!(pcm.samples.len(), 2760 * usize::from(channels));
        assert!(pcm.samples.iter().all(|sample| sample.abs() < 1e-8));
    }
    Ok(())
}
#[test]
fn packet_truncation_corruption_version_and_cancellation_are_explicit() -> Result<()> {
    let data = sample(1);
    for end in 0..data.len() {
        assert!(Opu.metadata(&data[..end]).is_err());
    }
    let mut wrong = data.clone();
    wrong[0] = 0;
    assert!(matches!(Opu.metadata(&wrong), Err(Error::InvalidFormat)));
    wrong = data.clone();
    wrong[8] = 1;
    assert!(matches!(Opu.metadata(&wrong), Err(Error::Unsupported(_))));
    wrong = data.clone();
    BinaryWriter::u32_be(u32::MAX, &mut wrong[40..]);
    assert!(
        matches!(Opu.metadata(&wrong), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    assert!(matches!(
        Opu.decode_cancellable(&data, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
