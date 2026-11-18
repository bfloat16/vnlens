use super::*;

#[test]
fn mp3_metadata_decode_cancel_and_rejects_non_mpeg() -> Result<()> {
    // Minimal MPEG-1 Layer III 128 kbps 44100 Hz mono frames (3 consecutive 417-byte frames).
    let mut frame = vec![0; 417];
    frame[..4].copy_from_slice(&[0xff, 0xfb, 0x90, 0xc4]);
    let stream = frame.repeat(3);
    let meta = Mp3.metadata(&stream)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(meta.codec, "MP3");
    assert_eq!(meta.channels, 1);
    assert_eq!(meta.sample_rate, 44100);
    let pcm = Mp3.decode(&stream)?;
    assert!(!pcm.samples.is_empty());
    assert!(matches!(
        Mp3.decode_cancellable(&stream, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(Mp3.metadata(b"RIFF\x24\0\0\0WAVEfmt ").is_err());
    Ok(())
}
