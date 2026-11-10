use super::*;
use vnlens_io::BinaryWriter;

/// Ten 4x2 YUV 4:4:4 frames at 10 fps; frame `i` has luma `16 + 20 * i`.
fn y4m() -> Arc<[u8]> {
    let mut bytes = b"YUV4MPEG2 W4 H2 F10:1 Ip A1:1 C444\n".to_vec();
    for index in 0..10u8 {
        bytes.extend_from_slice(b"FRAME\n");
        bytes.extend([16 + 20 * index; 8]);
        bytes.extend([128; 16]);
    }
    bytes.into()
}

/// 100 ms of 8 kHz stereo PCM: left +0.5, right -0.5.
fn wav() -> Arc<[u8]> {
    let frames = 800u32;
    let data = frames * 4;
    let mut bytes = vec![0; 44];
    bytes[0..4].copy_from_slice(b"RIFF");
    BinaryWriter::u32_le(36 + data, &mut bytes[4..]);
    bytes[8..16].copy_from_slice(b"WAVEfmt ");
    BinaryWriter::u32_le(16, &mut bytes[16..]);
    BinaryWriter::u16_le(1, &mut bytes[20..]);
    BinaryWriter::u16_le(2, &mut bytes[22..]);
    BinaryWriter::u32_le(8000, &mut bytes[24..]);
    BinaryWriter::u32_le(8000 * 4, &mut bytes[28..]);
    BinaryWriter::u16_le(4, &mut bytes[32..]);
    BinaryWriter::u16_le(16, &mut bytes[34..]);
    bytes[36..40].copy_from_slice(b"data");
    BinaryWriter::u32_le(data, &mut bytes[40..]);
    let mut sample = [0; 2];
    for _ in 0..frames {
        for value in [16384u16, 16384u16.wrapping_neg()] {
            BinaryWriter::u16_le(value, &mut sample);
            bytes.extend(sample);
        }
    }
    bytes.into()
}

/// Limited-range luma expanded to full range, as swscale does for BT.601.
fn gray(luma: u8) -> f64 {
    (f64::from(luma) - 16.) * 255. / 219.
}

fn assert_gray(picture: &Picture, luma: u8) {
    assert_eq!((picture.width, picture.height), (4, 2));
    assert_eq!(picture.bgra.len(), 4 * 2 * 4);
    for pixel in picture.bgra.as_chunks::<4>().0 {
        for &channel in &pixel[..3] {
            assert!(
                (f64::from(channel) - gray(luma)).abs() <= 2.,
                "{pixel:?} for luma {luma}"
            );
        }
        assert_eq!(pixel[3], 255);
    }
}

#[test]
fn opens_metadata_and_decodes_pictures_in_order() -> Result<()> {
    let mut video = Video::open_source_as(
        "ffmpeg",
        Arc::new(y4m()),
        Some("test.y4m"),
        Arc::new(AtomicBool::new(false)),
    )?
    .ok_or(Error::InvalidFormat)?;
    let meta = video.meta();
    assert_eq!(meta.container, "yuv4mpegpipe");
    assert_eq!(meta.video.codec, "rawvideo");
    assert_eq!((meta.video.width, meta.video.height), (4, 2));
    assert_eq!(meta.video.frame_rate, Some(10.));
    assert!(meta.audio.is_none());
    assert!(
        meta.duration
            .is_some_and(|duration| (duration - 1.).abs() < 1e-6)
    );
    for index in 0..10u8 {
        let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
        assert!((picture.time - f64::from(index) / 10.).abs() < 1e-6);
        assert_gray(&picture, 16 + 20 * index);
    }
    assert!(video.next_picture()?.is_none());
    Ok(())
}

#[test]
fn seek_lands_on_the_requested_picture_in_both_directions() -> Result<()> {
    let mut video = Video::open_source_as(
        "ffmpeg",
        Arc::new(y4m()),
        Some("test.y4m"),
        Arc::new(AtomicBool::new(false)),
    )?
    .ok_or(Error::InvalidFormat)?;
    assert!(video.seek(f64::NAN).is_err());
    video.seek(0.5)?;
    let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert!((picture.time - 0.5).abs() < 1e-6);
    assert_gray(&picture, 116);
    video.seek(0.2)?;
    let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert!((picture.time - 0.2).abs() < 1e-6);
    assert_gray(&picture, 56);
    // Between frames, the picture still on screen is returned.
    video.seek(0.75)?;
    let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert!((picture.time - 0.7).abs() < 1e-6);
    assert_gray(&picture, 156);
    video.seek(0.95)?;
    let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert!((picture.time - 0.9).abs() < 1e-6);
    assert!(video.next_picture()?.is_none());
    Ok(())
}

#[test]
fn audio_is_interleaved_f32_at_the_source_rate() -> Result<()> {
    let mut decoder = AudioDecoder::open(
        Arc::new(wav()),
        Some("test.wav"),
        Arc::new(AtomicBool::new(false)),
    )?
    .ok_or(Error::InvalidFormat)?;
    assert_eq!(
        (decoder.meta().channels, decoder.meta().sample_rate),
        (2, 8000)
    );
    let mut samples = Vec::new();
    while let Some(frame) = decoder.next_frame()? {
        samples.extend(frame.samples);
    }
    assert_eq!(samples.len(), 1600);
    for frame in samples.as_chunks::<2>().0 {
        assert_eq!(*frame, [0.5, -0.5]);
    }
    Ok(())
}

#[test]
fn audio_only_container_has_no_video_and_video_has_no_audio() -> Result<()> {
    assert!(
        Video::open_source_as(
            "ffmpeg",
            Arc::new(wav()),
            Some("test.wav"),
            Arc::new(AtomicBool::new(false)),
        )?
        .is_none()
    );
    assert!(
        AudioDecoder::open(
            Arc::new(y4m()),
            Some("test.y4m"),
            Arc::new(AtomicBool::new(false)),
        )?
        .is_none()
    );
    Ok(())
}

#[test]
fn cancelled_audio_decode_stops() {
    assert!(matches!(
        AudioDecoder::open(
            Arc::new(wav()),
            Some("test.wav"),
            Arc::new(AtomicBool::new(true)),
        ),
        Err(Error::Cancelled)
    ));
}

#[test]
fn unrecognized_bytes_are_an_error() {
    assert!(
        Video::open_source_as(
            "ffmpeg",
            Arc::new(Arc::<[u8]>::from(vec![0; 64])),
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .is_err()
    );
    assert!(
        Video::open_source_as(
            "ffmpeg",
            Arc::new(Arc::<[u8]>::from(Vec::new())),
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .is_err()
    );
}
