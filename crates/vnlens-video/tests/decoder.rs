use super::*;
use vnlens_io::BinaryWriter;

/// Set VNLENS_ARTEMIS_DIR to the local WorldActorGB installation, then run
/// cargo test -p vnlens-video artemis_stream -- --ignored --nocapture.
#[test]
#[ignore = "Requires the local Artemis game; no GUI or playback device is started"]
fn artemis_stream_decodes_theora_from_pfs_and_loose_wmv() -> Result<()> {
    use vnlens_core::{Catalog, ResourceOrigin, ResourceRoute};
    let root = std::path::PathBuf::from(
        std::env::var_os("VNLENS_ARTEMIS_DIR")
            .ok_or_else(|| Error::Unsupported("Set VNLENS_ARTEMIS_DIR".into()))?,
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let game = vnlens_engine::identify(&root, &cancel)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, vnlens_engine::Engine::Artemis);
    vnlens_archive::init();
    let path = root.join("WorldActorGB.pfs");
    let ResourceRoute::Archive(route) = game.route_path(&path)? else {
        return Err(Error::InvalidFormat);
    };
    let archive = Catalog::load()
        .open_view(Arc::new(game.files.open(&path)?), &route)?
        .archive;
    let entry = archive
        .entries()
        .iter()
        .find(|e| e.name.ends_with(".ogv"))
        .ok_or(Error::InvalidFormat)?;
    let ResourceRoute::Media { video: tag, .. } =
        game.resource_route(&entry.name, ResourceOrigin::Entry(entry.kind), &[])
    else {
        return Err(Error::InvalidFormat);
    };
    let source = archive
        .open_entry_source(entry)?
        .ok_or(Error::InvalidFormat)?;
    assert!(contains_video(source.clone(), cancel.clone())?);
    let mut video = Video::open_source_as(tag, source, Some(&entry.name), cancel.clone())?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(video.meta().video.codec, "theora");
    let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
    assert!(!picture.bgra.is_empty());
    video.seek(0.1)?;
    assert!(video.next_picture()?.is_some());
    eprintln!(
        "Artemis PFS: {}x{} Theora frame and seek verified",
        picture.width, picture.height
    );
    let mut movies = 0;
    for file in game.files.read_dir(&root.join("movie"))? {
        if file.metadata.directory {
            continue;
        }
        let ResourceRoute::Video(tag) = game.route_path(&file.path)? else {
            continue;
        };
        let mut video = Video::open_source_as(
            tag,
            game.files.source(&file.path)?,
            Some(&file.path.to_string_lossy()),
            cancel.clone(),
        )?
        .ok_or(Error::InvalidFormat)?;
        let picture = video.next_picture()?.ok_or(Error::InvalidFormat)?;
        assert!(!picture.bgra.is_empty());
        movies += 1;
    }
    assert_eq!(movies, 2);
    eprintln!("Artemis: {movies} WMV first frames verified");
    Ok(())
}

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
    let mut decoder = AudioDecoder::open_source_as(
        "ffmpeg",
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
        AudioDecoder::open_source_as(
            "ffmpeg",
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
        AudioDecoder::open_source_as(
            "ffmpeg",
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
