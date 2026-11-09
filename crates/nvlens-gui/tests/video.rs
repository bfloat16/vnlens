use super::*;
use std::time::Instant;

fn wait_for_queue(decoder: &Decoder, generation: u64) -> Result<usize> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let messages = decoder
            .pictures
            .messages
            .lock()
            .map_err(|_| anyhow!("Poisoned picture queue"))?;
        let ready = messages
            .iter()
            .filter(|message| matches!(message, Message::Picture(id, _) if *id == generation))
            .count();
        if ready >= PICTURE_QUEUE_CAPACITY {
            return Ok(messages.len());
        }
        if let Some(Message::Error(_, error)) = messages.back() {
            return Err(anyhow!("{error}"));
        }
        drop(messages);
        if Instant::now() >= deadline {
            return Err(anyhow!("Timed out waiting for decoded pictures"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn paused_picture_queue_stays_bounded_and_seek_replaces_queued_frames() -> Result<()> {
    let mut bytes = b"YUV4MPEG2 W4 H2 F60:1 Ip A1:1 C444\n".to_vec();
    for _ in 0..600 {
        bytes.extend_from_slice(b"FRAME\n");
        bytes.extend([128; 24]);
    }
    let bytes: Arc<[u8]> = bytes.into();
    let mut decoder = Decoder::open(
        crate::resource::VideoInput {
            tag: "ffmpeg",
            source: Arc::new(bytes),
            name: "queue.y4m".into(),
            archive: None,
        },
        Arc::new(AtomicBool::new(false)),
    )?
    .ok_or_else(|| anyhow!("Missing video stream"))?;
    assert_eq!(wait_for_queue(&decoder, 0)?, PICTURE_QUEUE_CAPACITY);
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(wait_for_queue(&decoder, 0)?, PICTURE_QUEUE_CAPACITY);
    decoder.seek(5.);
    assert_eq!(wait_for_queue(&decoder, 1)?, PICTURE_QUEUE_CAPACITY);
    let Some(Output::Picture(picture)) = decoder.poll() else {
        return Err(anyhow!("Missing picture after seek"));
    };
    assert!((picture.time - 5.).abs() < 1e-6);
    Ok(())
}

/// Set NVLENS_VIDEO_SAMPLE to a locally owned movie. No device or GUI is opened.
/// Run `cargo test -p nvlens-gui local_video_queue -- --ignored --nocapture`.
#[test]
#[ignore = "requires a locally owned movie in NVLENS_VIDEO_SAMPLE"]
fn local_video_queue() -> Result<()> {
    let path = std::path::PathBuf::from(
        std::env::var_os("NVLENS_VIDEO_SAMPLE")
            .ok_or_else(|| anyhow!("Set NVLENS_VIDEO_SAMPLE"))?,
    );
    let input = crate::resource::VideoInput {
        tag: "ffmpeg",
        source: Arc::new(nvlens_io::ArcView::open(&path)?),
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        archive: None,
    };
    let mut decoder = Decoder::open(input, Arc::new(AtomicBool::new(false)))?
        .ok_or_else(|| anyhow!("Missing video stream"))?;
    for position in [0., 5., 1.] {
        if position != 0. {
            decoder.seek(position);
        }
        wait_for_queue(&decoder, decoder.generation)?;
        std::thread::sleep(Duration::from_millis(80));
        let messages = decoder
            .pictures
            .messages
            .lock()
            .map_err(|_| anyhow!("Poisoned picture queue"))?;
        assert_eq!(messages.len(), PICTURE_QUEUE_CAPACITY);
        let bytes: usize = messages
            .iter()
            .filter_map(|message| match message {
                Message::Picture(_, picture) => Some(picture.bgra.len()),
                _ => None,
            })
            .sum();
        eprintln!(
            "{} at {position}s: {} queued pictures, {bytes} BGRA bytes",
            path.display(),
            messages.len()
        );
    }
    Ok(())
}
