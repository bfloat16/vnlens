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
    decoder.seek(8.);
    let superseded = decoder.seek_cancel.clone();
    decoder.seek(0.25);
    assert!(superseded.load(Ordering::Acquire));
    assert!(!decoder.seek_cancel.load(Ordering::Acquire));
    assert_eq!(wait_for_queue(&decoder, 3)?, PICTURE_QUEUE_CAPACITY);
    let Some(Output::Picture(picture)) = decoder.poll() else {
        return Err(anyhow!("Missing latest seek picture"));
    };
    assert!((picture.time - 0.25).abs() < 1e-6);
    Ok(())
}
