use super::*;
use std::prelude::rust_2024::test;

fn wait_picture(video: &mut VideoPreview, position: f64) -> anyhow::Result<vnlens_video::Picture> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(picture) = video.poll_picture(position)? {
            return Ok(picture);
        }
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!("Timed out waiting for preview picture"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn transport(input: VideoInput) -> anyhow::Result<()> {
    let mut video = VideoPreview::new(input, Arc::new(AtomicBool::new(false)))?
        .ok_or_else(|| anyhow::anyhow!("Missing test video"))?;
    assert!(!video.playing());
    assert_eq!(wait_picture(&mut video, 0.)?.time, 0.);
    // A duplicate or stale timestamp must not bypass pause, even if it is
    // already due. This check does not open an output device or a window.
    video.next = Some(vnlens_video::Picture {
        time: 0.,
        width: 1,
        height: 1,
        bgra: vec![1, 2, 3, 255],
    });
    assert!(video.poll_picture(10.)?.is_none());
    assert!(video.next.is_some());
    video.clock = Clock::Playing(Instant::now(), 0.);
    assert!(video.poll_picture(0.)?.is_some());
    video.clock = Clock::Paused(0.);
    video.seek(0.25);
    assert!(!video.playing());
    assert_eq!(video.position(), 0.25);
    let picture = wait_picture(&mut video, 0.25)?;
    assert!(picture.time <= 0.25 + 1e-6 && picture.time > 0.1);
    assert!(video.poll_picture(10.)?.is_none());
    video.clock = Clock::Playing(Instant::now(), 0.25);
    video.seek(0.5);
    assert!(video.playing());
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(video.position(), 0.5);
    let picture = wait_picture(&mut video, 0.5)?;
    assert!(picture.time <= 0.5 + 1e-6 && picture.time > 0.35);
    video.clock = Clock::Paused(0.5);
    assert!(video.poll_picture(10.)?.is_none());
    Ok(())
}

#[test]
fn pause_and_seek_control_presentation_without_a_window() -> anyhow::Result<()> {
    let mut bytes = b"YUV4MPEG2 W2 H2 F10:1 Ip A1:1 C444\n".to_vec();
    for value in 0..30 {
        bytes.extend_from_slice(b"FRAME\n");
        bytes.extend([value; 12]);
    }
    transport(VideoInput {
        tag: "ffmpeg",
        source: Arc::new(Arc::<[u8]>::from(bytes)),
        name: "transport.y4m".into(),
        archive: None,
    })
}

#[test]
fn an_unavailable_seek_frame_does_not_leave_a_running_frozen_clock() -> anyhow::Result<()> {
    let mut bytes = b"YUV4MPEG2 W2 H2 F10:1 Ip A1:1 C444\nFRAME\n".to_vec();
    bytes.extend([128; 12]);
    let mut video = VideoPreview::new(
        VideoInput {
            tag: "ffmpeg",
            source: Arc::new(Arc::<[u8]>::from(bytes)),
            name: "end.y4m".into(),
            archive: None,
        },
        Arc::new(AtomicBool::new(false)),
    )?
    .ok_or_else(|| anyhow::anyhow!("Missing video stream"))?;
    wait_picture(&mut video, 0.)?;
    video.clock = Clock::Playing(Instant::now(), 0.);
    video.seek(100.);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !video.ended {
        let _ = video.poll_picture(100.);
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!("Timed out waiting for seek completion"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!video.awaiting && !video.playing());
    Ok(())
}
