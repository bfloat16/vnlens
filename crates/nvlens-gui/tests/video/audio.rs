use super::*;

fn stream(rate: u32) -> Result<PcmStream> {
    Ok(PcmStream {
        shared: Arc::new(Shared {
            buffer: Mutex::new(Buffer {
                target: 0.,
                frames: VecDeque::new(),
                seconds: 0.,
                ended: false,
                error: None,
            }),
            changed: Condvar::new(),
            generation: AtomicU64::new(0),
            base: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            cancelled: Arc::new(AtomicBool::new(false)),
        }),
        channels: NonZero::new(2).ok_or_else(|| anyhow!("Zero channels"))?,
        rate: NonZero::new(rate).ok_or_else(|| anyhow!("Zero sample rate"))?,
        generation: 0,
        samples: Vec::new().into_iter(),
        gap: 0,
        phase: 0,
        buffering: true,
        align: true,
    })
}

fn enqueue(stream: &PcmStream, time: f64, samples: Vec<f32>, ended: bool) -> Result<()> {
    let frame = AudioFrame {
        time,
        channels: stream.channels.get(),
        sample_rate: stream.rate.get(),
        samples,
    };
    let mut buffer = stream
        .shared
        .buffer
        .lock()
        .map_err(|_| anyhow!("Poisoned PCM buffer"))?;
    buffer.seconds += frame_duration(&frame);
    buffer.frames.push_back(frame);
    buffer.ended = ended;
    Ok(())
}

#[test]
fn packet_timestamp_jitter_does_not_cut_or_pad_continuous_pcm() -> Result<()> {
    let mut stream = stream(48000)?;
    // WMA superframes in ASF have coarse, overlapping packet timestamps.
    // The decoded sample sequence must survive these block boundaries intact.
    let mut expected = vec![0.; 4080 * 2];
    for (index, (time, frames)) in [(0.085, 18432), (0.426, 20480), (0.863, 16384)]
        .into_iter()
        .enumerate()
    {
        let samples: Vec<_> = (0..frames)
            .flat_map(|frame| {
                let value = (index * 20480 + frame + 1) as f32 / 65536.;
                [value, -value]
            })
            .collect();
        expected.extend_from_slice(&samples);
        enqueue(&stream, time, samples, true)?;
    }
    for (index, expected) in expected.into_iter().enumerate() {
        assert_eq!(stream.next(), Some(expected), "sample {index}");
    }
    assert_eq!(stream.shared.consumed.load(Ordering::Acquire), 59376);
    Ok(())
}

#[test]
fn underrun_silence_keeps_stereo_frames_aligned() -> Result<()> {
    let mut stream = stream(10)?;
    assert_eq!(stream.next(), Some(0.));
    // Producer wakes between the left and right samples of one device frame.
    enqueue(&stream, 0., vec![0.25, -0.25, 0.5, -0.5], true)?;
    assert_eq!(stream.next(), Some(0.));
    assert_eq!(stream.shared.consumed.load(Ordering::Acquire), 0);
    assert_eq!(
        stream.by_ref().take(4).collect::<Vec<_>>(),
        [0.25, -0.25, 0.5, -0.5]
    );
    assert_eq!(stream.shared.consumed.load(Ordering::Acquire), 2);
    Ok(())
}

#[test]
fn startup_waits_for_pcm_and_short_final_blocks_still_play() -> Result<()> {
    let mut stream = stream(100)?;
    enqueue(&stream, 0., vec![0.25, -0.25], false)?;
    assert_eq!(stream.by_ref().take(10).collect::<Vec<_>>(), [0.; 10]);
    assert_eq!(stream.shared.consumed.load(Ordering::Acquire), 0);
    enqueue(&stream, 0.01, vec![0.5, -0.5], true)?;
    assert_eq!(
        stream.by_ref().take(4).collect::<Vec<_>>(),
        [0.25, -0.25, 0.5, -0.5]
    );
    assert!(!stream.shared.finished.load(Ordering::Acquire));
    assert_eq!(stream.next(), Some(0.));
    assert!(stream.shared.finished.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn callback_does_not_wait_for_locked_queue() -> Result<()> {
    let mut stream = stream(100)?;
    let shared = stream.shared.clone();
    let _guard = shared
        .buffer
        .lock()
        .map_err(|_| anyhow!("Poisoned PCM buffer"))?;
    assert_eq!(stream.by_ref().take(4).collect::<Vec<_>>(), [0.; 4]);
    assert_eq!(shared.consumed.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn seek_realigns_once_at_a_complete_channel_frame() -> Result<()> {
    let mut stream = stream(10)?;
    enqueue(&stream, 0., vec![0.25, -0.25, 0.5, -0.5], true)?;
    assert_eq!(stream.next(), Some(0.25));
    stream.shared.base.store(10, Ordering::Release);
    stream.shared.consumed.store(0, Ordering::Release);
    stream.shared.generation.store(1, Ordering::Release);
    enqueue(&stream, 1.1, vec![0.75, -0.75], true)?;
    assert_eq!(stream.next(), Some(-0.25));
    assert_eq!(stream.shared.consumed.load(Ordering::Acquire), 0);
    assert_eq!(
        stream.by_ref().take(4).collect::<Vec<_>>(),
        [0., 0., 0.75, -0.75]
    );
    assert_eq!(stream.shared.consumed.load(Ordering::Acquire), 2);
    Ok(())
}

/// Set NVLENS_VIDEO_SAMPLE to a locally owned movie and NVLENS_PCM_REFERENCE
/// to its FFmpeg output: `ffmpeg -i movie -map 0:a:0 -f f32le reference.f32`.
/// Run `cargo test -p nvlens-gui local_video_pcm -- --ignored --nocapture`.
/// Only pulls samples from the playback source; no audio device is opened.
#[test]
#[ignore = "requires a local movie and FFmpeg PCM reference"]
fn local_video_pcm() -> Result<()> {
    use std::io::Read;

    let path = std::path::PathBuf::from(
        std::env::var_os("NVLENS_VIDEO_SAMPLE")
            .ok_or_else(|| anyhow!("Set NVLENS_VIDEO_SAMPLE"))?,
    );
    let reference = std::env::var_os("NVLENS_PCM_REFERENCE")
        .ok_or_else(|| anyhow!("Set NVLENS_PCM_REFERENCE"))?;
    let mut reference = std::io::BufReader::new(std::fs::File::open(reference)?);
    let source = Arc::new(nvlens_io::ArcView::open(&path)?);
    let mut decoder = AudioDecoder::open(source, None, Arc::new(AtomicBool::new(false)))?
        .ok_or_else(|| anyhow!("Missing audio stream"))?;
    let mut stream = stream(decoder.meta().sample_rate)?;
    stream.channels =
        NonZero::new(decoder.meta().channels).ok_or_else(|| anyhow!("Zero channels"))?;
    let mut count = 0usize;
    let mut blocks = 0;
    while let Some(frame) = decoder.next_frame()? {
        let length = frame.samples.len();
        let mut expected = vec![0; length * 4];
        reference.read_exact(&mut expected)?;
        let silence = if count == 0 {
            (frame.time.max(0.) * f64::from(frame.sample_rate)).round() as usize
                * usize::from(frame.channels)
        } else {
            0
        };
        enqueue(&stream, frame.time, frame.samples, true)?;
        for _ in 0..silence {
            assert_eq!(stream.next(), Some(0.));
        }
        for (index, bytes) in expected.as_chunks::<4>().0.iter().enumerate() {
            let expected = nvlens_io::BinaryReader::f32_le(bytes);
            let sample = stream.next().ok_or_else(|| anyhow!("PCM ended early"))?;
            assert!(
                (sample - expected).abs() <= 1e-6,
                "sample {}: {sample} != {expected}",
                count + index
            );
        }
        count += length;
        blocks += 1;
    }
    assert_eq!(
        reference.read(&mut [0; 1])?,
        0,
        "PCM reference has more samples"
    );
    eprintln!(
        "{}: {count} samples in {blocks} blocks match FFmpeg PCM",
        path.display()
    );
    Ok(())
}
