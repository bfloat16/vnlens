//! Background decoding of video pictures for the preview player. Decoding
//! stays in vnlens-video; this module only runs it off the UI thread.
use anyhow::{Result, anyhow};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    time::Duration,
};
use vnlens_video::{Picture, Video, VideoMeta};
mod audio;
pub use audio::AudioOutput;

// Scheduling capacity, independent of frame rate and movie duration. Once
// full, the producer waits for presentation instead of decoding seconds of BGRA.
const PICTURE_QUEUE_CAPACITY: usize = 3;

pub enum Output {
    Picture(Picture),
    End,
    Error(String),
}

enum Message {
    Picture(u64, Picture),
    End(u64),
    Error(u64, String),
}

struct Pictures {
    messages: Mutex<VecDeque<Message>>,
    changed: Condvar,
}

/// A decoder thread for one resource. Dropping it stops the thread at its
/// next queue operation.
pub struct Decoder {
    pub meta: VideoMeta,
    seeks: Sender<(u64, f64)>,
    pictures: Arc<Pictures>,
    /// Incremented per seek so pictures decoded before it are discarded.
    generation: u64,
    cancelled: Arc<AtomicBool>,
}
impl Decoder {
    /// Opens `bytes` on a dedicated thread, because FFmpeg's scaler must stay
    /// on the thread that created it, and returns once the streams are known.
    /// `Ok(None)` means the container has no video stream.
    pub fn open(
        input: crate::resource::VideoInput,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<Self>> {
        let (seeks, seek_receiver) = mpsc::channel();
        let pictures = Arc::new(Pictures {
            messages: Mutex::new(VecDeque::new()),
            changed: Condvar::new(),
        });
        let pending = pictures.clone();
        let (opened, opened_receiver) = mpsc::channel();
        let token = cancelled.clone();
        std::thread::Builder::new()
            .name("video decoder".into())
            .spawn(move || {
                // Drop the decoder before releasing a nested archive's files.
                let _archive = input.archive;
                match Video::open_source_as(
                    input.tag,
                    input.source,
                    Some(&input.name),
                    token.clone(),
                ) {
                    Ok(Some(mut video)) => {
                        if opened.send(Ok(Some(video.meta().clone()))).is_ok() {
                            run(&mut video, &seek_receiver, &pending, &token);
                        }
                    }
                    result => {
                        let _ = opened.send(result.map(|_| None));
                    }
                }
            })?;
        let meta = opened_receiver
            .recv()
            .map_err(|_| anyhow!("Video decoder stopped while opening"))??;
        Ok(meta.map(|meta| Self {
            meta,
            seeks,
            pictures,
            generation: 0,
            cancelled,
        }))
    }

    pub fn seek(&mut self, seconds: f64) {
        self.generation = self.generation.wrapping_add(1);
        if let Ok(mut messages) = self.pictures.messages.lock() {
            messages.clear();
        }
        let _ = self.seeks.send((self.generation, seconds));
        self.pictures.changed.notify_one();
    }

    /// Returns the next decoded output of the current seek, if one is ready.
    pub fn poll(&self) -> Option<Output> {
        loop {
            let message = self.pictures.messages.lock().ok()?.pop_front()?;
            self.pictures.changed.notify_one();
            match message {
                Message::Picture(generation, picture) if generation == self.generation => {
                    return Some(Output::Picture(picture));
                }
                Message::End(generation) if generation == self.generation => {
                    return Some(Output::End);
                }
                Message::Error(generation, error) if generation == self.generation => {
                    return Some(Output::Error(error));
                }
                _ => {}
            }
        }
    }
}
impl Drop for Decoder {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.pictures.changed.notify_one();
    }
}

fn run(
    video: &mut Video,
    seeks: &Receiver<(u64, f64)>,
    pictures: &Pictures,
    cancelled: &AtomicBool,
) {
    let mut generation = 0;
    let mut ended = false;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return;
        }
        let seek = match seeks.try_recv() {
            Ok(seek) => Some(seek),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => return,
        };
        if let Some(mut seek) = seek {
            // Only the latest of several queued seeks, e.g. while dragging, matters.
            seek = seeks.try_iter().last().unwrap_or(seek);
            generation = seek.0;
            ended = false;
            if let Ok(mut messages) = pictures.messages.lock() {
                messages.clear();
            } else {
                return;
            }
            if let Err(error) = video.seek(seek.1) {
                ended = true;
                if let Ok(mut messages) = pictures.messages.lock() {
                    messages.push_back(Message::Error(generation, format!("Video seek: {error}")));
                } else {
                    return;
                }
                continue;
            }
        }
        let messages = match pictures.messages.lock() {
            Ok(messages) => messages,
            Err(_) => return,
        };
        if ended || messages.len() >= PICTURE_QUEUE_CAPACITY {
            // A timeout also observes cancellation from the preview request.
            if pictures
                .changed
                .wait_timeout(messages, Duration::from_millis(20))
                .is_err()
            {
                return;
            }
            continue;
        }
        drop(messages);
        let message = match video.next_picture() {
            Ok(Some(picture)) => Message::Picture(generation, picture),
            Ok(None) => {
                ended = true;
                Message::End(generation)
            }
            Err(error) => {
                ended = true;
                Message::Error(generation, format!("Video decode: {error}"))
            }
        };
        if let Ok(mut messages) = pictures.messages.lock() {
            messages.push_back(message);
        } else {
            return;
        }
    }
}

#[cfg(test)]
#[path = "../tests/video.rs"]
mod tests;
