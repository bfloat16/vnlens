//! Cancellable FFmpeg I/O with the original source errors retained.

use crate::decoder::error;
use ffmpeg_next::{
    Error as FfmpegError,
    format::{
        self,
        context::{Input, StreamIo},
    },
};
use std::{
    io::{self, Read, Seek, SeekFrom},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_core::{Error, Result};
use vnlens_io::{ReadAt, ReadSeek};

pub(super) struct IoState {
    cancelled: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<io::Error>>>,
}
impl IoState {
    pub(super) fn error(&self, cause: FfmpegError) -> Error {
        match self.check() {
            Ok(()) => error(cause),
            Err(error) => error,
        }
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let failure = self
            .failure
            .lock()
            .ok()
            .and_then(|mut failure| failure.take());
        match failure {
            Some(failure) if failure.get_ref().is_some_and(|cause| cause.is::<Error>()) => {
                match failure
                    .into_inner()
                    .and_then(|cause| cause.downcast::<Error>().ok())
                {
                    Some(cause) => Err(*cause),
                    None => Err(Error::Io(io::Error::other("Source I/O failed"))),
                }
            }
            Some(failure) => Err(Error::Io(failure)),
            None => Ok(()),
        }
    }
}
struct TrackedReader {
    reader: Box<dyn ReadSeek>,
    failure: Arc<Mutex<Option<io::Error>>>,
}
impl TrackedReader {
    fn retain<T>(&self, result: io::Result<T>) -> io::Result<T> {
        result.map_err(|failure| {
            let returned = io::Error::new(failure.kind(), failure.to_string());
            if let Ok(mut stored) = self.failure.lock()
                && stored.is_none()
            {
                *stored = Some(failure);
            }
            returned
        })
    }
}
impl Read for TrackedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = self.reader.read(buffer);
        self.retain(result)
    }
}
impl Seek for TrackedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let result = self.reader.seek(position);
        self.retain(result)
    }
}
pub(super) fn open(
    source: Arc<dyn ReadAt>,
    name: Option<&str>,
    cancelled: Arc<AtomicBool>,
) -> Result<(Input, IoState)> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let failure = Arc::new(Mutex::new(None));
    let state = IoState {
        cancelled: cancelled.clone(),
        failure: failure.clone(),
    };
    let reader = TrackedReader {
        reader: source.reader(cancelled.clone())?,
        failure,
    };
    let io = StreamIo::from_read_seek(reader).map_err(|cause| state.error(cause))?;
    let input = format::input_from_stream_with_interrupt(io, name, None, move || {
        cancelled.load(Ordering::Relaxed)
    })
    .map_err(|cause| state.error(cause))?;
    Ok((input, state))
}
