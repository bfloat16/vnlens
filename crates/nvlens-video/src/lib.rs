//! nvlens video decoding through FFmpeg.
//!
//! `lib.rs` only exposes the public surface; logic lives in separate modules.
#![forbid(unsafe_code)]

mod audio;
mod decoder;
mod input;
mod kaleido;
mod model;
mod video;
mod yuris;

pub use audio::AudioDecoder;
pub use decoder::contains_video;
pub use model::{AudioFrame, AudioStream, Picture, VideoMeta, VideoStream};
pub use video::{Video, VideoDecoder, VideoFormat, VideoRegistration, decode_source_as};

/// Forces this crate to be linked and keeps FFmpeg's own logging to errors;
/// failures are also returned to the caller.
pub fn init() {
    ffmpeg_next::log::set_level(ffmpeg_next::log::Level::Error);
}
