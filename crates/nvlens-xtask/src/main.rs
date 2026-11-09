//! Development tasks run through Cargo aliases in `.cargo/config.toml`.
//!
//! `cargo ffmpeg` fetches the pinned prebuilt FFmpeg used by nvlens-video.
#![forbid(unsafe_code)]

mod ffmpeg;

use std::process::ExitCode;

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    let result = match task.as_deref() {
        Some("ffmpeg") => ffmpeg::fetch(),
        _ => Err("usage: nvlens-xtask ffmpeg".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
