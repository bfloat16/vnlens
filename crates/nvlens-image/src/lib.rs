//! nvlens image-format decoders and the common decoded-image model.
//!
//! Format implementations are independent of the GUI and return owned pixels.
#![deny(unsafe_code)]

mod bgi;
mod exhibit;
mod format;
mod krkr;
mod model;
mod siglus;
mod standard;
mod will;
mod yuris;

pub use format::{ImageFormat, ImageRegistration, decode, decode_frame, frame_count, metadata};
pub use model::{Image, ImageMeta, OffsetUnit, PixelBuffer, swap_red_blue};

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
