//! nvlens image-format decoders and the common decoded-image model.
//!
//! Format implementations are independent of the GUI and return owned pixels.
#![forbid(unsafe_code)]

mod format;
mod model;
mod standard;
mod yuris;

pub use format::{ImageFormat, ImageRegistration, decode, metadata};
pub use model::{Image, ImageMeta, OffsetUnit, PixelBuffer};

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
