//! vnlens image-format decoders and the common decoded-image model.
//!
//! Format implementations are independent of the GUI and return owned pixels.
#![deny(unsafe_code)]

mod bgi;
mod csystem;
mod dds;
mod entisgls;
mod exhibit;
mod format;
mod krkr;
mod model;
mod propeller;
mod reallive;
mod rugp;
mod siglus;
mod softpal;
mod standard;
mod systemnnn;
mod tga;
mod will;
mod yuris;

pub use format::{
    ImageFormat, ImageRegistration, decode_as, decode_frame_as, decode_with_options_as,
    decode_with_resources_as, frame_count_as, metadata_as,
};
pub use model::{Image, ImageMeta, OffsetUnit, PixelBuffer, swap_red_blue};

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
