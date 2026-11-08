//! Game-engine identification and explicit archive routing.
#![forbid(unsafe_code)]

mod ages_mk2;
mod bgi;
mod detect;
mod emote;
mod exhibit;
mod krkrz_hxv4;
mod model;
mod siglus;
mod will;
mod yuris;

pub use detect::identify;
pub use model::{Engine, Identification};

pub fn init() {}
