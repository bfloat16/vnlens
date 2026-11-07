//! Game-engine identification and explicit archive routing.
#![forbid(unsafe_code)]

mod ages_mk2;
mod detect;
mod emote;
mod model;
mod will;
mod yuris;

pub use detect::identify;
pub use model::{Engine, Identification};

pub fn init() {}
