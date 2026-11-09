//! Game-engine identification and explicit archive routing.
#![forbid(unsafe_code)]

mod ages_mk2;
mod archive_set;
mod bgi;
mod detect;
mod emote;
mod escude;
mod exhibit;
mod krkr;
mod krkrz_hxv4;
mod model;
mod propeller;
mod routing;
mod rugp;
mod siglus;
mod systemnnn;
mod will;
mod yuris;

pub use archive_set::ArchiveSet;
pub use detect::identify;
pub use model::{Engine, Identification};

pub fn init() {}
