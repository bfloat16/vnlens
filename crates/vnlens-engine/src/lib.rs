//! Game-engine identification and explicit archive routing.
#![forbid(unsafe_code)]

mod ages_mk2;
mod archive_set;
mod bgi;
mod context;
mod csystem;
mod detect;
mod emote;
mod entisgls;
mod escude;
mod exhibit;
mod kaleido;
mod krkr;
mod krkrz_hxv4;
mod mages;
mod model;
mod propeller;
mod reallive;
mod routing;
mod rugp;
mod siglus;
mod softpal;
mod systemnnn;
mod will;
mod yuris;

pub use archive_set::ArchiveSet;
pub use detect::{identify, identify_with_progress};
pub use model::{Engine, Identification};

pub fn init() {}
