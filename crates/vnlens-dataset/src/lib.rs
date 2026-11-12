//! Dialogue datasets assembled from an identified game's scripts and resources.
#![forbid(unsafe_code)]

mod generate;
mod model;
mod resources;
mod yuris;

pub use generate::{generate, supports};
pub use model::{Progress, Record, Stage};
