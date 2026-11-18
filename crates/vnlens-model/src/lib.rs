//! Directed model decoding and GUI-independent static mesh data.
#![forbid(unsafe_code)]

mod format;
mod model;
mod tamsoft;

pub use format::{ModelFormat, ModelRegistration, decode_as};
pub use model::{Material, Mesh, Model, TextureBinding, Vertex};

pub fn init() {}
