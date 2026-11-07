//! External key blobs copied beside the executable and loaded on demand.
#![forbid(unsafe_code)]

pub mod keys;
mod loader;

pub use loader::load;
