//! Hash functions.

pub mod hxv4;
pub mod md5;
pub mod murmur2;
pub mod sha256;

pub use sha1_smol as sha1;

#[cfg(test)]
#[path = "../../tests/hash/mod.rs"]
mod tests;
