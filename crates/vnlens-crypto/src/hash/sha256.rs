//! Incremental SHA-256 for format hash trees and checksums.
use sha2::Digest;

#[derive(Debug, Default)]
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    #[must_use]
    pub fn digest(bytes: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(bytes).into()
    }
}

#[cfg(test)]
#[path = "../../tests/hash/sha256.rs"]
mod tests;
