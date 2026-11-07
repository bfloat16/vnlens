//! AGES-MK2 (`smash::fw`) audio formats.
//!
//! Pure algorithms come from [`nvlens_crypto`]; the external key blobs are
//! supplied by the caller (the FPD archive loads them via `nvlens_bin`).

pub mod fcd;
