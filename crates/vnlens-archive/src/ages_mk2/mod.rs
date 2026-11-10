//! AGES-MK2 (`smash::fw`) engine, used by Muv-Luv Tactics and related titles.
//!
//! The FPD archive lives here; its nested typed sub-formats are handled by their
//! own domain crates (FCD audio in `vnlens-audio`, EPK database in
//! `vnlens-script`). External key blobs come from [`vnlens_bin`]; pure
//! algorithms from [`vnlens_crypto`].

mod fpd;
