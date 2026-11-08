//! AGES-MK2 (`smash::fw`) engine, used by Muv-Luv Tactics and related titles.
//!
//! The FPD archive lives here; its nested typed sub-formats are handled by their
//! own domain crates (FCD audio in `nvlens-audio`, EPK database in
//! `nvlens-script`). External key blobs come from [`nvlens_bin`]; pure
//! algorithms from [`nvlens_crypto`].

mod fpd;
