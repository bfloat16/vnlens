//! nvlens pure computational algorithms.
//!
//! Home for stateless, engine-independent routines: decompression, cipher
//! (encrypt/decrypt) primitives, checksums, and similar. These take bytes and
//! produce bytes; they carry no archive/format concepts. Byte framing (e.g. a
//! length prefix) is read through [`nvlens_io`], keeping it the single source
//! of binary I/O.
#![forbid(unsafe_code)]

pub mod compress;
