//! nvlens pure computational algorithms.
//!
//! Home for stateless, engine-independent routines: compression, cipher
//! (encrypt/decrypt) primitives, hashes, and checksums. These take bytes and
//! produce bytes; they carry no archive/format concepts, and key material is
//! passed in as parameters rather than embedded. Byte framing (e.g. a length
//! prefix) is read through [`nvlens_io`], keeping it the single source of
//! binary I/O.
#![forbid(unsafe_code)]

pub mod checksum;
pub mod cipher;
pub mod compress;
pub mod hash;
