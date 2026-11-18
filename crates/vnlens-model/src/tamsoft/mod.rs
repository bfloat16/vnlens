//! ToHeart Tamlib CTmd2 static TMD0 meshes, little endian. The native loader
//! sub_140574370 describes attribute/table ranges; sub_1405758E0 expands packed
//! normals, vertex colors, fixed/float UVs and 16/32-bit triangle indices.
//! Object command streams bind materials (2/5/6) and primitives (3). Bone and
//! animation bytes stay intact in Model::source; this decoder reads rest geometry.
mod read;

use crate::{Model, ModelFormat, ModelRegistration};
use std::{sync::Arc, sync::atomic::AtomicBool};
use vnlens_core::{ArchiveOptions, Format, Result};

const SIGNATURES: &[u32] = &[0x3064_6d74];

#[derive(Debug, Default)]
struct Tmd;
impl Format for Tmd {
    fn tag(&self) -> &'static str {
        "tmd/tamsoft"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tmd"]
    }
    fn description(&self) -> &'static str {
        "Tamsoft TMD0 static model"
    }
}
impl ModelFormat for Tmd {
    fn decode(&self, data: Arc<[u8]>, _: &ArchiveOptions, cancelled: &AtomicBool) -> Result<Model> {
        read::decode(data, cancelled)
    }
}
vnlens_core::inventory::submit! { ModelRegistration(|| Box::new(Tmd)) }

#[cfg(test)]
#[path = "../../tests/tamsoft/mod.rs"]
mod tests;
