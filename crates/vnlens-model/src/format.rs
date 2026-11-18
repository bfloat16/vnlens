//! Inventory registration with a single explicit model route; no probing.
use crate::Model;
use std::{sync::Arc, sync::atomic::AtomicBool};
use vnlens_core::{ArchiveOptions, Error, Format, Result};

pub trait ModelFormat: Format {
    fn decode(
        &self,
        data: Arc<[u8]>,
        options: &ArchiveOptions,
        cancelled: &AtomicBool,
    ) -> Result<Model>;
}

#[derive(Debug)]
pub struct ModelRegistration(pub fn() -> Box<dyn ModelFormat>);
vnlens_core::inventory::collect!(ModelRegistration);

/// Decodes only the selected model format. Input ownership preserves all native
/// fields; cancellation and malformed ranges are returned without fallback.
pub fn decode_as(
    tag: &str,
    data: Arc<[u8]>,
    options: &ArchiveOptions,
    cancelled: &AtomicBool,
) -> Result<Model> {
    for registration in vnlens_core::inventory::iter::<ModelRegistration>() {
        let decoder = (registration.0)();
        if decoder.tag() == tag {
            return decoder.decode(data, options, cancelled);
        }
    }
    Err(Error::Unsupported(format!(
        "Model route is not registered: {tag}"
    )))
}
