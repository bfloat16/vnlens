//! EntisGLS / Cotopha hosts share ERISA archives. Both the classic host and
//! SakuraGL hosts use either EntisGLS_GameWindow / ERISAArchive or the
//! EntisGLS4_SGLGenericWindow class / ERISA::SGLArchiveFile type name.
//! These PE strings identify the host without opening resource archives.
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(
        (has(image, b"EntisGLS_GameWindow")? && has(image, b"ERISAArchive")?)
            || (has(image, b"EntisGLS4_SGLGenericWindow")?
                && has(image, b"ERISA::SGLArchiveFile")?),
    )
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::EntisGls,
        supersedes: None,
        subdirs: &["system"],
        pe,
        layout: |_| false,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/entisgls/mod.rs"]
mod tests;
