//! BGI/Ethornell: interpreter identity and archive-reader strings in the PE.
//! ARC20 indices and DSC streams carry their own parameters; no game key is
//! required by the verified 64-bit interpreter's resource reader.
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"Ethornell - BURIKO General Interpreter")? && has(pe, b"BURIKO ARC20")?)
}

fn layout(context: &crate::context::Context) -> bool {
    ["system.arc", "sysprg.arc", "sysgrp.arc"]
        .iter()
        .all(|name| context.files.is_file(&context.root.join(name)))
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Bgi,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}
