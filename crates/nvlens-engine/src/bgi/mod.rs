//! BGI/Ethornell: interpreter identity and archive-reader strings in the PE.
//! ARC20 indices and DSC streams carry their own parameters; no game key is
//! required by the verified 64-bit interpreter's resource reader.

use crate::{
    Engine,
    detect::{Detector, has, plain},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"Ethornell - BURIKO General Interpreter")? && has(pe, b"BURIKO ARC20")?)
}

fn layout(root: &std::path::Path) -> bool {
    ["system.arc", "sysprg.arc", "sysgrp.arc"]
        .iter()
        .all(|name| root.join(name).is_file())
}

nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Bgi, resolve: plain } }
