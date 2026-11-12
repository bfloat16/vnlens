//! PSBFile plugin identity, distinct from games merely embedding EmotePlayer.
pub(crate) mod route;

use crate::detect::{Middleware, has};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"PSBFile")? && has(pe, b"psbfile.dll")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context
        .files
        .is_file(&context.root.join("plugin/psbfile.dll"))
        && context.files.is_dir(&context.root.join("data"))
}

vnlens_core::inventory::submit! {
    Middleware {
        subdirs: &["data", "media", "plugin", "plugins"],
        pe,
        layout,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/emote/mod.rs"]
mod tests;
