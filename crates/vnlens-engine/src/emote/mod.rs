//! PSBFile plugin identity, distinct from games merely embedding EmotePlayer.
pub(crate) mod route;

use crate::detect::has;
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

pub(crate) const SUBDIRS: &[&str] = &["data", "media", "plugin", "plugins"];

pub(crate) fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"PSBFile")? && has(pe, b"psbfile.dll")?)
}

pub(crate) fn layout(context: &crate::context::Context) -> bool {
    context
        .files
        .is_file(&context.root.join("plugin/psbfile.dll"))
        && context.files.is_dir(&context.root.join("data"))
}
