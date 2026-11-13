//! YU-RIS loader strings and relocated x86 key initialization (0x46327C).
mod key;
mod license;
mod name;
mod route;

use crate::{
    Engine,
    detect::{Detector, has, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"ysbin\\yst%05d.ybn")? && has(pe, b"ysbin\\yst_list.ybn")?)
}

fn layout(context: &crate::context::Context) -> bool {
    (context.files.is_file(&context.root.join("pac/Scripts.ypf"))
        && context
            .files
            .is_file(&context.root.join("pac/Graphics.ypf")))
        || (context.files.is_file(&context.root.join("yscfg.dat"))
            && context
                .files
                .read_dir(&context.root.join("pac"))
                .is_ok_and(|files| {
                    files.iter().any(|file| {
                        !file.metadata.directory
                            && file
                                .path
                                .extension()
                                .is_some_and(|ext| ext.eq_ignore_ascii_case("ypf"))
                    })
                }))
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Yuris,
        supersedes: None,
        subdirs: &["pac"],
        pe,
        layout,
        resolve: key::resolve,
        scope: unscoped,
        route: route::ROUTER,
    }
}
