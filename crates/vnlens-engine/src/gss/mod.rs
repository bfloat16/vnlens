//! GSS: LSDARC paired indices and SCR bytecode. DistortedCode's bank loader
//! sub_50720 mounts BIN indices alongside ARC payloads; sub_1BAC0/sub_1BED0
//! install BMPDATA, WAVDATA and SCRDATA. Identification reads names only.
mod route;
use crate::{
    Engine,
    context::Context,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::{ArcView, pe::PeImage};

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"gss err : Exec 01")? && has(image, b"script\\OBJ\\AutoExec.OBJ")?)
}
fn layout(context: &Context) -> bool {
    let Ok(files) = context.files.read_dir(&context.root) else {
        return false;
    };
    ["BMPDATA", "SCRDATA", "WAVDATA"].iter().all(|bank| {
        ["BIN", "ARC"].iter().all(|extension| {
            let name = format!("{bank}.{extension}");
            files.iter().any(|file| {
                !file.metadata.directory
                    && file
                        .path
                        .file_name()
                        .is_some_and(|leaf| leaf.eq_ignore_ascii_case(&name))
            })
        })
    })
}
fn file(view: &ArcView) -> Result<bool> {
    Ok(view
        .path()
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
        && view.len() >= 12
        && view.slice(0, 12)? == b"LSDARC V.100")
}
vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Gss, supersedes: None, subdirs: &["data"],
        pe, layout, file, resolve: plain, scope: unscoped, route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/gss/mod.rs"]
mod tests;
