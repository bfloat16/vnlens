//! Otomate's STCM2/CL3 host. Kimi ni Madoi's EntryArchive (sub_E6110)
//! mounts the five named CONTENTS banks; detection reads names only. STCM2
//! runtime and CL3 section names provide independent executable evidence.
mod route;

use crate::{
    Engine,
    context::Context,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"STCM2SCRIPT_GROUP")? && has(image, b"FILE_COLLECTION")?)
}

fn layout(context: &Context) -> bool {
    let Ok(directories) = context.files.read_dir(&context.root) else {
        return false;
    };
    let banks = directories.iter().any(|directory| {
        directory.metadata.directory
            && directory
                .path
                .file_name()
                .is_some_and(|s| s.eq_ignore_ascii_case("CONTENTS"))
            && context.files.read_dir(&directory.path).is_ok_and(|files| {
                [
                    "SYSTEM.cpk",
                    "STORY.cpk",
                    "GAME.cpk",
                    "MOVIE.cpk",
                    "SOUND.cpk",
                ]
                .iter()
                .all(|name| {
                    files.iter().any(|file| {
                        !file.metadata.directory
                            && file
                                .path
                                .file_name()
                                .is_some_and(|s| s.eq_ignore_ascii_case(name))
                    })
                })
            })
    });
    if banks {
        return true;
    }
    // Extracted script directories supply direct file evidence, never archive
    // payload evidence. Only the six-byte identity prefix is requested.
    directories.iter().any(|directory| {
        directory.metadata.directory
            && directory
                .path
                .file_name()
                .is_some_and(|s| s.eq_ignore_ascii_case("SCRIPT"))
            && context.files.read_dir(&directory.path).is_ok_and(|files| {
                files.iter().any(|file| {
                    !file.metadata.directory
                        && file.path.extension().is_some_and(|s| {
                            s.eq_ignore_ascii_case("dat") || s.eq_ignore_ascii_case("stcm2")
                        })
                        && context.files.source(&file.path).is_ok_and(|source| {
                            source.len() >= 6
                                && source
                                    .read_at(0, 6)
                                    .is_ok_and(|head| head.as_ref() == b"STCM2L")
                        })
                })
            })
    })
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Otomate,
        supersedes: None,
        subdirs: &["contents", "script"],
        pe,
        layout,
        file: crate::detect::no_container,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/otomate/mod.rs"]
mod tests;
