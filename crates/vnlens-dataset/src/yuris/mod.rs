//! ERIS dialogue mapping. YSLB labels locate the project's folder, character,
//! and voice definitions; YSCM names identify commands across YSTB revisions.
//! es.SND channels 21..=30 are foreground voices. WORD/_ fragments end at
//! RETURNCODE; runtime scenario text uses the equivalent VO macros.

mod bytecode;
mod config;
mod expression;
mod scenario;
mod text;

use crate::resources::{Resources, check};
use crate::{Progress, Stage};
use std::sync::atomic::AtomicBool;
use vnlens_core::{ResourceRoute, Result};

pub(crate) use config::Config;

#[derive(Debug)]
pub(crate) struct Dialogue {
    pub speaker: String,
    pub voice: String,
    pub text: String,
}

/// YPF discovery defers update1..9, then inserts them in ascending order;
/// each patch invalidates the previous index record with the same name.
/// Verified in the 0x1E1 loader at 0x45F7D0 and 0x45EE30.
pub(crate) fn archive_priority(name: &str) -> u8 {
    let name = crate::resources::normalized(name);
    match name.rsplit('/').next().unwrap_or(&name) {
        "update1.ypf" => 1,
        "update2.ypf" => 2,
        "update3.ypf" => 3,
        "update4.ypf" => 4,
        "update5.ypf" => 5,
        "update6.ypf" => 6,
        "update7.ypf" => 7,
        "update8.ypf" => 8,
        "update9.ypf" => 9,
        _ => 0,
    }
}

pub(crate) fn collect(
    resources: &Resources,
    config: &Config,
    cancel: &AtomicBool,
    progress: &mut Progress,
    report: &mut impl FnMut(Progress, Option<String>),
) -> Result<Vec<Dialogue>> {
    let mut dialogues = Vec::new();
    let mut scripts = resources
        .items
        .iter()
        .enumerate()
        .filter_map(|(id, item)| {
            (resources.find(&item.name) == Some(id)
                && matches!(
                    item.route,
                    ResourceRoute::Script("ybn/yuris" | "scenario/yuris")
                ))
            .then_some(id)
        })
        .collect::<Vec<_>>();
    scripts.sort_by(|&a, &b| resources.items[a].name.cmp(&resources.items[b].name));
    progress.stage = Stage::ReadingScripts;
    progress.completed = 0;
    progress.total = scripts.len();
    for id in scripts {
        check(cancel)?;
        let item = &resources.items[id];
        let result = (|| {
            let bytes = resources.read(id)?;
            match item.route {
                ResourceRoute::Script("ybn/yuris") if bytes.starts_with(b"YSTB") => {
                    if let Some(script) =
                        vnlens_script::disassemble_as("ybn/yuris", &bytes, Some(resources))?
                    {
                        bytecode::collect(
                            &script,
                            &crate::resources::normalized(&item.name),
                            config,
                            cancel,
                            &mut dialogues,
                            &mut progress.skipped,
                        )?;
                    }
                }
                ResourceRoute::Script("scenario/yuris") => {
                    if let Some(text) = vnlens_script::decode_text_as("scenario/yuris", &bytes)? {
                        scenario::collect(
                            &text,
                            config,
                            cancel,
                            &mut dialogues,
                            &mut progress.skipped,
                        )?;
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(error) = result {
            check(cancel)?;
            if matches!(error, vnlens_core::Error::Cancelled) {
                return Err(error);
            }
            progress.failed += 1;
            report(*progress, Some(format!("{}: {error}", item.name)));
        }
        progress.completed += 1;
        report(*progress, None);
    }
    Ok(dialogues)
}

#[cfg(test)]
#[path = "../../tests/yuris/mod.rs"]
mod tests;
