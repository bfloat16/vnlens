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
            matches!(
                item.route,
                ResourceRoute::Script("ybn/yuris" | "scenario/yuris")
            )
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
