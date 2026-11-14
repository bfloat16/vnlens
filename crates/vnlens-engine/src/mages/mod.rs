//! MAGES libMgs resource loader: SC3 programs and language-specific MES banks.
mod dispatch;
mod route;
mod schema;

use crate::{
    Engine,
    detect::{Detector, has},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn scope(game: &crate::Identification, path: &std::path::Path) -> Option<crate::Identification> {
    if game
        .options
        .numbers
        .contains_key("mages_dialogue_extension")
    {
        return None;
    }
    let root = game.options.paths.get("mages_dialogue_root")?;
    if !path.starts_with(root) {
        return None;
    }
    let mut scoped = game.clone();
    scoped.root = root.clone();
    scoped.options.numbers.insert("mages_dialogue_extension", 1);
    Some(scoped)
}

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"mgs::")? && has(image, b".scx")? && has(image, b".msb")?)
}

fn layout(context: &crate::context::Context) -> bool {
    ["data", "DataMA", "DataMB", "DataMS"].iter().any(|folder| {
        let root = context.root.join(folder);
        context.files.is_file(&root.join("script.mpk"))
            && context.files.is_file(&root.join("mes00.mpk"))
            && (context.files.is_file(&root.join("system.mpk"))
                || context.files.is_file(&root.join("system_win.mpk")))
    })
}

vnlens_core::inventory::submit! {
    Detector {
        file: crate::detect::no_container,
        engine: Engine::Mages,
        supersedes: None,
        subdirs: &["data", "DataMA", "DataMB", "DataMS"],
        pe,
        layout,
        resolve: schema::resolve,
        scope,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/mages/mod.rs"]
mod tests;
