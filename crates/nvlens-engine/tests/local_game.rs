//! Set NVLENS_ENGINE_GAME to a locally owned game directory. No samples are bundled.
use nvlens_engine::identify;
use std::{path::PathBuf, sync::atomic::AtomicBool};

#[test]
#[ignore = "Requires NVLENS_ENGINE_GAME; inspects PE evidence and routes without opening archives"]
fn identifies_local_game() -> Result<(), Box<dyn std::error::Error>> {
    let root =
        PathBuf::from(std::env::var_os("NVLENS_ENGINE_GAME").ok_or("Set NVLENS_ENGINE_GAME")?);
    let game = identify(&root, &AtomicBool::new(false))?.ok_or("Engine not recognized")?;
    println!("Engine: {:?}; evidence: {}", game.engine, game.evidence);
    for name in [
        "Scripts.ypf",
        "Script2.arc",
        "resident.fpd",
        "game_info.psb.m",
        "character.psb",
    ] {
        if let Some(route) = game.route(name) {
            println!(
                "{name} -> {} ({} resolved keys)",
                route.tag,
                route.options.keys.len()
            );
        }
    }
    Ok(())
}
