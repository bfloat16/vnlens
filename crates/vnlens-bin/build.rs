//! Build script: copies external key blobs into a `bin/` sidecar directory next
//! to the compiled output, preserving the per-engine subfolder layout, so the
//! runtime loader can read them by their `<engine>/<file>` name.
//!
//! Keys are intentionally NOT embedded with `include_bytes!`; they live beside
//! the executable and can be swapped without recompiling.

#![forbid(unsafe_code)]

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let out_dir = std::env::var("OUT_DIR")?;
    let keys_dir = Path::new(&manifest_dir).join("keys");

    // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out.
    // The compiled binaries land in <target>/<profile>, i.e. the 3rd ancestor.
    let profile_dir = Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .ok_or("cannot locate target profile directory from OUT_DIR")?;
    let bin_dir = profile_dir.join("bin");

    // Expose the source keys dir so the runtime loader has a dev-time fallback
    // if the sidecar is removed without a rebuild. Harmless in a shipped binary
    // (the path won't exist there and is simply skipped).
    println!("cargo:rustc-env=VNLENS_KEYS_SRC={}", keys_dir.display());

    copy_keys(&keys_dir, &bin_dir)?;

    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}

/// Recursively copy every `*.bin` under `src` into `dst`, preserving the
/// relative subfolder layout (e.g. `keys/ages_mk2/x.bin` -> `bin/ages_mk2/x.bin`).
fn copy_keys(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Rebuild when a blob is added, removed, or changed at this level.
    println!("cargo:rerun-if-changed={}", src.display());
    let mut entries = std::fs::read_dir(src)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().ok_or("invalid directory name")?;
            copy_keys(&path, &dst.join(name))?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("bin") {
            let name = path.file_name().ok_or("invalid file name")?;
            std::fs::create_dir_all(dst)?;
            std::fs::copy(&path, dst.join(name))?;
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    Ok(())
}
