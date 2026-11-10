//! Build script: places the FFmpeg shared libraries named by `FFMPEG_DIR`
//! (see `.cargo/config.toml` and `cargo ffmpeg`) next to the compiled
//! binaries, so `nvlens.exe` starts without FFmpeg on `PATH`.
//!
//! It also adds `bin/` as a native search path, which Cargo puts on the
//! loader path for `cargo run` and `cargo test` when it lies under `target/`.

#![forbid(unsafe_code)]

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=FFMPEG_DIR");
    println!("cargo:rerun-if-changed=../nvlens-video/build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS")? != "windows" {
        return Ok(());
    }
    let ffmpeg = std::env::var("FFMPEG_DIR")
        .map_err(|_| "FFMPEG_DIR is not set; run `cargo ffmpeg` in the workspace root")?;
    let bin = Path::new(&ffmpeg).join("bin");
    // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out.
    let out_dir = std::env::var("OUT_DIR")?;
    let profile_dir = Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .ok_or("cannot locate target profile directory from OUT_DIR")?;
    println!("cargo:rerun-if-changed={}", bin.display());
    println!("cargo:rustc-link-search=native={}", bin.display());
    let mut entries = std::fs::read_dir(&bin)
        .map_err(|error| format!("{}: {error}; run `cargo ffmpeg`", bin.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
        {
            println!("cargo:rerun-if-changed={}", path.display());
            let name = path.file_name().ok_or("invalid file name")?;
            let destination = profile_dir.join(name);
            if same_contents(&path, &destination)? {
                continue;
            }
            // Each package stages in its own OUT_DIR. Atomic replacement avoids
            // audio/video build scripts concurrently truncating the same DLL.
            let temporary = Path::new(&out_dir).join(name);
            std::fs::copy(&path, &temporary)?;
            if let Err(error) = std::fs::rename(&temporary, &destination) {
                if !same_contents(&path, &destination)? {
                    return Err(error.into());
                }
                std::fs::remove_file(&temporary)?;
            }
        }
    }
    Ok(())
}

fn same_contents(source: &Path, destination: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut source = std::fs::File::open(source)?;
    let mut destination = match std::fs::File::open(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if source.metadata()?.len() != destination.metadata()?.len() {
        return Ok(false);
    }
    let (mut a, mut b) = ([0; 8192], [0; 8192]);
    loop {
        let count = source.read(&mut a)?;
        if count == 0 {
            return Ok(true);
        }
        destination.read_exact(&mut b[..count])?;
        if a[..count] != b[..count] {
            return Ok(false);
        }
    }
}
