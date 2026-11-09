//! Fetches the pinned FFmpeg-Builds (BtbN) LGPL shared build into `target/ffmpeg/`.
//!
//! The archive comes from a month-end autobuild, which BtbN keeps for two
//! years, and is checked against the SHA-256 published with the release asset.
//! The extracted tree (`bin/`, `include/`, `lib/`) is what `.cargo/config.toml`
//! exposes to ffmpeg-sys-next as `FFMPEG_DIR`; a matching `.sha256` marker
//! means the tree is complete and is reused without downloading again.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const URL: &str = "https://github.com/FFmpeg-Builds/FFmpeg-Builds/releases/download/autobuild-2026-10-31-12-59/ffmpeg-n9.0.2-39-g7adfbe40dc-win64-lgpl-shared-9.0.zip";
const SHA256: &str = "e907b01fa4783913151237e37df2a10fa97d99a1598a021bf59d4ae62ffed4c0";
/// Must match `FFMPEG_DIR` in `.cargo/config.toml`.
const DIR: &str = "9.0";
const MARKER: &str = ".sha256";

pub fn fetch() -> Result<()> {
    if !cfg!(all(windows, target_arch = "x86_64")) {
        return Err(
            "no pinned FFmpeg build for this host; set FFMPEG_DIR to an FFmpeg 9 shared build"
                .into(),
        );
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("cannot locate the workspace root")?
        .join("target")
        .join("ffmpeg");
    let dest = root.join(DIR);
    if fs::read_to_string(dest.join(MARKER)).is_ok_and(|marker| marker.trim() == SHA256) {
        println!("FFmpeg is up to date: {}", dest.display());
        return Ok(());
    }
    fs::create_dir_all(&root)?;
    let archive = root.join(format!("{DIR}.zip"));
    if sha256(&archive).ok().as_deref() != Some(SHA256) {
        let partial = root.join(format!("{DIR}.zip.part"));
        println!("Downloading {URL}");
        let status = Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--retry",
                "3",
                "--progress-bar",
                "--output",
            ])
            .arg(&partial)
            .arg(URL)
            .status()?;
        if !status.success() {
            return Err(format!("curl failed with {status}").into());
        }
        let digest = sha256(&partial)?;
        if digest != SHA256 {
            fs::remove_file(&partial)?;
            return Err(format!("SHA-256 mismatch: expected {SHA256}, got {digest}").into());
        }
        fs::rename(&partial, &archive)?;
    }

    let staging = root.join(format!("{DIR}.tmp"));
    remove_dir(&staging)?;
    zip::ZipArchive::new(File::open(&archive)?)?
        .extract_unwrapped_root_dir(&staging, zip::read::root_dir_common_filter)?;
    for required in ["bin", "include", "lib"] {
        if !staging.join(required).is_dir() {
            return Err(format!("FFmpeg archive has no {required}/ directory").into());
        }
    }
    fs::write(staging.join(MARKER), SHA256)?;
    remove_dir(&dest)?;
    fs::rename(&staging, &dest)?;
    fs::remove_file(&archive)?;
    println!("FFmpeg is ready: {}", dest.display());
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn remove_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}
