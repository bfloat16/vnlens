//! Loading and caching of external key blobs.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

fn cache() -> &'static Mutex<HashMap<String, Arc<[u8]>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<[u8]>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Loads a relative `<engine>/<file>.bin` key, sharing immutable cached bytes.
/// Invalid paths and missing assets return I/O errors.
pub fn load(name: &str) -> io::Result<Arc<[u8]>> {
    validate_name(name)?;
    if let Some(blob) = cache()
        .lock()
        .ok()
        .and_then(|guard| guard.get(name).cloned())
    {
        return Ok(blob);
    }
    let path = locate(name)?;
    let bytes = std::fs::read(&path)?;
    let blob: Arc<[u8]> = bytes.into();
    tracing::debug!(key = name, bytes = blob.len(), "loaded key blob");
    if let Ok(mut guard) = cache().lock() {
        return Ok(Arc::clone(guard.entry(name.to_owned()).or_insert(blob)));
    }
    Ok(blob)
}

fn validate_name(name: &str) -> io::Result<()> {
    let parts: Vec<_> = name.split('/').collect();
    if parts.len() < 2
        || !name.ends_with(".bin")
        || parts.iter().any(|part| {
            part.is_empty() || *part == "." || *part == ".." || part.contains(['\\', ':', '\0'])
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key name must be <engine>/<file>.bin",
        ));
    }
    Ok(())
}

fn locate(name: &str) -> io::Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::var_os("NVLENS_BIN_DIR") {
        candidates.push(PathBuf::from(dir).join(name));
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
    {
        candidates.push(dir.join("bin").join(name));
        candidates.push(dir.join(name));
        if let Some(up) = dir.parent() {
            candidates.push(up.join("bin").join(name));
        }
    }
    if let Some(src) = option_env!("NVLENS_KEYS_SRC") {
        candidates.push(PathBuf::from(src).join(name));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("key blob '{name}' not found; set NVLENS_BIN_DIR to its root directory"),
            )
        })
}

#[cfg(test)]
#[path = "../tests/loader.rs"]
mod tests;
