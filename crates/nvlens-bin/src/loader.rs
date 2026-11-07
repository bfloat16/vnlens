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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keys;

    #[test]
    fn loads_bundled_blob_by_engine_path() {
        // Exercises the `<engine>/<file>` name joined onto the bin/ sidecar
        // (with the source-dir fallback) and confirms the blob size, which also
        // guards the per-engine subfolder layout on platforms using `\` paths.
        let blob = load(keys::ages_mk2::SCRAMBLE_BASE).unwrap();
        assert_eq!(blob.len(), 0x1_0000);
    }

    #[test]
    fn repeated_loads_share_the_cached_arc() {
        let a = load(keys::ages_mk2::EPK_BLOWFISH_DATAS).unwrap();
        let b = load(keys::ages_mk2::EPK_BLOWFISH_DATAS).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.len(), 4168);
    }

    #[test]
    fn missing_blob_is_not_found() {
        let err = load("ages_mk2/does_not_exist.bin").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn compiled_sidecar_contains_all_keys_without_source_fallback() {
        let exe = std::env::current_exe().unwrap();
        let profile = exe.parent().unwrap().parent().unwrap();
        for name in [
            keys::ages_mk2::SCRAMBLE_BASE,
            keys::ages_mk2::EPK_BLOWFISH_DATAS,
            keys::ages_mk2::SOUND_BLOWFISH_DATAS,
            keys::ages_mk2::SOUND_MD5_SALT,
        ] {
            let bytes = std::fs::read(profile.join("bin").join(name)).unwrap();
            assert_eq!(bytes.as_slice(), load(name).unwrap().as_ref());
        }
    }

    #[test]
    fn rejects_key_path_traversal() {
        for name in [
            "../key.bin",
            "/engine/key.bin",
            "C:/key.bin",
            "engine/../key.bin",
        ] {
            assert_eq!(load(name).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }
}
