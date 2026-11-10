//! Local desktop preferences; writes run in background tasks and preserve toggle order.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug, Default)]
pub struct Preferences {
    virtual_paths: Arc<AtomicBool>,
    write_lock: Arc<Mutex<()>>,
}

impl Preferences {
    pub fn load() -> Self {
        let preferences = Self::default();
        let result = (|| -> anyhow::Result<()> {
            let path = directory()?.join("preferences");
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("virtual_script_paths=") {
                    preferences.set_virtual_paths(value.parse()?);
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            tracing::warn!(%error, "Cannot load preferences");
        }
        preferences
    }

    pub fn virtual_paths(&self) -> bool {
        self.virtual_paths.load(Ordering::Relaxed)
    }

    pub fn set_virtual_paths(&self, enabled: bool) {
        self.virtual_paths.store(enabled, Ordering::Relaxed);
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("Preference writer is unavailable"))?;
        // Read after acquiring the writer: an older queued task cannot restore
        // an obsolete value after a more recent click.
        let text = format!("virtual_script_paths={}\n", self.virtual_paths());
        vnlens_io::filesystem::write_under(&directory()?, "preferences", text.as_bytes())?;
        Ok(())
    }
}

fn directory() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|root| PathBuf::from(root).join("Library/Application Support"));
    #[cfg(not(any(windows, target_os = "macos")))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|root| PathBuf::from(root).join(".config")));
    root.map(|root| root.join("vnlens"))
        .ok_or_else(|| anyhow::anyhow!("Configuration directory is unavailable"))
}
