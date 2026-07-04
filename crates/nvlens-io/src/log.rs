//! Unified logging manager for the whole project.
//!
//! Built on the `tracing` ecosystem. Binaries call [`init`] once at startup;
//! every crate emits records with the `tracing` macros (`trace!`, `debug!`,
//! `info!`, `warn!`, `error!`). The active level can be overridden at runtime
//! via the `RUST_LOG` environment variable.

use std::sync::Once;

use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

/// Initializes the global logger.
///
/// `verbosity` maps `0 => info`, `1 => debug`, `>=2 => trace`. A `RUST_LOG`
/// value, if present, takes precedence. Safe to call more than once; only the
/// first call takes effect.
pub fn init(verbosity: u8) {
    INIT.call_once(|| {
        let level = match verbosity {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    });
}
