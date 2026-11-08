//! AdvHD JSON text validation; retain the original UTF-8 representation.
use nvlens_core::{Error, Result};
pub(super) fn decode(data: &[u8]) -> Result<Option<String>> {
    serde_json::from_slice::<serde_json::Value>(data).map_err(|e| Error::Corrupt {
        offset: e.column() as u64,
        reason: format!("Invalid AdvHD JSON: {e}"),
    })?;
    Ok(Some(
        std::str::from_utf8(data)
            .map_err(|_| Error::InvalidFormat)?
            .to_owned(),
    ))
}
