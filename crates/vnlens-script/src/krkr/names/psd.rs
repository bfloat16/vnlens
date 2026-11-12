//! PSDInfo::internalLoadTXT uses the fixed infonames column order; loadDATA
//! selects normal layers, getLayerImageName builds `stem_id` for positive IDs,
//! and PSDInfoLayer::setImageInfo appends `.tlg`. IDs come from actual table
//! rows, never from a guessed numeric range. The header is a comment in TJS;
//! recognizing it here does not allow it to redefine the native column order.
use super::check;
use std::{collections::BTreeSet, sync::atomic::AtomicBool};
use vnlens_core::Result;

pub(super) fn candidates(
    text: &str,
    name: &str,
    cancel: &AtomicBool,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    let Some((base, extension)) = name.rsplit_once('.') else {
        return Ok(());
    };
    if !extension.eq_ignore_ascii_case("txt")
        || !text.lines().next().is_some_and(|line| {
            line.starts_with(
                "#layer_type\tname\tleft\ttop\twidth\theight\ttype\topacity\tvisible\tlayer_id\t",
            )
        })
    {
        return Ok(());
    }
    for line in text.lines() {
        check(cancel)?;
        if line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        if fields.next().and_then(|value| value.parse::<i64>().ok()) != Some(0) {
            continue;
        }
        let Some(id) = fields.nth(8).and_then(|value| value.parse::<i64>().ok()) else {
            continue;
        };
        if id > 0 {
            out.insert(format!("{base}_{id}.tlg"));
        } else if id == 0 {
            // PSDInfo.reNumber is ^[1-9][0-9]*$, so zero is a literal name.
            out.insert("0.tlg".into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/krkr/names/psd.rs"]
mod tests;
