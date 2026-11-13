//! Script decoder registration, independent of the desktop presentation layer.

use crate::ir::Script;
use vnlens_core::{Format, ResourceResolver, Result};

pub trait ScriptFormat: Format {
    /// Removes resource encryption using parameters resolved by the engine.
    /// Unrecognized resources borrow their original bytes unchanged.
    fn decode<'a>(
        &self,
        data: &'a [u8],
        _options: &vnlens_core::ArchiveOptions,
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(data))
    }
    /// Resolves resource-backed encryption evidence on demand. PE parameters
    /// remain available to the selected decoder before requesting companions.
    fn decode_with_resources<'a>(
        &self,
        data: &'a [u8],
        _resources: Option<&dyn ResourceResolver>,
        options: &vnlens_core::ArchiveOptions,
        _cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        self.decode(data, options)
    }
    /// Decodes recognized text or presents structured data as text. Bytecode and
    /// unrelated bytes return None; the source resource remains unchanged.
    fn decode_text(&self, _data: &[u8]) -> Result<Option<String>> {
        Ok(None)
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>>;
    /// Supplies engine-resolved schemas or parameters to a bytecode reader.
    fn disassemble_with_options(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
        _options: &vnlens_core::ArchiveOptions,
    ) -> Result<Option<Script>> {
        self.disassemble(data, resources)
    }
    /// Allows long bytecode readers to respond at instruction/table boundaries.
    fn disassemble_cancellable(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
        options: &vnlens_core::ArchiveOptions,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<Script>> {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(vnlens_core::Error::Cancelled);
        }
        let result = self.disassemble_with_options(data, resources, options)?;
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(vnlens_core::Error::Cancelled);
        }
        Ok(result)
    }
}

#[derive(Debug)]
pub struct ScriptRegistration(pub fn() -> Box<dyn ScriptFormat>);
vnlens_core::inventory::collect!(ScriptRegistration);

fn selected(tag: &str) -> Result<Box<dyn ScriptFormat>> {
    for registration in vnlens_core::inventory::iter::<ScriptRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return Ok(format);
        }
    }
    Err(vnlens_core::Error::Unsupported(format!(
        "Script route is not registered: {tag}"
    )))
}

/// Decodes only the selected engine's resource envelope, before IR parsing.
pub fn decode_as<'a>(
    tag: &str,
    data: &'a [u8],
    options: &vnlens_core::ArchiveOptions,
) -> Result<std::borrow::Cow<'a, [u8]>> {
    selected(tag)?.decode(data, options)
}

/// Decodes the selected resource envelope with on-demand companion access.
/// Cancellation is checked before and after the decoder and during supported
/// recovery algorithms. Borrowed resources retain their original ownership.
pub fn decode_with_resources_as<'a>(
    tag: &str,
    data: &'a [u8],
    resources: Option<&dyn ResourceResolver>,
    options: &vnlens_core::ArchiveOptions,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<std::borrow::Cow<'a, [u8]>> {
    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(vnlens_core::Error::Cancelled);
    }
    let decoded = selected(tag)?.decode_with_resources(data, resources, options, cancelled)?;
    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(vnlens_core::Error::Cancelled);
    }
    Ok(decoded)
}

/// Selects text decoding using the identified engine's script route.
pub fn decode_text_as(tag: &str, data: &[u8]) -> Result<Option<String>> {
    selected(tag)?.decode_text(data)
}

/// Dispatches only to the bytecode reader selected by the game context.
pub fn disassemble_as(
    tag: &str,
    data: &[u8],
    resources: Option<&dyn ResourceResolver>,
) -> Result<Option<Script>> {
    selected(tag)?.disassemble(data, resources)
}

/// Selects one script format and passes the host's cancellation token through.
pub fn disassemble_cancellable_as(
    tag: &str,
    data: &[u8],
    resources: Option<&dyn ResourceResolver>,
    options: &vnlens_core::ArchiveOptions,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Option<Script>> {
    selected(tag)?.disassemble_cancellable(data, resources, options, cancelled)
}
