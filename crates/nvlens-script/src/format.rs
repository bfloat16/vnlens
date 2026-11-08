//! Script decoder registration, independent of the desktop presentation layer.

use crate::ir::Script;
use nvlens_core::{Format, ResourceResolver, Result};

pub trait ScriptFormat: Format {
    /// Removes resource encryption using parameters resolved by the engine.
    /// Unrecognized resources borrow their original bytes unchanged.
    fn decode<'a>(
        &self,
        data: &'a [u8],
        _options: &nvlens_core::ArchiveOptions,
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(data))
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
        _options: &nvlens_core::ArchiveOptions,
    ) -> Result<Option<Script>> {
        self.disassemble(data, resources)
    }
}

#[derive(Debug)]
pub struct ScriptRegistration(pub fn() -> Box<dyn ScriptFormat>);
nvlens_core::inventory::collect!(ScriptRegistration);

/// Decodes only the selected engine's resource envelope, before IR parsing.
pub fn decode_as<'a>(
    tag: &str,
    data: &'a [u8],
    options: &nvlens_core::ArchiveOptions,
) -> Result<std::borrow::Cow<'a, [u8]>> {
    for registration in nvlens_core::inventory::iter::<ScriptRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return format.decode(data, options);
        }
    }
    Err(nvlens_core::Error::Unsupported(format!(
        "Script route is not registered: {tag}"
    )))
}

/// Selects text decoding using the identified engine's script route.
pub fn decode_text_as(tag: &str, data: &[u8]) -> Result<Option<String>> {
    for registration in nvlens_core::inventory::iter::<ScriptRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return format.decode_text(data);
        }
    }
    Err(nvlens_core::Error::Unsupported(format!(
        "Script route is not registered: {tag}"
    )))
}

/// Dispatches only to the bytecode reader selected by the game context.
pub fn disassemble_as(
    tag: &str,
    data: &[u8],
    resources: Option<&dyn ResourceResolver>,
) -> Result<Option<Script>> {
    disassemble_with_options_as(
        tag,
        data,
        resources,
        &nvlens_core::ArchiveOptions::default(),
    )
}

/// Dispatches with the identified game's bytecode parameters.
pub fn disassemble_with_options_as(
    tag: &str,
    data: &[u8],
    resources: Option<&dyn ResourceResolver>,
    options: &nvlens_core::ArchiveOptions,
) -> Result<Option<Script>> {
    for registration in nvlens_core::inventory::iter::<ScriptRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return format.disassemble_with_options(data, resources, options);
        }
    }
    Err(nvlens_core::Error::Unsupported(format!(
        "Script route is not registered: {tag}"
    )))
}
