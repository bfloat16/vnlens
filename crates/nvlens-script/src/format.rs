//! Script decoder registration, independent of the desktop presentation layer.

use crate::ir::Script;
use nvlens_core::{Format, ResourceResolver, Result};

pub trait ScriptFormat: Format {
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>>;
}

#[derive(Debug)]
pub struct ScriptRegistration(pub fn() -> Box<dyn ScriptFormat>);
nvlens_core::inventory::collect!(ScriptRegistration);

/// Dispatches only to the bytecode reader selected by the game context.
pub fn disassemble_as(
    tag: &str,
    data: &[u8],
    resources: Option<&dyn ResourceResolver>,
) -> Result<Option<Script>> {
    for registration in nvlens_core::inventory::iter::<ScriptRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return format.disassemble(data, resources);
        }
    }
    Err(nvlens_core::Error::Unsupported(format!(
        "Script route is not registered: {tag}"
    )))
}
