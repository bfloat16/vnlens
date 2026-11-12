//! MAGES_Tools SCX/MES layouts and libMgs ExecuteScxLoop/ReadValue dispatch.
//! SC3 programs retain code, tables and embedded data; MES messages retain
//! glyph IDs and rendering controls without assuming a Unicode character set.
mod expression;
mod msb;
mod opcode;
mod scx;
mod semantics;

use crate::{ScriptFormat, ScriptRegistration, ir::*};
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};

#[derive(Debug)]
struct Scx;
impl Format for Scx {
    fn tag(&self) -> &'static str {
        "scx/mages"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x0033_4353]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["scx"]
    }
    fn description(&self) -> &'static str {
        "MAGES SC3 bytecode"
    }
}
impl ScriptFormat for Scx {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        self.disassemble_with_options(data, None, &ArchiveOptions::default())
    }
    fn disassemble_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        options: &ArchiveOptions,
    ) -> Result<Option<Script>> {
        scx::disassemble(
            data,
            Layout {
                glyph_width: glyph_width(options)?,
                dialogue_extension: options.numbers.get("mages_dialogue_extension") == Some(&1),
                extended_context: options.numbers.get("mages_extended_context") == Some(&1),
                surface_operands: options.numbers.get("mages_surface_operands").copied(),
                layer_operands: options.numbers.get("mages_layer_operands").copied(),
            },
        )
        .map(Some)
    }
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    glyph_width: usize,
    dialogue_extension: bool,
    extended_context: bool,
    surface_operands: Option<u64>,
    layer_operands: Option<u64>,
}
#[derive(Debug)]
struct Msb;
impl Format for Msb {
    fn tag(&self) -> &'static str {
        "msb/mages"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x0053_454d]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["msb"]
    }
    fn description(&self) -> &'static str {
        "MAGES MES message bank"
    }
}
impl ScriptFormat for Msb {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        self.disassemble_with_options(data, None, &ArchiveOptions::default())
    }
    fn disassemble_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        options: &ArchiveOptions,
    ) -> Result<Option<Script>> {
        msb::disassemble(data, glyph_width(options)?).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Scx)) }
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Msb)) }

fn corrupt(at: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: at as u64,
        reason: reason.into(),
    }
}
fn span(start: usize, end: usize) -> Span {
    Span {
        offset: start as u64,
        size: (end - start) as u64,
    }
}
fn arg(name: ArgName, start: usize, end: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(start, end),
        value,
        attributes: Vec::new(),
    }
}
fn op(namespace: &str, code: u32, operation: Operation) -> Opcode {
    Opcode {
        operation,
        variant: None,
        namespace: namespace.into(),
        code,
        native_mnemonic: None,
    }
}
fn section(name: &str, data: &[u8], start: usize, end: usize) -> Section {
    Section {
        name: name.into(),
        span: span(start, end),
        raw: data[start..end].to_vec(),
    }
}

fn glyph_width(options: &ArchiveOptions) -> Result<usize> {
    match options.numbers.get("mages_glyph_width") {
        Some(2) => Ok(2),
        Some(4) => Ok(4),
        _ => Err(Error::Unsupported(
            "MAGES script layout requires an identified glyph reader".into(),
        )),
    }
}

#[cfg(test)]
#[path = "../../tests/mages/mod.rs"]
mod tests;
