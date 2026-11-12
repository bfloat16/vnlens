//! Shared lossless script data model and JSON export.
use super::{ArgName, Operation, Qualifier};
use serde::Serialize;

/// Version 5 shares a document envelope; documented native VMs retain their
/// own opcode and argument vocabulary.
pub const VERSION: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Span {
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub span: Span,
    /// Decoded source bytes, preserving padding and fields unused by the VM.
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Attribute {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Opcode {
    /// The engine-independent opcode used by consumers and disassembly.
    #[serde(flatten)]
    pub operation: Operation,
    /// Shared semantic qualifier, e.g. integer/text or logical/arithmetic.
    /// See docs/script-ir.md; this never contains an engine opcode name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<Qualifier>,
    pub namespace: String,
    pub code: u32,
    /// Exact engine-provided name, if present. A shared operation is not
    /// a substitute for this name or for the namespace and numeric opcode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_mnemonic: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Value {
    Nil,
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    /// Preserve IEEE bits, including NaN payloads and negative zero.
    Float64Bits(u64),
    Float32Bits(u32),
    Text(String),
    Bytes(Vec<u8>),
    /// Absolute byte offset in this decoded resource, not an instruction ID.
    CodeAddress(u64),
    /// Absolute byte offset of referenced data in this decoded resource.
    DataAddress(u64),
    InstructionTarget(u64),
    ResourceInstructionTarget {
        resource: String,
        instruction: u64,
        symbol: String,
    },
    Expression(Vec<Token>),
    Group(Vec<Arg>),
}

#[derive(Clone, Debug, Serialize)]
pub struct Token {
    pub opcode: Opcode,
    pub span: Span,
    pub args: Vec<Arg>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Arg {
    #[serde(flatten)]
    pub name: ArgName,
    /// Exact name from a companion definition, including empty names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_name: Option<String>,
    pub span: Span,
    pub value: Value,
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Instruction {
    pub id: u64,
    pub span: Span,
    pub source_line: Option<u32>,
    pub opcode: Opcode,
    pub args: Vec<Arg>,
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Script {
    pub ir_version: u32,
    pub format: String,
    pub format_version: u32,
    pub sections: Vec<Section>,
    pub instructions: Vec<Instruction>,
}

impl Script {
    pub fn to_json(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| crate::Error::Unsupported(format!("Cannot serialize script IR: {e}")))
    }
}

impl Instruction {
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::Unsupported(format!("Cannot serialize instruction IR: {e}")))
    }
}
