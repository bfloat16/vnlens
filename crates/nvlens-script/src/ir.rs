//! Extensible, lossless disassembly IR shared by bytecode script engines.
//! Addresses and spans refer to decoded resource bytes. Unknown operations and
//! operands retain their numeric IDs and bytes; no high-level code is inferred.

use serde::Serialize;
use std::fmt::Write;

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
    pub namespace: String,
    pub code: u32,
    pub mnemonic: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Value {
    Integer(i64),
    Unsigned(u64),
    /// Preserve IEEE bits, including NaN payloads and negative zero.
    Float64Bits(u64),
    Text(String),
    Bytes(Vec<u8>),
    InstructionTarget(u64),
    ResourceInstructionTarget {
        resource: String,
        instruction: u64,
        symbol: String,
    },
    Expression(Vec<Token>),
    Fields(Vec<Operand>),
}

#[derive(Clone, Debug, Serialize)]
pub struct Token {
    pub opcode: Opcode,
    pub span: Span,
    pub value: Option<Value>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Operand {
    pub name: String,
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
    pub operands: Vec<Operand>,
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
    pub fn to_json(&self) -> nvlens_core::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| {
            nvlens_core::Error::Unsupported(format!("Cannot serialize script IR: {e}"))
        })
    }
}

impl Instruction {
    pub fn to_json(&self) -> nvlens_core::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            nvlens_core::Error::Unsupported(format!("Cannot serialize instruction IR: {e}"))
        })
    }
    #[must_use]
    pub fn disassembly(&self) -> String {
        let mut text = format!("{:08X}  ", self.span.offset);
        if let Some(line) = self.source_line {
            let _ = write!(text, "L{line:<6} ");
        }
        text.push_str(&self.opcode_name());
        let operands = self.operands_disassembly();
        if !operands.is_empty() {
            text.push_str("  ");
            text.push_str(&operands);
        }
        text
    }

    /// Returns the mnemonic used by the disassembly view, retaining an
    /// explicit numeric name for an opcode that has no known definition.
    #[must_use]
    pub fn opcode_name(&self) -> String {
        self.opcode
            .mnemonic
            .clone()
            .unwrap_or_else(|| format!("op_{:02X}", self.opcode.code))
    }

    /// Renders only the operand list so consumers can place it in a table
    /// without parsing the complete disassembly string.
    #[must_use]
    pub fn operands_disassembly(&self) -> String {
        let mut text = String::new();
        for (index, operand) in self.operands.iter().enumerate() {
            text.push_str(if index == 0 { "" } else { ", " });
            let _ = write!(text, "{}=", operand.name);
            render_value(&operand.value, &mut text);
        }
        text
    }
}

fn render_value(value: &Value, text: &mut String) {
    match value {
        Value::Integer(v) => {
            let _ = write!(text, "{v}");
        }
        Value::Unsigned(v) => {
            let _ = write!(text, "0x{v:X}");
        }
        Value::Float64Bits(v) => {
            let _ = write!(text, "{}", f64::from_bits(*v));
        }
        Value::Text(v) => {
            let _ = write!(text, "{v:?}");
        }
        Value::Bytes(v) => {
            text.push_str("hex[");
            for byte in v {
                let _ = write!(text, "{byte:02X}");
            }
            text.push(']');
        }
        Value::InstructionTarget(v) => {
            let _ = write!(text, "@{v:06}");
        }
        Value::ResourceInstructionTarget {
            resource,
            instruction,
            symbol,
        } => {
            let _ = write!(text, "{resource}:@{instruction:06} ({symbol})");
        }
        Value::Expression(tokens) => {
            text.push('[');
            for (index, token) in tokens.iter().enumerate() {
                if index != 0 {
                    text.push(' ');
                }
                if let Some(name) = &token.opcode.mnemonic {
                    text.push_str(name);
                } else {
                    let _ = write!(text, "token_{:02X}", token.opcode.code);
                }
                if let Some(value) = &token.value {
                    text.push('(');
                    render_value(value, text);
                    text.push(')');
                }
            }
            text.push(']');
        }
        Value::Fields(fields) => {
            text.push('{');
            for (index, field) in fields.iter().enumerate() {
                if index != 0 {
                    text.push_str(", ");
                }
                text.push_str(&field.name);
                text.push(':');
                render_value(&field.value, text);
            }
            text.push('}');
        }
    }
}
