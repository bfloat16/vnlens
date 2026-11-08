//! Text rendering for common IR and explicitly native bytecode dialects.
use super::*;
use std::{borrow::Cow, fmt::Write};

impl Opcode {
    /// Shared semantic name, or the native mnemonic of an unmapped dialect.
    #[must_use]
    pub fn display_name(&self) -> Cow<'_, str> {
        if self.operation == Operation::Native {
            self.native_mnemonic.as_deref().map_or_else(
                || Cow::Owned(format!("OP_{:02X}", self.code)),
                Cow::Borrowed,
            )
        } else {
            Cow::Borrowed(self.operation.name())
        }
    }
}

impl Instruction {
    #[must_use]
    pub fn disassembly(&self) -> String {
        let mut text = format!("{:08X}  ", self.span.offset);
        if let Some(line) = self.source_line {
            let _ = write!(text, "L{line:<6} ");
        }
        text.push_str(&self.opcode_name());
        let args = self.args_disassembly();
        if !args.is_empty() {
            text.push_str("  ");
            text.push_str(&args);
        }
        text
    }

    /// Returns the shared operation name or an explicitly native mnemonic.
    #[must_use]
    pub fn opcode_name(&self) -> String {
        self.opcode.display_name().into_owned()
    }

    /// Renders only the operand list so consumers can place it in a table
    /// without parsing the complete disassembly string.
    #[must_use]
    pub fn args_disassembly(&self) -> String {
        let mut text = String::new();
        render_opcode_details(&self.opcode, &mut text);
        for operand in &self.args {
            if !text.is_empty() {
                text.push_str(", ");
            }
            let _ = write!(text, "{}=", operand.name);
            render_value(&operand.value, &mut text);
        }
        text
    }
}

fn render_opcode_details(opcode: &Opcode, text: &mut String) {
    if let Some(variant) = &opcode.variant {
        let _ = write!(text, "variant={}", variant.name());
    }
    if matches!(
        opcode.operation,
        Operation::Runtime(RuntimeOperation::EngineCall) | Operation::Unknown
    ) {
        if !text.is_empty() {
            text.push_str(", ");
        }
        let _ = write!(text, "native={}:0x{:02X}", opcode.namespace, opcode.code);
        if let Some(name) = &opcode.native_mnemonic {
            let _ = write!(text, " ({name:?})");
        }
    } else if opcode.operation == Operation::Data(DataOperation::Record)
        && let Some(name) = &opcode.native_mnemonic
    {
        if !text.is_empty() {
            text.push_str(", ");
        }
        let _ = write!(text, "command={name:?}");
    }
}

fn render_value(value: &Value, text: &mut String) {
    match value {
        Value::Nil => text.push_str("nil"),
        Value::Boolean(v) => {
            let _ = write!(text, "{v}");
        }
        Value::Integer(v) => {
            let _ = write!(text, "{v}");
        }
        Value::Unsigned(v) => {
            let _ = write!(text, "0x{v:X}");
        }
        Value::Float32Bits(v) => {
            let _ = write!(text, "{}", f32::from_bits(*v));
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
        Value::CodeAddress(v) => {
            let _ = write!(text, "code@0x{v:X}");
        }
        Value::DataAddress(v) => {
            let _ = write!(text, "data@0x{v:X}");
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
                text.push_str(&token.opcode.display_name());
                let mut details = String::new();
                render_opcode_details(&token.opcode, &mut details);
                if !details.is_empty() {
                    let _ = write!(text, "{{{details}}}");
                }
                if !token.args.is_empty() {
                    text.push('(');
                    for (index, arg) in token.args.iter().enumerate() {
                        if index != 0 {
                            text.push_str(", ");
                        }
                        let _ = write!(text, "{}=", arg.name);
                        render_value(&arg.value, text);
                    }
                    text.push(')');
                }
            }
            text.push(']');
        }
        Value::Group(fields) => {
            text.push('{');
            for (index, field) in fields.iter().enumerate() {
                if index != 0 {
                    text.push_str(", ");
                }
                let _ = write!(text, "{}", field.name);
                text.push(':');
                render_value(&field.value, text);
            }
            text.push('}');
        }
    }
}
