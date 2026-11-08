//! Iterative JSON presentation of PSB trees, including explicit resource
//! references and non-finite IEEE values. Resource payloads are not read.
use super::{Psb, PsbNumber, PsbValue};
use nvlens_core::{Error, Result};

impl Psb {
    /// Presents the parsed object tree as JSON without recursive traversal or
    /// copying resource bodies. Non-finite floats retain their original bits.
    pub fn to_json(&self) -> Result<String> {
        self.root.to_json()
    }
}

impl PsbValue {
    /// Presents this value and its descendants as JSON, preserving the same
    /// resource references and IEEE bit annotations as a whole PSB export.
    pub fn to_json(&self) -> Result<String> {
        enum Pending<'a> {
            Value(&'a PsbValue, usize),
            Key(&'a str),
            Text(&'static str),
            Indent(usize),
        }
        let mut output = String::new();
        let mut pending = vec![Pending::Value(self, 0)];
        while let Some(item) = pending.pop() {
            match item {
                Pending::Text(text) => output.push_str(text),
                Pending::Indent(depth) => {
                    output.push('\n');
                    for _ in 0..depth {
                        output.push_str("  ");
                    }
                }
                Pending::Key(key) => {
                    output.push_str(&json(key)?);
                    output.push_str(": ");
                }
                Pending::Value(value, depth) => match value {
                    PsbValue::Null => output.push_str("null"),
                    PsbValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
                    PsbValue::Number(PsbNumber::Integer(value)) => {
                        output.push_str(&value.to_string())
                    }
                    PsbValue::Number(PsbNumber::Float(value)) => {
                        output.push_str(&if value.is_finite() {
                            json(value)?
                        } else {
                            format!("{{\"$float_bits\": {}}}", value.to_bits())
                        });
                    }
                    PsbValue::Number(PsbNumber::Double(value)) => {
                        output.push_str(&if value.is_finite() {
                            json(value)?
                        } else {
                            format!("{{\"$double_bits\": {}}}", value.to_bits())
                        });
                    }
                    PsbValue::String { value, .. } => output.push_str(&json(value)?),
                    PsbValue::Array(values) => {
                        output.push('[');
                        for (i, value) in values.iter().enumerate() {
                            if i != 0 {
                                output.push_str(", ");
                            }
                            output.push_str(&value.to_string());
                        }
                        output.push(']');
                    }
                    PsbValue::Resource { index, is_extra } => {
                        output.push_str(&format!(
                            "{{\"$resource\": {index}, \"$extra\": {is_extra}}}"
                        ));
                    }
                    PsbValue::List(values) => {
                        output.push('[');
                        pending.push(Pending::Text("]"));
                        if !values.is_empty() {
                            pending.push(Pending::Indent(depth));
                        }
                        for (i, value) in values.iter().enumerate().rev() {
                            if i + 1 != values.len() {
                                pending.push(Pending::Text(","));
                            }
                            pending.push(Pending::Value(value, depth + 1));
                            pending.push(Pending::Indent(depth + 1));
                        }
                    }
                    PsbValue::Object(values) => {
                        output.push('{');
                        pending.push(Pending::Text("}"));
                        if !values.is_empty() {
                            pending.push(Pending::Indent(depth));
                        }
                        for (i, (key, value)) in values.iter().enumerate().rev() {
                            if i + 1 != values.len() {
                                pending.push(Pending::Text(","));
                            }
                            pending.push(Pending::Value(value, depth + 1));
                            pending.push(Pending::Key(key));
                            pending.push(Pending::Indent(depth + 1));
                        }
                    }
                },
            }
        }
        output.push('\n');
        Ok(output)
    }
}

fn json(value: &(impl serde::Serialize + ?Sized)) -> Result<String> {
    serde_json::to_string(value).map_err(|e| Error::Unsupported(format!("PSB JSON: {e}")))
}
