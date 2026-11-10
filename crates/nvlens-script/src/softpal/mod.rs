//! Softpal Sv20 stack VM: LE u32 opcodes (namespace 1), tagged u32 operands,
//! and encrypted CP932 companion lists. Verified against sub_47C890,
//! sub_459060 and the native handlers sub_4591A0..sub_459B30.
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use nvlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use nvlens_io::BinaryReader;
use std::borrow::Cow;
const SIGNATURES: &[u32] = &[
    0x3032_7653,
    0x5845_5424,
    0x4c49_4624,
    0x494f_5024,
    0x4d45_4d24,
    0x4152_4724,
];
#[derive(Debug, Default)]
struct Softpal;
impl Format for Softpal {
    fn tag(&self) -> &'static str {
        "script/softpal"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["src", "dat", "csv", "txt", "ini"]
    }
    fn description(&self) -> &'static str {
        "Softpal Sv20 bytecode and resource lists"
    }
}
/// Decrypts recognized list payloads; the 16-byte header and partial last word
/// remain intact. Hosts call this once before parsing or resolving companions.
pub fn decode_envelope(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if [
        b"$TEXT_LIST_".as_slice(),
        b"$FILE_LIST_",
        b"$POINT_LIST_",
        b"$MEM_LIST_",
        b"$GRAPH_LIST_",
    ]
    .iter()
    .any(|magic| data.starts_with(magic))
    {
        let mut r = BinaryReader::new(data);
        r.read_bytes(16)?;
        let mut out = data.to_vec();
        nvlens_crypto::cipher::softpal::decrypt(&mut out[16..]);
        Ok(Cow::Owned(out))
    } else {
        Ok(Cow::Borrowed(data))
    }
}
impl ScriptFormat for Softpal {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        decode_envelope(data)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        if data.starts_with(b"$TEXT_LIST__") || data.starts_with(b"$FILE_LIST__") {
            let mut header = BinaryReader::new_at(data, 12)?;
            let count = header.read_u32_le()?;
            let mut r = BinaryReader::new_at(data, 16)?;
            let mut lines = Vec::new();
            for i in 0..count {
                let (id, bytes) = if data.starts_with(b"$FILE") {
                    let bytes = r.read_bytes(32)?;
                    (i, bytes.split(|b| *b == 0).next().unwrap_or_default())
                } else {
                    let id = r.read_u32_le()?;
                    let start = r.position();
                    while r.read_u8()? != 0 {}
                    (id, &data[start..r.position() - 1])
                };
                let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
                if errors {
                    return Err(bad(r.position(), "Invalid Softpal CP932 list text"));
                }
                lines.push(format!("{id}\t{text}"));
            }
            return Ok(Some(lines.join("\n")));
        }
        if data.starts_with(b"Sv20") || data.starts_with(b"$") {
            return Ok(None);
        }
        if data.contains(&0) {
            return Ok(None);
        }
        let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(data);
        Ok((!errors).then(|| text.into_owned()))
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        if !data.starts_with(b"Sv20") {
            return Ok(None);
        }
        let mut r = BinaryReader::new(data);
        r.read_bytes(8)?;
        let entry = r.read_u32_le()?;
        if u64::from(entry) >= data.len() as u64 || entry < 12 || !entry.is_multiple_of(4) {
            return Err(bad(8, "Sv20 entry point is outside code"));
        }
        let points = resources
            .map(|r| r.read_resource("POINT.DAT"))
            .transpose()?
            .flatten();
        let mut instructions = Vec::new();
        while r.remaining() != 0 {
            let start = r.position();
            let word = r.read_u32_le()?;
            if word >> 16 != 1 {
                return Err(bad(start, "Invalid Sv20 opcode namespace"));
            }
            let code = word & 0xffff;
            let count = match code {
                1..=8 | 10 | 12..=19 | 23 | 26..=28 => 2,
                9 | 11 | 20 | 29..=33 => 1,
                _ => 0,
            };
            let mut args = Vec::new();
            for i in 0..count {
                let at = r.position();
                let value = r.read_u32_le()?;
                let target = if matches!(code, 9..=11) && i == 0 && value >> 28 == 0 {
                    if value == 0 {
                        Some(12)
                    } else if let Some(points) = &points {
                        let distance = u64::from(value) * 4;
                        let at = (points.len() as u64)
                            .checked_sub(distance)
                            .filter(|at| *at >= 16)
                            .ok_or_else(|| bad(start, "Sv20 label is outside Point.dat"))?;
                        let mut p = BinaryReader::new_at(points, at as usize)?;
                        Some(u64::from(p.read_u32_le()?) + 12)
                    } else {
                        None
                    }
                } else {
                    None
                };
                args.push(Arg {
                    // Keep the encoded addressing mode even for resolved labels.
                    name: ArgName::Value,
                    native_name: None,
                    span: Span {
                        offset: at as u64,
                        size: 4,
                    },
                    value: target.map_or(Value::Unsigned(u64::from(value)), Value::CodeAddress),
                    attributes: vec![Attribute {
                        name: "addressing_mode".into(),
                        value: u64::from(value >> 28),
                    }],
                });
            }
            let mnemonic = match code {
                1 => "mov",
                2 => "add",
                3 => "sub",
                4 => "mul",
                5 => "div",
                6 => "and",
                7 => "or",
                8 => "xor",
                9 => "jump",
                10 => "jump_zero",
                11 => "call",
                12 => "equal",
                13 => "not_equal",
                14 => "less_equal",
                15 => "greater_equal",
                16 => "less",
                17 => "greater",
                18 => "logical_or",
                19 => "logical_and",
                20 => "not",
                21 => "end",
                22 => "nop",
                23 => "native_call",
                24 => "return",
                25 => "reset",
                26 => "mod",
                27 => "shift_left",
                28 => "shift_right",
                29 => "negate",
                30 => "pop",
                31 => "push",
                32 => "enter",
                33 => "leave",
                _ => "native",
            };
            instructions.push(Instruction {
                id: instructions.len() as u64,
                span: Span {
                    offset: start as u64,
                    size: (r.position() - start) as u64,
                },
                source_line: None,
                opcode: Opcode {
                    operation: Operation::Native,
                    variant: None,
                    namespace: "softpal.sv20".into(),
                    code,
                    native_mnemonic: Some(mnemonic.into()),
                },
                args,
                attributes: Vec::new(),
            });
        }
        Ok(Some(Script {
            ir_version: VERSION,
            format: "Softpal Sv20".into(),
            format_version: 20,
            sections: vec![Section {
                name: "source".into(),
                span: Span {
                    offset: 0,
                    size: data.len() as u64,
                },
                raw: data.to_vec(),
            }],
            instructions,
        }))
    }
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Softpal)) }
#[cfg(test)]
#[path = "../../tests/softpal/mod.rs"]
mod tests;
