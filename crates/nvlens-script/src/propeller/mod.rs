//! Stuff MSC, verified against sub_406700, sub_40DF30 and its seven group
//! handlers. LE header: reserved:u16, code_offset:u32, local_table_size:u32,
//! local rows, exported_table_size:u32, exported rows. Rows are tag:u8,
//! label:i16, code-relative offset:u32. Commands are group:u8, opcode:u8.
//! sub_412B20 values are a type byte and a signed i16; strings are i16-length
//! CP932. Source bytes, duplicate labels and value types remain in the IR.
mod opcode;
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use nvlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use nvlens_io::BinaryReader;
use std::borrow::Cow;

#[derive(Debug, Default)]
struct Msc;
impl Format for Msc {
    fn tag(&self) -> &'static str {
        "msc/propeller"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["msc"]
    }
    fn description(&self) -> &'static str {
        "Propeller Stuff MSC bytecode"
    }
}
impl ScriptFormat for Msc {
    fn decode<'a>(&self, data: &'a [u8], options: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        let key = options.keys.get("propeller_msc").ok_or_else(|| {
            Error::UnknownScheme(Some("Missing identified Propeller MSC parameters".into()))
        })?;
        let mut out = data.to_vec();
        nvlens_crypto::cipher::xor::apply(&mut out, key.bytes())
            .map_err(|e| Error::Unsupported(e.to_string()))?;
        Ok(Cow::Owned(out))
    }
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        parse(data).map(Some)
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Msc)) }

fn parse(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new(data);
    let reserved = r.read_u16_le()?;
    let base = usize::try_from(r.read_u32_le()?)
        .map_err(|_| corrupt(2, "MSC offset exceeds address space"))?;
    let mut instructions = Vec::new();
    let mut header = vec![
        arg(
            ArgName::Reserved,
            0,
            2,
            Value::Unsigned(u64::from(reserved)),
        ),
        arg(ArgName::DataOffset, 2, 4, Value::CodeAddress(base as u64)),
    ];
    let mut labels = std::collections::BTreeMap::new();
    for table in 0..2 {
        let start = r.position();
        let size = usize::try_from(r.read_u32_le()?)
            .map_err(|_| corrupt(start, "MSC table size exceeds address space"))?;
        if !size.is_multiple_of(7) {
            return Err(corrupt(start, "MSC label table has an incomplete row"));
        }
        let bytes = r.read_bytes(size)?;
        let mut rows = BinaryReader::new(bytes);
        let mut items = Vec::new();
        while rows.remaining() != 0 {
            let at = start + 4 + rows.position();
            let tag = rows.read_u8()?;
            let label = rows.read_u16_le()? as i16;
            let target = u64::from(rows.read_u32_le()?) + base as u64;
            if target > data.len() as u64 {
                return Err(corrupt(at + 3, "MSC label target exceeds code storage"));
            }
            if table == 0 {
                labels.insert(i64::from(label), target);
            }
            items.push(arg(
                ArgName::Row(items.len() as u64),
                at,
                7,
                Value::Group(vec![
                    arg(ArgName::Unknown(0), at, 1, Value::Unsigned(u64::from(tag))),
                    arg(
                        ArgName::LabelId,
                        at + 1,
                        2,
                        Value::Integer(i64::from(label)),
                    ),
                    arg(ArgName::Target, at + 3, 4, Value::CodeAddress(target)),
                ]),
            ));
        }
        header.push(arg(
            if table == 0 {
                ArgName::Labels
            } else {
                ArgName::Targets
            },
            start,
            4 + size,
            Value::Group(vec![
                arg(ArgName::ByteCount, start, 4, Value::Unsigned(size as u64)),
                arg(ArgName::Rows, start + 4, size, Value::Group(items)),
            ]),
        ));
    }
    if r.position() > base {
        return Err(corrupt(2, "MSC code overlaps label tables"));
    }
    if r.position() < base {
        let at = r.position();
        header.push(arg(
            ArgName::Unknown(2),
            at,
            base - at,
            Value::Bytes(r.read_bytes(base - at)?.to_vec()),
        ));
    }
    instructions.push(Instruction {
        id: 0,
        span: span(0, base),
        source_line: None,
        opcode: op(
            Operation::Data(DataOperation::Record),
            Some(Qualifier::ScriptMetadata),
            "propeller.msc.header",
            0,
        ),
        args: header,
        attributes: Vec::new(),
    });
    while r.remaining() != 0 {
        let start = r.position();
        let group = r.read_u8()?;
        let code = r.read_u8()?;
        let schema = opcode::schema(group, code).ok_or_else(|| corrupt(start,
            &format!("Unknown MSC instruction {group:02x}:{code:02x}; its argument boundary is unavailable")))?;
        let mut args = Vec::new();
        for (i, &kind) in schema.iter().enumerate() {
            // The event-binding handler treats other event selectors as a
            // no-op and does not consume a label in that branch.
            if (group, code, i) == (4, 0, 2)
                && matches!(
                    args.get(1).map(|a: &Arg| &a.value),
                    Some(Value::Unsigned(4..))
                )
            {
                break;
            }
            let at = r.position();
            let mut item = match kind {
                b'b' => arg(
                    ArgName::Unknown(i as u64),
                    at,
                    1,
                    Value::Unsigned(u64::from(r.read_u8()?)),
                ),
                b'w' => arg(
                    ArgName::Unknown(i as u64),
                    at,
                    2,
                    Value::Integer(i64::from(r.read_u16_le()? as i16)),
                ),
                b'v' => value(data, &mut r, i)?,
                b's' => {
                    let length = r.read_u16_le()? as i16;
                    let length = usize::try_from(length)
                        .map_err(|_| corrupt(at, "Negative MSC string length"))?;
                    let bytes = r.read_bytes(length)?;
                    let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(bytes);
                    if invalid {
                        return Err(corrupt(at + 2, "Invalid MSC CP932 string"));
                    }
                    arg(
                        ArgName::Unknown(i as u64),
                        at,
                        length + 2,
                        Value::Text(text.into_owned()),
                    )
                }
                _ => return Err(Error::Unsupported("Invalid MSC argument schema".into())),
            };
            item.name = opcode::name(group, code, i);
            args.push(item);
        }
        let (operation, variant) = opcode::semantic(group, code, &args);
        // Labels are one-based IDs, not byte offsets. Only literal local
        // targets can be resolved statically; variable operands remain intact.
        let encoded_count = args.len();
        for i in 0..encoded_count {
            if (group, code) == (0, 1)
                && !matches!(args.get(3).map(|a| &a.value), Some(Value::Unsigned(0 | 1)))
            {
                continue;
            }
            if args[i].name == ArgName::LabelId
                && let Value::Integer(label) = args[i].value
                && let Some(&target) = labels.get(&label)
            {
                args.push(arg(
                    ArgName::ResolvedTarget,
                    r.position(),
                    0,
                    Value::CodeAddress(target),
                ));
            }
        }
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span: span(start, r.position() - start),
            source_line: None,
            opcode: op(
                operation,
                variant,
                "propeller.msc",
                u32::from(group) * 256 + u32::from(code),
            ),
            args,
            attributes: Vec::new(),
        });
    }
    Ok(Script {
        ir_version: VERSION,
        format: "msc/propeller".into(),
        format_version: 0,
        sections: vec![Section {
            name: "msc".into(),
            span: span(0, data.len()),
            raw: data.to_vec(),
        }],
        instructions,
    })
}
fn value(data: &[u8], r: &mut BinaryReader<'_>, index: usize) -> Result<Arg> {
    let at = r.position();
    let kind = r.read_u8()?;
    let word = if kind <= 4 {
        Some(i64::from(r.read_u16_le()? as i16))
    } else {
        None
    };
    let mut fields = vec![arg(
        ArgName::ValueType,
        at,
        1,
        Value::Unsigned(u64::from(kind)),
    )];
    let operation = match kind {
        0 => Operation::Storage(StorageOperation::Push),
        1 | 2 => Operation::Storage(StorageOperation::Load),
        3 => Operation::Basic(BasicOperation::Random),
        4 => Operation::Runtime(RuntimeOperation::EngineCall),
        _ => Operation::Unknown,
    };
    if let Some(word) = word {
        fields.push(arg(
            match kind {
                1 | 2 => ArgName::VariableId,
                3 => ArgName::Maximum,
                0 => ArgName::Value,
                _ => ArgName::Unknown(0),
            },
            at + 1,
            2,
            Value::Integer(word),
        ));
    }
    let value = if kind == 0 {
        Value::Integer(word.unwrap_or_default())
    } else {
        Value::Expression(vec![Token {
            opcode: op(operation, None, "propeller.msc.value", u32::from(kind)),
            span: span(at, r.position() - at),
            args: fields,
            raw: data[at..r.position()].to_vec(),
        }])
    };
    let mut item = arg(ArgName::Unknown(index as u64), at, r.position() - at, value);
    item.attributes.push(Attribute {
        name: "type".into(),
        value: u64::from(kind),
    });
    Ok(item)
}
fn span(offset: usize, size: usize) -> Span {
    Span {
        offset: offset as u64,
        size: size as u64,
    }
}
fn arg(name: ArgName, offset: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(offset, size),
        value,
        attributes: Vec::new(),
    }
}
fn op(operation: Operation, variant: Option<Qualifier>, namespace: &str, code: u32) -> Opcode {
    Opcode {
        operation,
        variant,
        namespace: namespace.into(),
        code,
        native_mnemonic: None,
    }
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/propeller/mod.rs"]
mod tests;
