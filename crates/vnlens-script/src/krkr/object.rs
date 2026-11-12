//! OBJS records from tTJSByteCodeLoader::ReadObjects. Links are resolved after
//! every record has been read, so forward references and empty properties work.
use super::{
    bad,
    bytecode::{array, operand},
};
use crate::ir::*;
use std::collections::BTreeMap;
use vnlens_core::Result;
use vnlens_io::BinaryReader;

#[derive(Debug)]
pub(super) struct Object<'a> {
    pub base: usize,
    pub header: [i32; 12],
    pub code_base: usize,
    pub code: Vec<i16>,
    pub source: BTreeMap<usize, u32>,
    pub data: &'a [u8],
    pub data_base: usize,
    pub metadata: Vec<Arg>,
}

fn signed(bytes: &[u8]) -> i32 {
    BinaryReader::u32_le(bytes) as i32
}

fn index(value: i32, count: usize, at: usize) -> Result<()> {
    if value >= 0 && usize::try_from(value).map_or(true, |v| v >= count) {
        return Err(bad(at, "TJS object index out of range"));
    }
    Ok(())
}

pub(super) fn name(value: i32, strings: &[Value], at: usize) -> Result<Value> {
    if value < 0 {
        return Ok(Value::Nil);
    }
    strings
        .get(value as usize)
        .cloned()
        .ok_or_else(|| bad(at, "TJS string index out of range"))
}

impl<'a> Object<'a> {
    pub fn read(bytes: &'a [u8], base: usize, count: usize, strings: &[Value]) -> Result<Self> {
        let mut r = BinaryReader::new(bytes);
        let mut header = [0; 12];
        let mut metadata = Vec::new();
        for (i, field) in [
            ArgName::ParentIndex,
            ArgName::StringIndex,
            ArgName::ContextId,
            ArgName::VariableCount,
            ArgName::ReserveCount,
            ArgName::MaximumRegisterIndex,
            ArgName::ArgumentCount,
            ArgName::ArgumentBase,
            ArgName::CollapseBase,
            ArgName::SetterIndex,
            ArgName::GetterIndex,
            ArgName::SuperClassGetterIndex,
        ]
        .into_iter()
        .enumerate()
        {
            let at = base + r.position();
            header[i] = r.read_u32_le()? as i32;
            metadata.push(operand(field, at, 4, Value::Integer(i64::from(header[i]))));
            if matches!(i, 0 | 9..=11) {
                index(header[i], count, at)?;
            }
        }
        metadata.push(operand(
            ArgName::Name,
            base + 4,
            0,
            name(header[1], strings, base + 4)?,
        ));
        let source_count_at = base + r.position();
        let source_count = r.read_u32_le()? as usize;
        let source_size = source_count
            .checked_mul(4)
            .ok_or_else(|| bad(source_count_at, "TJS source map size overflow"))?;
        let code_positions = r.read_bytes(source_size)?;
        let source_positions = r.read_bytes(source_size)?;
        let mut source = BTreeMap::new();
        let mut rows = Vec::new();
        for (i, (code, text)) in code_positions
            .as_chunks::<4>()
            .0
            .iter()
            .zip(source_positions.as_chunks::<4>().0.iter())
            .enumerate()
        {
            let code = BinaryReader::u32_le(code);
            let text = BinaryReader::u32_le(text);
            source.insert(code as usize, text);
            rows.push(operand(
                ArgName::Row(i as u64),
                source_count_at + 4 + i * 4,
                source_size + 4,
                Value::Group(vec![
                    operand(
                        ArgName::Index,
                        source_count_at + 4 + i * 4,
                        4,
                        Value::Unsigned(u64::from(code)),
                    ),
                    operand(
                        ArgName::SourceOffset,
                        source_count_at + 4 + source_size + i * 4,
                        4,
                        Value::Unsigned(u64::from(text)),
                    ),
                ]),
            ));
        }
        metadata.push(operand(
            ArgName::SourceMap,
            source_count_at,
            4 + source_size * 2,
            Value::Group(rows),
        ));
        let code_bytes = array(&mut r, 2)?;
        let code_base = base + r.position() - code_bytes.len();
        let code = code_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| BinaryReader::u16_le(b) as i16)
            .collect::<Vec<_>>();
        let mut descriptor = vec![
            operand(
                ArgName::Count,
                code_base - 4,
                4,
                Value::Unsigned(code.len() as u64),
            ),
            operand(
                ArgName::DataOffset,
                code_base,
                0,
                Value::DataAddress(code_base as u64),
            ),
        ];
        if !code.is_empty() {
            descriptor.push(operand(
                ArgName::Target,
                code_base,
                0,
                Value::CodeAddress(code_base as u64),
            ));
        }
        metadata.push(operand(
            ArgName::Code,
            code_base - 4,
            4,
            Value::Group(descriptor),
        ));
        r.read_bytes(code_bytes.len() % 4)?;
        let data = array(&mut r, 4)?;
        let data_base = base + r.position() - data.len();
        let getters = array(&mut r, 4)?;
        let getters_base = base + r.position() - getters.len();
        let mut targets = Vec::new();
        for (i, pointer) in getters.as_chunks::<4>().0.iter().enumerate() {
            let pointer = BinaryReader::u32_le(pointer) as usize;
            if pointer >= code.len() {
                return Err(bad(
                    getters_base + i * 4,
                    "TJS superclass getter entry out of range",
                ));
            }
            targets.push(operand(
                ArgName::Row(i as u64),
                getters_base + i * 4,
                4,
                Value::Group(vec![
                    operand(
                        ArgName::Index,
                        getters_base + i * 4,
                        4,
                        Value::Unsigned(pointer as u64),
                    ),
                    operand(
                        ArgName::Target,
                        getters_base + i * 4,
                        0,
                        Value::CodeAddress((code_base + pointer * 2) as u64),
                    ),
                ]),
            ));
        }
        metadata.push(operand(
            ArgName::Targets,
            getters_base - 4,
            getters.len() + 4,
            Value::Group(targets),
        ));
        let properties = array(&mut r, 8)?;
        let properties_base = base + r.position() - properties.len();
        let mut rows = Vec::new();
        for (i, pair) in properties.as_chunks::<8>().0.iter().enumerate() {
            let at = properties_base + i * 8;
            let string = signed(pair);
            let object = signed(&pair[4..]);
            index(object, count, at + 4)?;
            rows.push(operand(
                ArgName::Row(i as u64),
                at,
                8,
                Value::Group(vec![
                    operand(
                        ArgName::StringIndex,
                        at,
                        4,
                        Value::Integer(i64::from(string)),
                    ),
                    operand(ArgName::Name, at, 0, name(string, strings, at)?),
                    operand(
                        ArgName::FunctionIndex,
                        at + 4,
                        4,
                        Value::Integer(i64::from(object)),
                    ),
                ]),
            ));
        }
        metadata.push(operand(
            ArgName::Properties,
            properties_base - 4,
            properties.len() + 4,
            Value::Group(rows),
        ));
        if r.remaining() != 0 {
            return Err(bad(base + r.position(), "Trailing TJS object data"));
        }
        Ok(Self {
            base,
            header,
            code_base,
            code,
            source,
            data,
            data_base,
            metadata,
        })
    }
}
