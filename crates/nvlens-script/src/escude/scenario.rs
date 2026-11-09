//! Scenario layout from misc/script.c::load_script_file/load_script_mess.
//! The 45 instructions and fixed LE i32 operand counts are defined by
//! misc/script.inc::scr_init; ADV overrides are in adv/adv_script.inc.
//! Native procedures and message references are resolved from companions on demand.
use super::*;
use crate::ir::{
    ArgName as A, BasicOperation as B, ControlFlowOperation as C, Qualifier as Q,
    StorageOperation as S,
};

pub(super) fn code(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new_at(data, 8)?;
    let code_size = r.read_u32_le()?;
    let count = r.read_u32_le()?;
    let text_size = r.read_u32_le()?;
    let messages = r.read_u32_le()?;
    let code = r.read_bytes(code_size as usize)?;
    let pool_start = r.position();
    let offsets_size = (count as usize)
        .checked_mul(4)
        .ok_or_else(|| bad(12, "Scenario table size overflow"))?;
    let offsets = r.read_bytes(offsets_size)?;
    let text_start = r.position();
    let pool = r.read_bytes(text_size as usize)?;
    let mut out = script(data, "scenario/escude", 1);
    record(
        &mut out,
        0,
        24,
        Q::ScriptMetadata,
        vec![
            arg(A::Signature, 0, 8, Value::Bytes(data[..8].to_vec())),
            number(A::ByteCount, 8, code_size),
            number(A::Count, 12, count),
            number(A::ByteCount, 16, text_size),
            number(A::Count, 20, messages),
        ],
    );
    let mut pc = BinaryReader::new(code);
    let mut line = None;
    let mut targets = Vec::new();
    while pc.remaining() != 0 {
        let start = 24 + pc.position();
        let op = pc.read_u8()?;
        let (operation, variant, name, params) =
            opcode(op).ok_or_else(|| bad(start, "Unknown Escu:de scenario instruction layout"))?;
        let mut args = Vec::new();
        for index in 0..params {
            let at = 24 + pc.position();
            let word = pc.read_u32_le()?;
            let (role, value) = match op {
                2 => (A::Count, Value::Unsigned(u64::from(word))),
                4 => (A::Value, Value::Integer(i64::from(word as i32))),
                5 => (A::Value, Value::Float32Bits(word)),
                7 => (A::ConstantIndex, Value::Unsigned(u64::from(word))),
                8 | 41 => (A::MessageIndex, Value::Unsigned(u64::from(word))),
                9 | 11 => (A::VariableId, Value::Unsigned(u64::from(word))),
                10 | 12 => (A::LocalIndex, Value::Integer(i64::from(word as i32))),
                13 => (A::Count, Value::Unsigned(u64::from(word))),
                15..=17 => (A::Target, Value::Unsigned(u64::from(word))),
                40 => (A::SpeakerId, Value::Integer(i64::from(word as i32))),
                43 if index == 0 => (A::MessageIndex, Value::Unsigned(u64::from(word))),
                43 => (A::Target, Value::Unsigned(u64::from(word))),
                44 => (A::Callee, Value::Unsigned(u64::from(word))),
                45 => (A::SourceLine, Value::Integer(i64::from(word as i32))),
                _ => (A::Unknown(index), Value::Unsigned(u64::from(word))),
            };
            args.push(arg(role, at, 4, value));
            if role == A::Target {
                let address = 24 + u64::from(word);
                targets.push((at, address));
                args.push(arg(A::ResolvedTarget, at, 0, Value::CodeAddress(address)));
            }
            if role == A::ConstantIndex {
                if word >= count {
                    return Err(bad(at, "Scenario string index exceeds table"));
                }
                let offset = BinaryReader::u32_le(&offsets[word as usize * 4..]) as usize;
                args.push(arg(A::Text, at, 0, text(cstring(pool, offset)?)));
            }
            if op == 45 {
                line = u32::try_from(word as i32).ok();
            }
        }
        out.instructions.push(Instruction {
            id: out.instructions.len() as u64,
            span: span(start, 24 + pc.position() - start),
            source_line: line,
            opcode: Opcode {
                operation,
                variant,
                namespace: "escude.scenario".into(),
                code: u32::from(op),
                native_mnemonic: Some(name.into()),
            },
            args,
            attributes: Vec::new(),
        });
    }
    let boundaries: std::collections::BTreeSet<_> = out
        .instructions
        .iter()
        .skip(1)
        .map(|i| i.span.offset)
        .collect();
    for (at, target) in targets {
        if !boundaries.contains(&target) {
            return Err(bad(at, "Scenario target is not an instruction boundary"));
        }
    }
    let strings = pool_args(offsets, pool, pool_start, text_start)?;
    record(
        &mut out,
        pool_start,
        offsets_size + pool.len(),
        Q::ConstantTable,
        vec![arg(
            A::StringPool,
            pool_start,
            offsets_size + pool.len(),
            Value::Group(strings),
        )],
    );
    if r.remaining() != 0 {
        let at = r.position();
        record(
            &mut out,
            at,
            r.remaining(),
            Q::Bytes,
            vec![arg(
                A::Data,
                at,
                r.remaining(),
                Value::Bytes(r.read_bytes(r.remaining())?.to_vec()),
            )],
        );
    }
    Ok(out)
}

pub(super) fn resolve(script: &mut Script, resources: Option<&dyn ResourceResolver>) -> Result<()> {
    let Some(resources) = resources else {
        return Ok(());
    };
    if script
        .instructions
        .iter()
        .any(|i| i.opcode.namespace == "escude.scenario" && i.opcode.code == 44)
    {
        super::procedure::resolve(script, resources)?;
    }
    if !script
        .instructions
        .iter()
        .any(|i| i.args.iter().any(|a| a.name == A::MessageIndex))
    {
        return Ok(());
    }
    let Some(name) = resources.resource_name() else {
        return Ok(());
    };
    let Some((stem, _)) = name.rsplit_once('.') else {
        return Ok(());
    };
    let companion = format!("{stem}.001").replace('\\', "/");
    let Some(bytes) = resources.read_resource(&companion)? else {
        return Ok(());
    };
    let bytes = envelope(&bytes)?;
    let values = if bytes.starts_with(b"@mess:__") {
        let table = messages(&bytes)?;
        let Some(Value::Group(items)) = table.instructions[0]
            .args
            .iter()
            .find(|a| a.name == A::Messages)
            .map(|a| &a.value)
        else {
            return Ok(());
        };
        items
            .iter()
            .filter_map(|a| match &a.value {
                Value::Group(fields) => fields
                    .iter()
                    .find(|a| a.name == A::Text)
                    .map(|a| a.value.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    } else {
        let decoded = Text.decode_text(&bytes)?.unwrap_or_default();
        decoded
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .split_inclusive('\n')
            .filter(|line| line.ends_with('\n'))
            .map(|line| Value::Text(line[..line.len() - 1].into()))
            .collect()
    };
    for instruction in &mut script.instructions {
        let Some(reference) = instruction.args.iter().find(|a| a.name == A::MessageIndex) else {
            continue;
        };
        let Value::Unsigned(index) = reference.value else {
            continue;
        };
        let Some(value) = values.get(index as usize) else {
            return Err(bad(
                reference.span.offset as usize,
                "Scenario message index exceeds companion table",
            ));
        };
        instruction.args.push(arg(
            A::Message,
            instruction.span.offset as usize,
            0,
            Value::Group(vec![
                arg(
                    A::Resource,
                    instruction.span.offset as usize,
                    0,
                    Value::Text(companion.clone()),
                ),
                arg(A::Text, instruction.span.offset as usize, 0, value.clone()),
            ]),
        ));
    }
    Ok(())
}

pub(super) fn messages(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new_at(data, 8)?;
    let count = r.read_u32_le()?;
    let size = r.read_u32_le()?;
    let table_size = (count as usize)
        .checked_mul(4)
        .ok_or_else(|| bad(8, "Message table size overflow"))?;
    let offsets = r.read_bytes(table_size)?;
    let base = r.position();
    let mut pool = r.read_bytes(size as usize)?.to_vec();
    nvlens_crypto::cipher::xor::apply_u32_key(&mut pool, &[0x55; 4]);
    let mut out = script(data, "messages/escude", 1);
    let mut args = vec![
        arg(A::Signature, 0, 8, Value::Bytes(data[..8].to_vec())),
        number(A::Count, 8, count),
        number(A::ByteCount, 12, size),
    ];
    args.push(arg(
        A::Messages,
        16,
        table_size + pool.len(),
        Value::Group(pool_args(offsets, &pool, 16, base)?),
    ));
    record(&mut out, 0, r.position(), Q::MessageTable, args);
    if r.remaining() != 0 {
        let at = r.position();
        record(
            &mut out,
            at,
            r.remaining(),
            Q::Bytes,
            vec![arg(
                A::Data,
                at,
                r.remaining(),
                Value::Bytes(r.read_bytes(r.remaining())?.to_vec()),
            )],
        );
    }
    Ok(out)
}

fn pool_args(offsets: &[u8], pool: &[u8], table: usize, base: usize) -> Result<Vec<Arg>> {
    let mut strings = Vec::new();
    for (index, word) in offsets.as_chunks::<4>().0.iter().enumerate() {
        let offset = BinaryReader::u32_le(word) as usize;
        let bytes = cstring(pool, offset)?;
        strings.push(arg(
            A::StringAt(index as u64),
            table + index * 4,
            4,
            Value::Group(vec![
                number(A::DataOffset, table + index * 4, offset as u32),
                arg(A::Text, base + offset, bytes.len(), text(bytes)),
                arg(
                    A::Terminator(0),
                    base + offset + bytes.len(),
                    1,
                    Value::Unsigned(0),
                ),
            ]),
        ));
    }
    Ok(strings)
}

fn opcode(code: u8) -> Option<(Operation, Option<Q>, &'static str, u64)> {
    use Operation::{Basic, ControlFlow as Flow, Data, Runtime, Storage, Text};
    let (op, q, name, n) = match code {
        1 => (Storage(S::Pop), None, "INST_POP", 0),
        2 => (Storage(S::Pop), Some(Q::Many), "INST_POP_N", 1),
        3 => (Storage(S::Pop), Some(Q::ReturnValue), "INST_POP_RET", 0),
        4 => (Storage(S::Push), Some(Q::Integer), "INST_PUSH_INT", 1),
        5 => (Storage(S::Push), Some(Q::Float32), "INST_PUSH_FLOAT", 1),
        6 => (Storage(S::Push), Some(Q::ReturnValue), "INST_PUSH_RET", 0),
        7 => (Storage(S::Push), Some(Q::Text), "INST_PUSH_TEXT", 1),
        8 => (Storage(S::Push), Some(Q::Message), "INST_PUSH_MESS", 1),
        9 => (Storage(S::Load), Some(Q::Variable), "INST_PUSH_GVAR", 1),
        10 => (Storage(S::Load), Some(Q::Local), "INST_PUSH_LVAR", 1),
        11 => (Storage(S::Store), Some(Q::Variable), "INST_STORE_GVAR", 1),
        12 => (Storage(S::Store), Some(Q::Local), "INST_STORE_LVAR", 1),
        13 => (Storage(S::EnterFrame), None, "INST_ENTER", 1),
        14 => (Storage(S::LeaveFrame), None, "INST_LEAVE", 0),
        15 => (Flow(C::Jump), None, "INST_JMP", 1),
        16 => (Flow(C::Branch), Some(Q::Zero), "INST_JMPZ", 1),
        17 => (Flow(C::Call), None, "INST_CALL", 1),
        18 => (Flow(C::Return), None, "INST_RET", 0),
        19 => (Flow(C::LogicalOr), None, "INST_LOG_OR", 0),
        20 => (Flow(C::LogicalAnd), None, "INST_LOG_AND", 0),
        21 => (Flow(C::LogicalNot), None, "INST_LOG_NOT", 0),
        22 => (Basic(B::BitOr), None, "INST_OR", 0),
        23 => (Basic(B::BitXor), None, "INST_XOR", 0),
        24 => (Basic(B::BitAnd), None, "INST_AND", 0),
        25 => (Basic(B::BitNot), None, "INST_NOT", 0),
        26 => (Flow(C::Equal), None, "INST_CMP_EQ", 0),
        27 => (Flow(C::NotEqual), None, "INST_CMP_NE", 0),
        28 => (Flow(C::Less), None, "INST_CMP_LT", 0),
        29 => (Flow(C::LessEqual), None, "INST_CMP_LE", 0),
        30 => (Flow(C::Greater), None, "INST_CMP_GT", 0),
        31 => (Flow(C::GreaterEqual), None, "INST_CMP_GE", 0),
        32 => (Basic(B::ShiftLeft), None, "INST_SHL", 0),
        33 => (Basic(B::ShiftRight), Some(Q::Arithmetic), "INST_SHR", 0),
        34 => (Basic(B::Add), None, "INST_ADD", 0),
        35 => (Basic(B::Subtract), None, "INST_SUB", 0),
        36 => (Basic(B::Multiply), None, "INST_MUL", 0),
        37 => (Basic(B::Divide), None, "INST_DIV", 0),
        38 => (Basic(B::Remainder), None, "INST_MOD", 0),
        39 => (Basic(B::Negate), None, "INST_NEG", 0),
        40 => (
            Text(TextOperation::Configure),
            Some(Q::Speaker),
            "INST_NAME",
            1,
        ),
        41 => (Text(TextOperation::Show), None, "INST_TEXT", 1),
        42 => (Text(TextOperation::Wait), None, "INST_PAGE", 0),
        43 => (Flow(C::AddChoice), None, "INST_OPTION", 2),
        44 => (Runtime(RuntimeOperation::EngineCall), None, "INST_PROC", 1),
        45 => (Data(DataOperation::SourceLocation), None, "INST_LINE", 1),
        _ => return None,
    };
    Some((op, q, name, n))
}

#[cfg(test)]
#[path = "../../tests/escude/scenario.rs"]
mod tests;
