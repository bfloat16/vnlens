//! MOT action stream from misc/anime.c::anime_main. Instructions are reached
//! through execution edges, leaving embedded keyframe data out of disassembly.
//! get_var treats only 0x80000000..0x80000034 as encoded variable references.
use super::*;
use crate::ir::{ArgName as A, ControlFlowOperation as C, Qualifier as Q, StorageOperation as S};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn parse(out: &mut Script, code: &[u8], base: usize) -> Result<()> {
    let mut pending = vec![0usize];
    let mut decoded = BTreeMap::<usize, Instruction>::new();
    let mut keys = BTreeSet::new();
    while let Some(pc) = pending.pop() {
        if decoded.contains_key(&pc) {
            continue;
        }
        let mut r = BinaryReader::new_at(code, pc)?;
        let op = r.read_u8()?;
        let (name, roles) =
            layout(op).ok_or_else(|| bad(base + pc, "Unknown MOT action layout"))?;
        let mut args = Vec::new();
        if op == 6 {
            let at = base + r.position();
            args.push(arg(
                A::Easing,
                at,
                1,
                Value::Unsigned(u64::from(r.read_u8()?)),
            ));
        }
        for (index, &role) in roles.iter().enumerate() {
            let at = base + r.position();
            let raw = r.read_u32_le()?;
            let target = role == A::Target;
            let variable =
                role == A::Destination || !(target || matches!((op, index), (7, 1) | (27, 0)));
            let value = if variable && (0x8000_0000..0x8000_0035).contains(&raw) {
                Value::Expression(vec![Token {
                    opcode: Opcode {
                        operation: Operation::Storage(S::Reference),
                        variant: Some(Q::Variable),
                        namespace: "escude.motion.value".into(),
                        code: raw,
                        native_mnemonic: None,
                    },
                    span: span(at, 4),
                    args: vec![number(A::VariableId, at, raw)],
                    raw: code[r.position() - 4..r.position()].to_vec(),
                }])
            } else {
                Value::Integer(i64::from(raw as i32))
            };
            args.push(arg(role, at, 4, value));
            if target {
                let target = raw as usize;
                if target >= code.len() {
                    return Err(bad(at, "MOT target exceeds action stream"));
                }
                pending.push(target);
                args.push(arg(
                    A::ResolvedTarget,
                    at,
                    0,
                    Value::CodeAddress((base + target) as u64),
                ));
            } else if op == 7 && index == 1 {
                keys.insert(raw as usize);
                args.push(arg(
                    A::DataOffset,
                    at,
                    0,
                    Value::DataAddress(base as u64 + u64::from(raw)),
                ));
            }
        }
        if matches!(op, 28 | 35 | 38 | 39) {
            let at = base + r.position();
            let size = if op == 35 || out.format_version >= 2 {
                64
            } else {
                32
            };
            let bytes = r.read_bytes(size)?;
            args.push(arg(
                if op == 35 { A::Text } else { A::Resource },
                at,
                size,
                text(bytes.split(|&b| b == 0).next().unwrap_or_default()),
            ));
        }
        let operation = match op {
            0 => Operation::ControlFlow(C::Halt),
            1 | 9..=15 => Operation::ControlFlow(C::Branch),
            2 => Operation::ControlFlow(C::Jump),
            5 | 8 => Operation::Runtime(RuntimeOperation::Wait),
            16 => Operation::ControlFlow(C::Call),
            17 => Operation::ControlFlow(C::Return),
            18..=23 => Operation::Storage(S::Store),
            27 | 28 | 30 => Operation::Audio(AudioOperation::Play),
            29 | 31 => Operation::Audio(AudioOperation::Stop),
            33 | 34 => Operation::Image(ImageOperation::Draw),
            35 => Operation::Text(TextOperation::Show),
            _ => Operation::Runtime(RuntimeOperation::EngineCall),
        };
        let variant = match op {
            19 => Some(Q::AddAssign),
            20 => Some(Q::SubtractAssign),
            21 => Some(Q::MultiplyAssign),
            22 => Some(Q::DivideAssign),
            23 => Some(Q::RemainderAssign),
            _ => None,
        };
        if (10..=15).contains(&op) {
            args.push(arg(
                A::Condition,
                base + pc,
                0,
                Value::Unsigned(u64::from(op)),
            ));
        }
        let end = r.position();
        if !matches!(op, 0 | 2 | 17) {
            if end >= code.len() {
                return Err(bad(base + end, "MOT execution falls past action stream"));
            }
            pending.push(end);
        }
        decoded.insert(
            pc,
            Instruction {
                id: 0,
                span: span(base + pc, end - pc),
                source_line: None,
                opcode: Opcode {
                    operation,
                    variant,
                    namespace: "escude.motion".into(),
                    code: u32::from(op),
                    native_mnemonic: Some(name.into()),
                },
                args,
                attributes: Vec::new(),
            },
        );
    }
    for pc in keys {
        let mut r = BinaryReader::new_at(code, pc)?;
        loop {
            let start = r.position();
            if let Some(existing) = decoded.get(&start) {
                if existing.opcode.operation != Operation::Data(DataOperation::Record) {
                    return Err(bad(base + start, "MOT keyframe overlaps code"));
                }
                break;
            }
            let at = base + start;
            let mode = r.read_u8()?;
            let mut args = vec![arg(A::Mode, at, 1, Value::Unsigned(u64::from(mode)))];
            if mode < 10 {
                args.push(number(A::Duration, at + 1, r.read_u32_le()?));
                args.push(number(A::Value, at + 5, r.read_u32_le()?));
            }
            decoded.insert(
                start,
                Instruction {
                    id: 0,
                    span: span(at, r.position() - start),
                    source_line: None,
                    opcode: Opcode {
                        operation: Operation::Data(DataOperation::Record),
                        variant: Some(Q::Frame),
                        namespace: "escude.motion".into(),
                        code: u32::from(mode),
                        native_mnemonic: None,
                    },
                    args,
                    attributes: Vec::new(),
                },
            );
            if mode >= 10 {
                break;
            }
        }
    }
    let mut end = 0;
    for (pc, mut instruction) in decoded {
        if pc < end {
            return Err(bad(base + pc, "MOT instruction or data ranges overlap"));
        }
        if pc > end {
            record(
                out,
                base + end,
                pc - end,
                Q::Bytes,
                vec![arg(
                    A::Data,
                    base + end,
                    pc - end,
                    Value::Bytes(code[end..pc].to_vec()),
                )],
            );
        }
        end = pc + instruction.span.size as usize;
        instruction.id = out.instructions.len() as u64;
        out.instructions.push(instruction);
    }
    if end < code.len() {
        record(
            out,
            base + end,
            code.len() - end,
            Q::Bytes,
            vec![arg(
                A::Data,
                base + end,
                code.len() - end,
                Value::Bytes(code[end..].to_vec()),
            )],
        );
    }
    Ok(())
}

fn layout(op: u8) -> Option<(&'static str, &'static [A])> {
    Some(match op {
        0 => ("P_ENDM", &[]),
        1 => ("P_LOOP", &[A::Count, A::Target]),
        2 => ("P_JUMP", &[A::Target]),
        3 => ("P_NEW", &[A::OffsetX, A::OffsetY, A::Target]),
        4 => ("P_CHILD", &[A::OffsetX, A::OffsetY, A::Target]),
        5 => ("P_AWAIT", &[]),
        6 => (
            "P_LINE",
            &[A::Destination, A::InitialValue, A::Value, A::Duration],
        ),
        7 => ("P_KEY", &[A::Destination, A::DataOffset]),
        8 => ("P_WAIT", &[A::Duration]),
        9 => ("P_JWAIT", &[A::Duration, A::Target]),
        10 => ("P_JE", &[A::Left, A::Right, A::Target]),
        11 => ("P_JNE", &[A::Left, A::Right, A::Target]),
        12 => ("P_JG", &[A::Left, A::Right, A::Target]),
        13 => ("P_JGE", &[A::Left, A::Right, A::Target]),
        14 => ("P_JL", &[A::Left, A::Right, A::Target]),
        15 => ("P_JLE", &[A::Left, A::Right, A::Target]),
        16 => ("P_CALL", &[A::Target]),
        17 => ("P_RET", &[]),
        18 => ("P_SET", &[A::Destination, A::Value]),
        19 => ("P_ADD", &[A::Destination, A::Value]),
        20 => ("P_SUB", &[A::Destination, A::Value]),
        21 => ("P_MUL", &[A::Destination, A::Value]),
        22 => ("P_DIV", &[A::Destination, A::Value]),
        23 => ("P_MOD", &[A::Destination, A::Value]),
        24 => ("P_ATAN", &[A::Destination, A::OffsetX, A::OffsetY]),
        25 => ("P_HYPOT", &[A::Destination, A::OffsetX, A::OffsetY]),
        26 => ("P_ROTATE", &[A::Destination, A::Destination, A::Value]),
        27 => ("P_SE", &[A::ResourceId]),
        28 => ("P_SE_PLAY", &[A::Channel, A::Duration]),
        29 => ("P_SE_STOP", &[A::Channel, A::Duration]),
        30 => ("P_VO_PLAY", &[A::Channel, A::ResourceId]),
        31 => ("P_VO_STOP", &[A::Channel]),
        32 => ("P_FILL", &[A::ImageFrame, A::Color]),
        33 => (
            "P_COPY",
            &[A::ImageFrame, A::OffsetX, A::OffsetY, A::ImageFrame],
        ),
        34 => (
            "P_BLEND",
            &[A::ImageFrame, A::OffsetX, A::OffsetY, A::ImageFrame],
        ),
        35 => ("P_TEXT", &[A::ImageFrame, A::OffsetX, A::OffsetY]),
        36 => ("P_COPY_NEW", &[A::OffsetX, A::OffsetY, A::Target]),
        37 => ("P_COPY_CHILD", &[A::OffsetX, A::OffsetY, A::Target]),
        38 => ("P_LOAD_NEW", &[A::OffsetX, A::OffsetY]),
        39 => ("P_LOAD_CHILD", &[A::OffsetX, A::OffsetY]),
        40 => ("P_RANDOM", &[A::Destination, A::Left, A::Right]),
        41 => ("P_CLAMP", &[A::Destination, A::Left, A::Right]),
        42 => ("P_MIN", &[A::Destination, A::Value]),
        43 => ("P_MAX", &[A::Destination, A::Value]),
        44 => ("P_CALLBACK", &[]),
        _ => return None,
    })
}
