//! ReadValue: zero-terminated expression, operator/precedence pairs, and
//! tagged signed 5/13/21/32-bit immediates with a trailing precedence byte.
//! The 13/21-bit forms combine the tag's low five bits with a LE payload.
//! MemoOff9 sub_14005D4E0 reduces the highest precedence first; sub_14005E030
//! implements the operators. In particular 0x0B is bitwise NOT, not logical NOT.
//! These are ordered infix/prefix tokens, not a postfix evaluation stack.
use super::{arg, op, span};
use crate::ir::*;
use vnlens_core::Result;
use vnlens_io::BinaryReader;

pub(super) fn read(reader: &mut BinaryReader<'_>, data: &[u8], base: usize) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    loop {
        let start = reader.position();
        let code = reader.read_u8()?;
        let mut args = Vec::new();
        let operation = if code == 0 {
            Operation::Data(DataOperation::Record)
        } else if code & 0x80 != 0 {
            let bits = match code & 0x60 {
                0 => 5,
                0x20 => 13,
                0x40 => 21,
                _ => 32,
            };
            let value = if bits == 32 {
                i64::from(reader.read_u32_le()? as i32)
            } else {
                reader.read_signed_le_with_high_bits(code & 0x1f, 5, (bits - 5) / 8)?
            };
            args.push(arg(
                ArgName::Value,
                base + start,
                base + reader.position(),
                Value::Integer(value),
            ));
            Operation::Storage(StorageOperation::Push)
        } else {
            semantic(code)
        };
        if code != 0 {
            let at = reader.position();
            let precedence = reader.read_u8()?;
            args.push(arg(
                ArgName::Precedence,
                base + at,
                base + reader.position(),
                Value::Unsigned(u64::from(precedence)),
            ));
        }
        let end = reader.position();
        let mut opcode = op("mages/expression", u32::from(code), operation);
        opcode.variant = qualifier(code);
        tokens.push(Token {
            opcode,
            span: span(base + start, base + end),
            args,
            raw: data[start..end].to_vec(),
        });
        if code == 0 {
            // The assignment path leaves the leading variable selector as an
            // lvalue. Do not report it as an independent read of that variable.
            if tokens
                .iter()
                .any(|t| matches!(t.opcode.code, 0x14..=0x1e | 0x20 | 0x21))
                && let Some(first) = tokens.first_mut()
                && matches!(first.opcode.code, 0x28..=0x2a | 0x2d | 0x2e)
            {
                first.opcode.operation = Operation::Storage(StorageOperation::Reference);
            }
            return Ok(tokens);
        }
    }
}

fn semantic(code: u8) -> Operation {
    use {BasicOperation as B, ControlFlowOperation as C, Operation as O, StorageOperation as S};
    match code {
        1 => O::Basic(B::Multiply),
        2 => O::Basic(B::Divide),
        3 => O::Basic(B::Add),
        4 => O::Basic(B::Subtract),
        5 => O::Basic(B::Remainder),
        6 => O::Basic(B::ShiftLeft),
        7 => O::Basic(B::ShiftRight),
        8 => O::Basic(B::BitAnd),
        9 => O::Basic(B::BitXor),
        10 => O::Basic(B::BitOr),
        11 => O::Basic(B::BitNot),
        12 => O::ControlFlow(C::Equal),
        13 => O::ControlFlow(C::NotEqual),
        14 => O::ControlFlow(C::LessEqual),
        15 => O::ControlFlow(C::GreaterEqual),
        16 => O::ControlFlow(C::Less),
        17 => O::ControlFlow(C::Greater),
        0x14..=0x1e | 0x20..=0x21 => O::Storage(S::Store),
        0x28..=0x30 => O::Storage(S::Load),
        0x33 => O::Basic(B::Random),
        _ => O::Unknown,
    }
}

fn qualifier(code: u8) -> Option<Qualifier> {
    use Qualifier as Q;
    Some(match code {
        0 => Q::BlockEnd,
        7 => Q::Arithmetic,
        0x14 => Q::Assign,
        0x15 => Q::MultiplyAssign,
        0x16 => Q::DivideAssign,
        0x17 => Q::AddAssign,
        0x18 => Q::SubtractAssign,
        0x19 => Q::RemainderAssign,
        0x1a => Q::ShiftLeftAssign,
        0x1b => Q::ShiftRightAssign,
        0x1c => Q::BitAndAssign,
        0x1d => Q::BitOrAssign,
        0x1e => Q::BitXorAssign,
        0x20 => Q::Increment,
        0x21 => Q::Decrement,
        0x28 => Q::Variable,
        0x29 => Q::Flag,
        0x2a => Q::DataAddress,
        0x2b | 0x2c => Q::Label,
        0x2d => Q::Local,
        0x80..=0xff => Q::Integer,
        _ => return None,
    })
}
