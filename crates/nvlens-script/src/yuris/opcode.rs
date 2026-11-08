//! Semantic mapping for the verified YSTB 0x1EE command set. Companion names remain
//! exact in IR; unverified commands use the shared engine_call operation.

use crate::ir::{ArgName, BasicOperation, Opcode, Operation, Qualifier};
use crate::ir::{ControlFlowOperation, RuntimeOperation, StorageOperation, TextOperation};

pub(super) fn command(code: u32, native: Option<&str>) -> Operation {
    let known = match code {
        43 => Some(("GO", Operation::ControlFlow(ControlFlowOperation::Jump))),
        44 => Some(("GOSUB", Operation::ControlFlow(ControlFlowOperation::Call))),
        45 => Some(("IF", Operation::ControlFlow(ControlFlowOperation::Branch))),
        54 => Some(("LET", Operation::Storage(StorageOperation::Store))),
        77 => Some((
            "RETURN",
            Operation::ControlFlow(ControlFlowOperation::Return),
        )),
        106 => Some(("WORD", Operation::Text(TextOperation::Show))),
        _ => None,
    };
    if let Some((expected, name)) = known
        && native.is_none_or(|native| native == expected)
    {
        return name;
    }
    if native.is_some() {
        Operation::Runtime(RuntimeOperation::EngineCall)
    } else {
        Operation::Unknown
    }
}

// Complete positional mapping: every unmatched slot has an explicit Unknown
// identity. Companion strings are preserved by the caller as native_name only.
pub(super) fn argument(code: u32, id: u8, position: u8, control: bool) -> ArgName {
    if control {
        return match (code, position) {
            (79, _) => ArgName::ReturnCode,
            (11 | 45, 1) => ArgName::NextBranchTarget,
            (45, 2) | (56, 1) => ArgName::EndTarget,
            _ => ArgName::Unknown(u64::from(id)),
        };
    }
    match (code, position) {
        (11 | 45, 0) => ArgName::Condition,
        (54, 0) => ArgName::Destination,
        (54, 1) | (110, 0) => ArgName::Value,
        (17..=19 | 26 | 51 | 80..=82 | 90, 0) => ArgName::Variable,
        (17..=19 | 26 | 51 | 80..=82 | 90, 1) => ArgName::InitialValue,
        (43 | 44, 0) => ArgName::Target,
        (52 | 53, 0) => ArgName::Label,
        (106, 0) => ArgName::Text,
        _ => ArgName::Unknown(u64::from(id)),
    }
}

pub(super) fn opcode(code: u32, name: Option<String>) -> Opcode {
    Opcode {
        namespace: "yuris.command".into(),
        code,
        operation: command(code, name.as_deref()),
        variant: None,
        native_mnemonic: name,
    }
}

pub(super) fn expression(code: u8) -> Option<(Operation, Option<Qualifier>)> {
    Some(match code {
        b'+' => (Operation::Basic(BasicOperation::Add), None),
        b'-' => (Operation::Basic(BasicOperation::Subtract), None),
        b'*' => (Operation::Basic(BasicOperation::Multiply), None),
        b'/' => (Operation::Basic(BasicOperation::Divide), None),
        b'%' => (Operation::Basic(BasicOperation::Remainder), None),
        b'R' => (Operation::Basic(BasicOperation::Negate), None),
        b'=' => (Operation::ControlFlow(ControlFlowOperation::Equal), None),
        b'!' => (Operation::ControlFlow(ControlFlowOperation::NotEqual), None),
        b'<' => (Operation::ControlFlow(ControlFlowOperation::Less), None),
        b'>' => (Operation::ControlFlow(ControlFlowOperation::Greater), None),
        b'S' => (
            Operation::ControlFlow(ControlFlowOperation::LessEqual),
            None,
        ),
        b'Z' => (
            Operation::ControlFlow(ControlFlowOperation::GreaterEqual),
            None,
        ),
        b'&' => (
            Operation::ControlFlow(ControlFlowOperation::LogicalAnd),
            None,
        ),
        b'|' => (
            Operation::ControlFlow(ControlFlowOperation::LogicalOr),
            None,
        ),
        b'A' => (Operation::Basic(BasicOperation::BitAnd), None),
        b'O' => (Operation::Basic(BasicOperation::BitOr), None),
        b'^' => (Operation::Basic(BasicOperation::BitXor), None),
        b',' => (Operation::Storage(StorageOperation::IndexSeparator), None),
        b's' => (
            Operation::Basic(BasicOperation::Convert),
            Some(Qualifier::Text),
        ),
        b'i' => (
            Operation::Basic(BasicOperation::Convert),
            Some(Qualifier::Number),
        ),
        _ => return None,
    })
}
