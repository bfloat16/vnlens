//! Semantic mapping for YSTB commands across revisions. Companion names remain
//! exact in IR; unverified commands use the shared engine_call operation.

use crate::ir::{ArgName, BasicOperation, Opcode, Operation, Qualifier};
use crate::ir::{ControlFlowOperation, RuntimeOperation, StorageOperation, TextOperation};

/// Map shared commands to the 0x1EE numbering used by the semantic tables.
/// Companion names take precedence: 0x1DF/0x1E0 omit commands inserted in
/// later releases, so their numeric IDs cannot use the 0x1EE mapping.
/// The 0x22B YSCM table replaces CDDA with ALIAS, removes EMOTEINFO, and adds
/// MOVIE2/MOVIE2END/MOVIE2INFO before PLUG. Dispatch is verified at 0x463550.
/// New and unknown commands retain their native opcode and companion name.
pub(super) fn semantic_code(version: u32, code: u32, native: Option<&str>) -> Option<u32> {
    if let Some(native) = native {
        return Some(match native {
            "ELSE" => 11,
            "F_FLT" => 17,
            "F_INT" => 18,
            "F_STR" => 19,
            "FLT" => 26,
            "GO" => 43,
            "GOSUB" => 44,
            "IF" => 45,
            "IFBLEND" => 46,
            "INT" => 51,
            "LABEL" => 52,
            "LABELINFO" => 53,
            "LET" => 54,
            "LOOP" => 56,
            "RETURN" => 77,
            "RETURNCODE" => 79,
            "S_FLT" => 80,
            "S_INT" => 81,
            "S_STR" => 82,
            "STR" => 90,
            "WORD" => 106,
            "_" => 110,
            _ => return None,
        });
    }
    match (version, code) {
        (0x1ee, _) | (0x22b, 1..=12) => Some(code),
        (0x22b, 13..=72) => Some(code + 1),
        (0x22b, 76..=120) => Some(code - 2),
        _ => None,
    }
}

fn command(code: Option<u32>, native: Option<&str>) -> Operation {
    let known = match code {
        Some(43) => Some(("GO", Operation::ControlFlow(ControlFlowOperation::Jump))),
        Some(44) => Some(("GOSUB", Operation::ControlFlow(ControlFlowOperation::Call))),
        Some(45) => Some(("IF", Operation::ControlFlow(ControlFlowOperation::Branch))),
        Some(54) => Some(("LET", Operation::Storage(StorageOperation::Store))),
        Some(77) => Some((
            "RETURN",
            Operation::ControlFlow(ControlFlowOperation::Return),
        )),
        Some(106) => Some(("WORD", Operation::Text(TextOperation::Show))),
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
pub(super) fn argument(code: Option<u32>, id: u8, position: u8, control: bool) -> ArgName {
    let Some(code) = code else {
        return ArgName::Unknown(u64::from(id));
    };
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

pub(super) fn opcode(code: u32, semantic: Option<u32>, name: Option<String>) -> Opcode {
    Opcode {
        namespace: "yuris.command".into(),
        code,
        operation: command(semantic, name.as_deref()),
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
