//! BGI compact and compiled opcode/argument mappings, separate from readers.
use crate::ir::*;

// The native dispatch table at 0x1401CFB80 and scrctrl._bp's installed
// handlers use the same arithmetic numbering. SHR and SAR are distinct.
fn arithmetic(code: u32) -> Option<(Operation, Option<Qualifier>)> {
    Some(match code {
        0x20 => (Operation::Basic(BasicOperation::Add), None),
        0x21 => (Operation::Basic(BasicOperation::Subtract), None),
        0x22 => (Operation::Basic(BasicOperation::Multiply), None),
        0x23 => (Operation::Basic(BasicOperation::Divide), None),
        0x24 => (Operation::Basic(BasicOperation::Remainder), None),
        0x25 => (Operation::Basic(BasicOperation::BitAnd), None),
        0x26 => (Operation::Basic(BasicOperation::BitOr), None),
        0x27 => (Operation::Basic(BasicOperation::BitXor), None),
        0x28 => (Operation::Basic(BasicOperation::BitNot), None),
        0x29 => (Operation::Basic(BasicOperation::ShiftLeft), None),
        0x30 => (Operation::ControlFlow(ControlFlowOperation::Equal), None),
        0x31 => (Operation::ControlFlow(ControlFlowOperation::NotEqual), None),
        0x32 => (
            Operation::ControlFlow(ControlFlowOperation::LessEqual),
            None,
        ),
        0x33 => (
            Operation::ControlFlow(ControlFlowOperation::GreaterEqual),
            None,
        ),
        0x34 => (Operation::ControlFlow(ControlFlowOperation::Less), None),
        0x35 => (Operation::ControlFlow(ControlFlowOperation::Greater), None),
        0x38 => (
            Operation::ControlFlow(ControlFlowOperation::LogicalAnd),
            None,
        ),
        0x39 => (
            Operation::ControlFlow(ControlFlowOperation::LogicalOr),
            None,
        ),
        0x3a => (
            Operation::ControlFlow(ControlFlowOperation::LogicalNot),
            None,
        ),
        0x2a => (
            Operation::Basic(BasicOperation::ShiftRight),
            Some(Qualifier::Logical),
        ),
        0x2b => (
            Operation::Basic(BasicOperation::ShiftRight),
            Some(Qualifier::Arithmetic),
        ),
        _ => return None,
    })
}

pub(super) fn compact(code: u8) -> (Operation, Option<Qualifier>) {
    match code {
        0x00..=0x02 => (
            Operation::Storage(StorageOperation::Push),
            Some(Qualifier::Integer),
        ),
        0x03 => (
            Operation::Storage(StorageOperation::Push),
            Some(Qualifier::Integers),
        ),
        0x04 => (
            Operation::Storage(StorageOperation::Push),
            Some(Qualifier::LocalAddress),
        ),
        0x05 => (
            Operation::Storage(StorageOperation::Push),
            Some(Qualifier::DataAddress),
        ),
        0x06 => (
            Operation::Storage(StorageOperation::Push),
            Some(Qualifier::CodeAddress),
        ),
        0x08 => (Operation::Storage(StorageOperation::Load), None),
        0x09 => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::AddressValue),
        ),
        0x0a => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::ValueAddress),
        ),
        0x0b => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Bytes),
        ),
        0x0c => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Many),
        ),
        0x0d => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Immediate),
        ),
        0x0e => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::LocalImmediate),
        ),
        0x0f => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Local),
        ),
        0x10 => (Operation::Storage(StorageOperation::GetStackPointer), None),
        0x11 => (Operation::Storage(StorageOperation::SetStackPointer), None),
        0x12 => (
            Operation::Storage(StorageOperation::AdjustStackPointer),
            None,
        ),
        0x13 | 0x14 => (Operation::ControlFlow(ControlFlowOperation::Jump), None),
        0x15 => (Operation::ControlFlow(ControlFlowOperation::Branch), None),
        0x16 | 0xee => (Operation::ControlFlow(ControlFlowOperation::Call), None),
        0x17 => (Operation::ControlFlow(ControlFlowOperation::Return), None),
        _ => arithmetic(u32::from(code)).unwrap_or((Operation::Unknown, None)),
    }
}

pub(super) fn compact_arg(code: u8, index: usize) -> Option<ArgName> {
    Some(match (code, index) {
        (0x00..=0x02 | 0x0d, 0) | (0x0e, 1) => ArgName::Value,
        (0x03, 0) => ArgName::Mode,
        (0x04 | 0x0e, 0) => ArgName::LocalOffset,
        (0x08..=0x0a | 0x0c, 0) => ArgName::WidthTag,
        (0x0b, 0) => ArgName::ByteCount,
        (0x0c, 1) => ArgName::Count,
        (0x0f, 0) => ArgName::LocalDescriptor,
        (0x12, 0) => ArgName::Delta,
        (0x15, 0) => ArgName::Flags,
        _ => return None,
    })
}

pub(super) fn compiled(code: u32) -> ((Operation, Option<Qualifier>), usize) {
    match code {
        0 => (
            (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Integer),
            ),
            1,
        ),
        1 => (
            (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::CodeAddress),
            ),
            1,
        ),
        2 => (
            (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::LocalAddress),
            ),
            1,
        ),
        3 => (
            (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Text),
            ),
            1,
        ),
        8 => ((Operation::Storage(StorageOperation::Load), None), 1),
        9 => (
            (
                Operation::Storage(StorageOperation::Store),
                Some(Qualifier::Checked),
            ),
            1,
        ),
        10 => (
            (
                Operation::Storage(StorageOperation::Store),
                Some(Qualifier::Unchecked),
            ),
            1,
        ),
        0x10 => (
            (Operation::Storage(StorageOperation::GetStackPointer), None),
            0,
        ),
        0x11 => (
            (Operation::Storage(StorageOperation::SetStackPointer), None),
            0,
        ),
        0x15 | 0x16 | 0x18 => (
            (Operation::ControlFlow(ControlFlowOperation::Jump), None),
            0,
        ),
        0x17 | 0x19 => (
            (Operation::ControlFlow(ControlFlowOperation::Branch), None),
            1,
        ),
        0x1a => (
            (Operation::ControlFlow(ControlFlowOperation::Call), None),
            0,
        ),
        0x1b => (
            (Operation::ControlFlow(ControlFlowOperation::Return), None),
            0,
        ),
        0x1e => (
            (
                Operation::ControlFlow(ControlFlowOperation::RegisterException),
                None,
            ),
            0,
        ),
        0x1f => (
            (
                Operation::ControlFlow(ControlFlowOperation::UnregisterException),
                None,
            ),
            0,
        ),
        0x3f => (
            (Operation::Storage(StorageOperation::GetArguments), None),
            1,
        ),
        0x7f => ((Operation::Data(DataOperation::SourceLocation), None), 2),
        0x7b => ((Operation::Unknown, None), 3),
        0x7e => ((Operation::Unknown, None), 1),
        0xf4 => (
            (Operation::ControlFlow(ControlFlowOperation::Halt), None),
            0,
        ),
        _ => (arithmetic(code).unwrap_or((Operation::Unknown, None)), 0),
    }
}
pub(super) fn compiled_arg(code: u32, index: usize) -> ArgName {
    match (code, index) {
        (0, 0) => ArgName::Value,
        (2, 0) => ArgName::LocalOffset,
        (8..=10, 0) => ArgName::Mode,
        (0x17 | 0x19, 0) => ArgName::Condition,
        (0x3f, 0) => ArgName::Count,
        (0x7f, 1) => ArgName::SourceLine,
        _ => ArgName::Unknown(index as u64),
    }
}
