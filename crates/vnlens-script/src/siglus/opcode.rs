//! Siglus unary/binary operation selectors from sub_674B40.
use crate::ir::*;

fn arithmetic(unary: bool, code: u8) -> (Operation, Option<Qualifier>) {
    if unary {
        return match code {
            1 => (
                Operation::Basic(BasicOperation::Convert),
                Some(Qualifier::Identity),
            ),
            2 => (Operation::Basic(BasicOperation::Negate), None),
            0x30 => (Operation::Basic(BasicOperation::BitNot), None),
            _ => (Operation::Unknown, None),
        };
    }
    (
        match code {
            1 => Operation::Basic(BasicOperation::Add),
            2 => Operation::Basic(BasicOperation::Subtract),
            3 => Operation::Basic(BasicOperation::Multiply),
            4 => Operation::Basic(BasicOperation::Divide),
            5 => Operation::Basic(BasicOperation::Remainder),
            0x10 => Operation::ControlFlow(ControlFlowOperation::Equal),
            0x11 => Operation::ControlFlow(ControlFlowOperation::NotEqual),
            0x12 => Operation::ControlFlow(ControlFlowOperation::Greater),
            0x13 => Operation::ControlFlow(ControlFlowOperation::GreaterEqual),
            0x14 => Operation::ControlFlow(ControlFlowOperation::Less),
            0x15 => Operation::ControlFlow(ControlFlowOperation::LessEqual),
            0x20 => Operation::ControlFlow(ControlFlowOperation::LogicalAnd),
            0x21 => Operation::ControlFlow(ControlFlowOperation::LogicalOr),
            0x31 => Operation::Basic(BasicOperation::BitAnd),
            0x32 => Operation::Basic(BasicOperation::BitOr),
            0x33 => Operation::Basic(BasicOperation::BitXor),
            0x34 => Operation::Basic(BasicOperation::ShiftLeft),
            0x35 | 0x36 => Operation::Basic(BasicOperation::ShiftRight),
            _ => Operation::Unknown,
        },
        match code {
            0x35 => Some(Qualifier::Arithmetic),
            0x36 => Some(Qualifier::Logical),
            _ => None,
        },
    )
}

/// Select the native command's shared operation; selector is the decoded
/// value type for PUSH or the arithmetic selector for unary/binary commands.
pub(super) fn opcode(code: u8, selector: u32) -> Opcode {
    let (operation, variant) = match code {
        0 | 0x16 => (
            Operation::ControlFlow(ControlFlowOperation::Halt),
            Some(Qualifier::Error),
        ),
        1 => (Operation::Data(DataOperation::SourceLocation), None),
        2 => match selector {
            10 => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Integer),
            ),
            20 => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Text),
            ),
            _ => (Operation::Unknown, None),
        },
        3 => (Operation::Storage(StorageOperation::Pop), None),
        4 => (Operation::Storage(StorageOperation::Duplicate), None),
        5 => (
            Operation::Storage(StorageOperation::Load),
            Some(Qualifier::Property),
        ),
        6 => (
            Operation::Storage(StorageOperation::Duplicate),
            Some(Qualifier::Reference),
        ),
        7 => (
            Operation::Storage(StorageOperation::Declare),
            Some(Qualifier::Local),
        ),
        8 => (
            Operation::Storage(StorageOperation::IndexBegin),
            Some(Qualifier::Reference),
        ),
        9 => (Operation::Storage(StorageOperation::GetArguments), None),
        0x10 => (Operation::ControlFlow(ControlFlowOperation::Jump), None),
        0x11 => (
            Operation::ControlFlow(ControlFlowOperation::Branch),
            Some(Qualifier::Nonzero),
        ),
        0x12 => (
            Operation::ControlFlow(ControlFlowOperation::Branch),
            Some(Qualifier::Zero),
        ),
        0x13 => (
            Operation::ControlFlow(ControlFlowOperation::Call),
            Some(Qualifier::Integer),
        ),
        0x14 => (
            Operation::ControlFlow(ControlFlowOperation::Call),
            Some(Qualifier::Text),
        ),
        0x15 => (Operation::ControlFlow(ControlFlowOperation::Return), None),
        0x20 => (
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Property),
        ),
        0x21 | 0x22 => arithmetic(code == 0x21, selector as u8),
        0x30 => (Operation::Runtime(RuntimeOperation::EngineCall), None),
        0x31 => (Operation::Text(TextOperation::Show), None),
        0x32 => (
            Operation::Text(TextOperation::Show),
            Some(Qualifier::Speaker),
        ),
        _ => (Operation::Unknown, None),
    };
    Opcode {
        operation,
        variant,
        namespace: "siglus.scene".into(),
        code: u32::from(code),
        native_mnemonic: None,
    }
}
