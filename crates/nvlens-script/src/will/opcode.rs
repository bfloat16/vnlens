//! WS2 roles verified against the native VM dispatch and handlers
//! sub_140068580 (condition), sub_1400688A0 (call), and the choice reader.
//! A parameter schema proves layout only, never command semantics.
use crate::ir::ArgName;
use crate::ir::{Arg, Opcode, Operation, Value};
use crate::ir::{AudioOperation, ControlFlowOperation, RuntimeOperation};

pub(super) fn opcode(code: u8) -> Opcode {
    Opcode {
        operation: match code {
            1 => Operation::ControlFlow(ControlFlowOperation::Branch),
            2 | 6 => Operation::ControlFlow(ControlFlowOperation::Jump),
            4 => Operation::ControlFlow(ControlFlowOperation::Call),
            5 => Operation::ControlFlow(ControlFlowOperation::Return),
            255 => Operation::ControlFlow(ControlFlowOperation::Halt),
            // CSecondaryBuffer/StreamingVoiceContext creation and playback,
            // teardown/fade-out and volume update paths, respectively.
            40 => Operation::Audio(AudioOperation::Play),
            41 | 46 => Operation::Audio(AudioOperation::Stop),
            42 => Operation::Audio(AudioOperation::SetVolume),
            // Non-null handlers installed by sub_140067AE0 in opcode-indexed
            // slots at this+0x1BB0, plus the VM's explicit look-ahead counter.
            0
            | 7..=15
            | 17..=34
            | 40..=48
            | 50..=117
            | 140..=145
            | 150..=161
            | 165..=176
            | 180
            | 200..=203
            | 212..=214
            | 220..=224
            | 230
            | 233
            | 248..=254 => Operation::Runtime(RuntimeOperation::EngineCall),
            _ => Operation::Unknown,
        },
        variant: None,
        namespace: "advhd.ws2".into(),
        code: u32::from(code),
        native_mnemonic: None,
    }
}

pub(super) fn args(code: u8, args: &mut [Arg]) {
    let mut argument = 0;
    for operand in args.iter_mut() {
        if operand
            .attributes
            .iter()
            .any(|a| a.name == "parameter_type" && a.value == 8)
        {
            continue;
        }
        let i = argument;
        argument += 1;
        let name = match (code, i) {
            (1, 0) => ArgName::Flags,
            (1, 1) => ArgName::VariableId,
            (1, 2) => ArgName::Value,
            (1, 3) => ArgName::NextBranchTarget,
            (1, 4) => ArgName::EndTarget,
            (2 | 4 | 6, 0) => ArgName::Target,
            (15, 0) => ArgName::Count,
            (41 | 42, 0) => ArgName::Channel,
            (41 | 42, 1) => ArgName::Duration,
            (42, 2) => ArgName::Volume,
            _ => continue,
        };
        operand.name = name;
        if matches!((code, i), (1, 3 | 4) | (2 | 6, 0))
            && let Value::Unsigned(address) = operand.value
            // The first conditional offset uses zero to select the second.
            && !(code == 1 && i == 3 && address == 0)
        {
            operand.value = Value::CodeAddress(address);
        }
    }
}
