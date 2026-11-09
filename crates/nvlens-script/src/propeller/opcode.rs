//! Argument consumption verified against sub_40E6A0, sub_40F5E0,
//! sub_4104B0, sub_4119F0, sub_411D10, sub_4120D0 and sub_4125A0.
//! b = byte, w = signed word, v = tagged value, s = length-prefixed CP932.
use crate::ir::*;

pub(super) fn schema(group: u8, code: u8) -> Option<&'static [u8]> {
    Some(match (group, code) {
        (0, 0) => b"bwbv",
        (0, 1) => b"vbvbv",
        (0, 2 | 3 | 0x10 | 0x11 | 0x17 | 0x33 | 0x34) => b"v",
        (0, 4 | 6 | 9 | 0xb..=0xf | 0x12..=0x14 | 0x30..=0x32) => b"",
        (0, 5) => b"vb",
        (0, 7 | 0xa | 0x16) => b"b",
        (0, 8) => b"s",
        (0, 0x20) => b"vvbb",
        (1, 0) => b"s",
        (1, 1 | 4 | 0x15) => b"bs",
        (1, 2 | 0xf | 0x11 | 0x14 | 0x16) => b"v",
        (1, 3) => b"sss",
        (1, 5..=7 | 0xa) => b"vv",
        (1, 8 | 0x12) => b"vvvvvvv",
        (1, 9) => b"sssb",
        (1, 0xb) => b"vvs",
        (1, 0xc) => b"bv",
        (1, 0xd) => b"vss",
        (1, 0xe) => b"bvvvv",
        (1, 0x10) => b"bvvv",
        (1, 0x13) => b"vvvvv",
        (1, 0x17) => b"ss",
        (2, 0) => b"vs",
        (2, 1 | 5 | 0xa | 0x10 | 0x11) => b"vvv",
        (2, 2) => b"vb",
        (2, 3) => b"vvvvv",
        (2, 4 | 6 | 7 | 0xd..=0xf | 0x13) => b"vv",
        (2, 8 | 0xb | 0x15) => b"vvvv",
        (2, 9) => b"vvvvvv",
        (2, 0xc) => b"vvvvb",
        (2, 0x12) => b"vvvvvs",
        (2, 0x14) => b"vsvvvb",
        (2, 0x16) => b"vsvvvv",
        (3, 0) => b"vsvb",
        (3, 1) => b"vvb",
        (3, 2) => b"v",
        (3, 3) => b"sb",
        (4, 0) => b"vbv",
        (4, 1 | 2) => b"vb",
        (4, 3 | 4) => b"vv",
        (5, 0) => b"vs",
        (5, 1) => b"vvvvvvvv",
        (5, 2) => b"vvvvvvv",
        (5, 3 | 4) => b"vv",
        (6, 0) => b"sbv",
        (6, 1 | 6 | 8 | 9) => b"v",
        (6, 2) => b"s",
        (6, 3 | 7) => b"",
        (6, 4) => b"vs",
        (6, 5) => b"vb",
        _ => return None,
    })
}

pub(super) fn semantic(group: u8, code: u8, args: &[Arg]) -> (Operation, Option<Qualifier>) {
    let mut variant = None;
    let operation = match (group, code) {
        (0, 0) => {
            variant = match args.get(2).map(|a| &a.value) {
                Some(Value::Unsigned(0)) => Some(Qualifier::Assign),
                Some(Value::Unsigned(1)) => Some(Qualifier::AddAssign),
                Some(Value::Unsigned(2)) => Some(Qualifier::SubtractAssign),
                _ => Some(Qualifier::UnknownUpdate),
            };
            Operation::Storage(StorageOperation::Store)
        }
        (0, 1) => Operation::ControlFlow(ControlFlowOperation::Branch),
        (0, 2) => Operation::ControlFlow(ControlFlowOperation::Jump),
        (0, 3) => Operation::ControlFlow(ControlFlowOperation::Call),
        (0, 4) => Operation::ControlFlow(ControlFlowOperation::Return),
        (0, 5 | 0x17) => Operation::Runtime(RuntimeOperation::Wait),
        (0, 6) => Operation::ControlFlow(ControlFlowOperation::Halt),
        (0, 8) => {
            variant = Some(Qualifier::ScriptFile);
            Operation::ControlFlow(ControlFlowOperation::Jump)
        }
        (0, 0x13 | 0x32) => Operation::Runtime(RuntimeOperation::Save),
        (0, 0x31) => Operation::Runtime(RuntimeOperation::NoOp),
        (0, 0x33) => {
            variant = Some(Qualifier::Conditional);
            Operation::ControlFlow(ControlFlowOperation::Branch)
        }
        (1, 0) => Operation::Text(TextOperation::Configure),
        (2, 0) => Operation::Image(ImageOperation::Load),
        (2, 1..=0x11 | 0x13..=0x16) => Operation::Image(ImageOperation::Configure),
        (2, 0x12) => Operation::Text(TextOperation::Show),
        (3, 0 | 1) => Operation::Effect(EffectOperation::Transition),
        (3, 3) => Operation::Video(VideoOperation::Play),
        (5, 0) => Operation::Text(TextOperation::Show),
        (5, 1..=3) => Operation::Text(TextOperation::Configure),
        (6, 0) => {
            variant = Some(Qualifier::Music);
            Operation::Audio(AudioOperation::Play)
        }
        (6, 1) => {
            variant = Some(Qualifier::Music);
            Operation::Audio(AudioOperation::Stop)
        }
        (6, 2 | 3) => {
            variant = Some(Qualifier::Voice);
            Operation::Audio(AudioOperation::Configure)
        }
        (6, 4) => Operation::Audio(AudioOperation::Configure),
        (6, 5 | 7 | 8) => {
            if code != 5 {
                variant = Some(Qualifier::Voice);
            }
            Operation::Audio(AudioOperation::Play)
        }
        (6, 6) => Operation::Audio(AudioOperation::Stop),
        (6, 9) => Operation::Audio(AudioOperation::Wait),
        // The remaining verified handlers configure host UI, gallery, saves,
        // archive mounts and event bindings. Their field meanings stay unknown.
        _ => Operation::Runtime(RuntimeOperation::EngineCall),
    };
    (operation, variant)
}

pub(super) fn name(group: u8, code: u8, index: usize) -> ArgName {
    use ArgName::*;
    let names: &[ArgName] = match (group, code) {
        (0, 0) => &[Scope, VariableId, Operator, Value],
        (0, 1) => &[Left, Operator, Right, Mode, LabelId],
        (0, 2 | 3 | 0x33) => &[LabelId],
        (0, 5) => &[Duration, Mode],
        (0, 8) => &[Resource],
        (0, 0x17) => &[Layer],
        (0, 0x20) => &[Index, ProcedureId, Mode, Flags],
        (1, 0) => &[Title],
        (1, 1) => &[Mode, Resource],
        (1, 3) => &[Unknown(0), Unknown(1), Unknown(2)],
        (1, 0xc) => &[Mode, LabelId],
        (1, 0x15) => &[Mode, Path],
        (1, 0x17) => &[Path, Resource],
        (2, 0) => &[Layer, Resource],
        (2, 1) => &[Layer, OffsetX, OffsetY],
        (2, 2) => &[Layer, Enabled],
        (2, 3) => &[Layer, RectLeft, RectTop, RectRight, RectBottom],
        (2, 4) => &[Layer, Rotation],
        (2, 5) => &[Layer, ScaleX, ScaleY],
        (2, 8) => &[Layer, OffsetX, OffsetY, Duration],
        (2, 9) => &[Layer, RectLeft, RectTop, RectRight, RectBottom, Duration],
        (2, 0xa) => &[Layer, Rotation, Duration],
        (2, 0xb) => &[Layer, ScaleX, ScaleY, Duration],
        (2, 0xc) => &[Layer, ValueAt(1), ImageFrame, Duration, Mode],
        (2, 0xd) => &[Layer, ImageFrame],
        (2, 0xe) => &[Layer, Opacity],
        (2, 0x10) => &[Layer, Opacity, Duration],
        (2, 0x12) => &[Layer, OffsetX, OffsetY, Unknown(3), Color, Text],
        (3, 0) => &[EffectId, Resource, Duration, Flags],
        (3, 1) => &[EffectId, Duration, Flags],
        (3, 3) => &[Resource, Mode],
        (4, 0) => &[Layer, Mode, LabelId],
        (5, 0) => &[MessageIndex, Text],
        (5, 4) => &[LabelId, LabelId],
        (6, 0) => &[Resource, Mode, Duration],
        (6, 1) => &[Duration],
        (6, 2) => &[Resource],
        (6, 4) => &[Channel, Resource],
        (6, 5) => &[Channel, Mode],
        (6, 6 | 9) => &[Channel],
        _ => &[],
    };
    names.get(index).copied().unwrap_or(Unknown(index as u64))
}
