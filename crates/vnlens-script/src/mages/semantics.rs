//! Semantic definitions for the checked libMgs SC3 dispatch tables.
//! References are handler addresses in MemoOff9_Steam unless stated otherwise:
//! table00 = funcs_14008E635, table01 = funcs_14008E655,
//! table10 = funcs_14008E675.
//! Names here describe verified behavior; they are not engine-native symbols.
use crate::ir::*;
use vnlens_core::Result;

pub(super) fn annotate(i: &mut Instruction, layout: super::Layout) -> Result<()> {
    let super::Layout {
        glyph_width,
        dialogue_extension,
        extended_context,
        ..
    } = layout;
    use {
        ArgName as A, AudioOperation as U, BasicOperation as B, ControlFlowOperation as C,
        ImageOperation as I, Operation as O, Qualifier as Q, RuntimeOperation as R,
        StorageOperation as S, TextOperation as T, VideoOperation as V,
    };
    let mode = i.args.first().and_then(|a| match a.value {
        Value::Unsigned(value) => u8::try_from(value).ok(),
        _ => None,
    });
    let (operation, variant, names): (_, _, &[ArgName]) = match i.opcode.code {
        // Context scheduling and control flow, sub_140090020..sub_1400928D0.
        0x0000 | 0x0006 => (O::ControlFlow(C::Halt), None, &[]),
        0x0001 => (
            O::Runtime(R::EngineCall),
            None,
            &[A::Mode, A::ContextId, A::ScriptId, A::LabelId, A::Name],
        ),
        0x0002 => (O::Runtime(R::EngineCall), Some(Q::Delete), &[A::ContextId]),
        0x0003 | 0x001c => (O::Runtime(R::Yield), None, &[]),
        0x0004 => (
            O::Runtime(R::EngineCall),
            Some(Q::ScriptFile),
            &[A::Mode, A::ContextId, A::ResourceId],
        ),
        0x0005 => (O::Runtime(R::Wait), Some(Q::Frame), &[A::Duration]),
        0x0007 => (O::ControlFlow(C::Jump), None, &[A::LabelId]),
        0x0008 => (O::ControlFlow(C::Jump), None, &[A::Index, A::LabelBase]),
        0x000a => (
            O::ControlFlow(C::Branch),
            mode.map(|m| if m == 0 { Q::Zero } else { Q::Nonzero }),
            &[A::Mode, A::Condition, A::LabelId],
        ),
        0x000b => (
            O::ControlFlow(C::Call),
            None,
            &[A::LabelId, A::ReturnTargets],
        ),
        0x000c | 0x001b => (
            O::ControlFlow(C::Jump),
            Some(Q::ScriptFile),
            &[A::ScriptId, A::LabelId],
        ),
        0x000d => (
            O::ControlFlow(C::Call),
            Some(Q::ScriptFile),
            &[A::ScriptId, A::LabelId, A::ReturnTargets],
        ),
        0x000e => (O::ControlFlow(C::Return), None, &[]),
        0x000f => (
            O::ControlFlow(C::Branch),
            Some(Q::Decrement),
            &[A::LabelId, A::Count],
        ),
        0x0010 => (
            O::ControlFlow(C::Branch),
            Some(Q::Flag),
            &[A::State, A::FlagId, A::LabelId],
        ),
        0x0011 => (O::Runtime(R::Wait), Some(Q::Flag), &[A::State, A::FlagId]),
        0x0012 | 0x0013 if mode.is_some_and(|m| m <= 2) => (
            O::Storage(S::Store),
            Some(Q::Flag),
            match mode {
                Some(0) => &[A::Mode, A::FlagId],
                Some(1) => &[A::Mode, A::FlagId, A::Count],
                Some(2) => &[A::Mode, A::FlagId, A::Maximum],
                _ => &[A::Mode, A::FlagId],
            },
        ),
        0x0014 => (
            O::Storage(S::Store),
            Some(Q::Flag),
            &[A::Source, A::Destination],
        ),
        0x0015 => (
            O::ControlFlow(C::Branch),
            None,
            if mode.is_some_and(|m| m < 10) {
                &[A::Flags, A::Mask, A::Mode, A::LabelId]
            } else {
                &[A::Flags, A::VirtualKey, A::LabelId]
            },
        ),
        0x0016 => (O::Runtime(R::Wait), None, &[A::Flags, A::Mask, A::Mode]),
        0x0017 => (
            O::Runtime(R::Wait),
            Some(Q::Frame),
            &[A::Flags, A::Duration, A::Mask, A::Mode],
        ),
        0x0018 => (
            O::Storage(S::Store),
            Some(Q::Local),
            &[A::LocalIndex, A::Value],
        ),
        0x0019 => (O::Runtime(R::EngineCall), None, &[A::ContextId, A::Mode]),
        0x001a => (O::Runtime(R::EngineCall), Some(Q::Reference), &[]),
        0x001d | 0x0042 | 0x004f | 0x00fe => (O::Basic(B::Evaluate), None, &[A::Value]),
        0x001f => (O::Storage(S::Store), Some(Q::Register), &[A::Value]),
        0x0020 => (
            O::ControlFlow(C::Branch),
            Some(Q::Register),
            &[A::Value, A::LabelId],
        ),
        // Audio request/state records, sub_1400929A0..sub_1400966D0.
        0x0021 => (
            O::Audio(U::Play),
            Some(Q::Music),
            &[A::Mode, A::ResourceId, A::Enabled],
        ),
        0x0022 => (O::Audio(U::Stop), Some(Q::Music), &[A::Mode]),
        0x0023 => (
            O::Audio(U::Control),
            None,
            &[A::Channel, A::Mode, A::ResourceId, A::Enabled],
        ),
        0x0024 => (O::Audio(U::Stop), None, &[A::Channel]),
        0x0026 => (O::Audio(U::Play), None, &[A::ResourceId]),
        0x0027 => (O::Audio(U::Stop), None, &[]),
        0x0028 => (
            O::Storage(S::Store),
            Some(Q::Local),
            &[A::Source, A::Destination, A::LocalIndex, A::Count],
        ),
        0x002a => (O::Runtime(R::EngineCall), None, &[A::Mode]),
        0x002b => (O::Basic(B::Evaluate), None, &[A::Value]),
        0x002c => (O::Runtime(R::MarkSeen), Some(Q::Music), &[A::ResourceId]),
        0x0031 => (
            O::Runtime(R::EngineCall),
            Some(Q::ResourceTable),
            &[A::Mode, A::ResourceId],
        ),
        0x0033 => (O::Runtime(R::Wait), Some(Q::Frame), &[A::Duration]),
        0x0034 => (O::ControlFlow(C::Halt), None, &[]),
        0x0035 => (O::ControlFlow(C::Branch), Some(Q::Conditional), &[A::Mode]),
        0x0037 => (
            O::Audio(U::Play),
            None,
            &[A::Channel, A::ResourceId, A::Enabled],
        ),
        0x0038 => (O::Audio(U::Stop), Some(Q::Fade), &[A::Channel, A::Duration]),
        0x0039 | 0x003c => (O::Audio(U::Wait), None, &[A::Channel]),
        0x003a => (
            O::Audio(U::Control),
            Some(Q::Music),
            match mode {
                Some(0) => &[A::Mode, A::ResourceId, A::ResourceId],
                Some(2 | 3) => &[A::Mode, A::Duration],
                _ => &[A::Mode],
            },
        ),
        0x003b => (O::Audio(U::Control), None, &[A::Mode]),
        0x003d if !extended_context => {
            (O::Basic(B::Evaluate), None, &[A::ValueAt(0), A::ValueAt(1)])
        }
        0x0043 => (O::Text(T::Configure), None, &[A::Flags]),
        0x0046 => (O::Runtime(R::EngineCall), Some(Q::ReturnValue), &[A::Mode]),
        0x0047 => (O::Runtime(R::Yield), None, &[]),
        0x0048 => (O::ControlFlow(C::Halt), None, &[]),
        0x004b => (O::Runtime(R::Wait), None, &[A::Mode]),
        0x004c => (O::Runtime(R::Wait), None, &[A::Mode, A::Duration]),
        0x004d => (O::Basic(B::Evaluate), None, &[A::Reserved, A::Value]),
        0x0050 if glyph_width == 2 => (O::ControlFlow(C::Jump), None, &[A::Mode, A::LabelId]),
        0x0050 => (O::Runtime(R::Wait), None, &[A::Mode, A::Duration]),
        0x0053 => (
            O::ControlFlow(C::Branch),
            None,
            &[A::Flags, A::VirtualKey, A::LabelId],
        ),
        0x0054 => (
            O::ControlFlow(C::Call),
            Some(Q::Conditional),
            &[A::State, A::FlagId, A::LabelId, A::ReturnTargets],
        ),
        0x0055 => (
            O::ControlFlow(C::Branch),
            Some(Q::ScriptFile),
            &[A::State, A::FlagId, A::ScriptId, A::LabelId],
        ),
        0x0056 => (
            O::ControlFlow(C::Call),
            Some(Q::Conditional),
            &[
                A::State,
                A::FlagId,
                A::ScriptId,
                A::LabelId,
                A::ReturnTargets,
            ],
        ),
        0x0057 => (
            O::ControlFlow(C::Return),
            Some(Q::Conditional),
            &[A::State, A::FlagId],
        ),
        0x0059 if glyph_width == 4 => (
            O::Audio(U::SetVolume),
            None,
            &[A::Channel, A::Duration, A::Volume],
        ),
        0x005a => (
            if mode == Some(1) {
                O::ControlFlow(C::Jump)
            } else {
                O::Storage(S::Store)
            },
            Some(Q::Label),
            &[A::Mode, A::VariableId, A::Value],
        ),
        0x005c => (O::Runtime(R::EngineCall), None, &[A::Mode, A::Name]),
        0x005d => (
            O::Runtime(R::EngineCall),
            Some(Q::Configuration),
            &[A::Value],
        ),
        // Images, variables and text, sub_140083850..sub_14008C160.
        0x0100 => (
            O::Image(I::Configure),
            None,
            &[A::Mode, A::ResourceId, A::Width, A::Height],
        ),
        0x0101 => (O::Image(I::Clear), None, &[A::Mode, A::ResourceId]),
        0x0102 => (
            O::Image(I::Load),
            None,
            &[A::Destination, A::Type, A::ResourceId],
        ),
        0x0103 if layout.surface_operands == Some(1) => {
            (O::Image(I::Clear), None, &[A::ResourceId])
        }
        0x0103 if layout.surface_operands == Some(3) => (
            O::Basic(B::Evaluate),
            Some(Q::Many),
            &[A::ValueAt(0), A::ValueAt(1), A::ValueAt(2)],
        ),
        0x0104 => (
            O::Image(I::Draw),
            None,
            &[A::Destination, A::Red, A::Green, A::Blue, A::Opacity],
        ),
        0x0105 if mode.is_some_and(|m| matches!(m, 0..=7 | 10)) => (
            O::Storage(S::Store),
            Some(Q::Variable),
            match mode {
                Some(0 | 1) => &[A::Mode, A::Destination, A::Rotation],
                Some(2) => &[A::Mode, A::Destination, A::OffsetX, A::OffsetY],
                Some(3 | 4) => &[
                    A::Mode,
                    A::Destination,
                    A::ScaleX,
                    A::Rotation,
                    A::InitialValue,
                ],
                Some(5) => &[A::Mode, A::Destination, A::Left, A::Right, A::Value],
                Some(6) => &[A::Mode, A::Destination, A::Value, A::StartTime, A::Duration],
                Some(7) => &[A::Mode, A::Destination, A::Maximum],
                Some(10) => &[
                    A::Mode,
                    A::Destination,
                    A::InitialValue,
                    A::Value,
                    A::StartTime,
                    A::Duration,
                    A::EasingParameter,
                ],
                _ => &[A::Mode],
            },
        ),
        0x0106 => (
            if mode == Some(1) {
                O::Runtime(R::EngineCall)
            } else {
                O::Runtime(R::MarkSeen)
            },
            Some(Q::Message),
            if mode == Some(1) {
                &[A::Mode, A::Destination, A::ScriptId, A::MessageIndex]
            } else {
                &[A::Mode, A::ScriptId, A::MessageIndex]
            },
        ),
        0x0108 | 0x010a => (O::Text(T::Configure), None, &[A::Mode, A::Index]),
        0x0109 => (
            O::Text(T::Configure),
            None,
            match mode.map(|m| m & 0x7f) {
                Some(0) => &[A::Mode, A::Id],
                Some(1) if mode.is_some_and(|m| m & 0x80 != 0) => &[A::Mode, A::Id, A::Index],
                _ => &[A::Mode, A::Index],
            },
        ),
        0x010b => (O::Text(T::Configure), Some(Q::BlockBegin), &[]),
        0x010c => (O::Text(T::Show), Some(Q::Message), &[A::Flags]),
        0x010d => (O::Text(T::Wait), None, &[A::Mode]),
        0x010e => (O::Text(T::Configure), None, &[A::Index, A::LabelBase]),
        0x010f => (
            O::Text(T::Configure),
            None,
            &[A::StringIndex, A::StringIndex],
        ),
        0x0110 => (O::Text(T::Configure), Some(Q::History), &[A::Mode]),
        0x0111 => (O::Text(T::Configure), None, &[A::Mode, A::Index]),
        0x0112 => (
            if mode == Some(0) {
                O::Runtime(R::EngineCall)
            } else {
                O::ControlFlow(C::AddChoice)
            },
            Some(Q::ChoiceTable),
            &[A::Mode],
        ),
        0x0113 => (
            O::ControlFlow(C::ShowChoices),
            None,
            &[A::Mode, A::Destination],
        ),
        0x0114 => (
            if mode.is_some_and(|m| m <= 1) {
                O::Runtime(R::EngineCall)
            } else {
                O::ControlFlow(C::AddChoice)
            },
            Some(Q::ChoiceTable),
            &[A::Mode],
        ),
        0x0115 => (
            O::ControlFlow(C::ShowChoices),
            None,
            match mode.map(|m| m & 0xf) {
                Some(0) => &[A::Mode, A::HeadingCount, A::DefaultChoice],
                Some(2 | 3) => &[A::Mode, A::Destination],
                _ => &[A::Mode],
            },
        ),
        0x0116 if glyph_width == 4 => (
            O::Text(T::Configure),
            Some(Q::MessageTable),
            &[A::Mode, A::ScriptId],
        ),
        // sub_1400D9320 builds a scrolling text panel with its own state.
        0x011e if glyph_width == 4 && !extended_context => {
            (O::Runtime(R::EngineCall), Some(Q::Text), &[A::Mode])
        }
        0x0120 => (O::Image(I::Capture), None, &[A::Destination]),
        0x0121 => (O::Text(T::Configure), None, &[A::Index, A::LabelBase]),
        0x0122 => (
            O::Video(V::Play),
            None,
            if mode == Some(0x63) {
                &[A::Mode, A::Flags, A::Mode, A::ResourceId, A::Enabled]
            } else {
                &[A::Flags, A::Mode, A::ResourceId, A::Enabled]
            },
        ),
        0x0123 => (
            if mode == Some(2) {
                O::Video(V::Stop)
            } else {
                O::Runtime(R::EngineCall)
            },
            None,
            &[A::Mode],
        ),
        0x0125 if mode.is_some_and(|m| m & 0xf <= if extended_context { 5 } else { 3 }) => {
            (O::Text(T::AppendHistory), None, &[A::Flags])
        }
        0x0127 => (O::Runtime(R::EngineCall), None, &[A::Mode]),
        // Layer resources, funcs_14008E675. 2-byte glyph VMs omit 1001's mode.
        0x1000 => (O::Runtime(R::EngineCall), Some(Q::Clear), &[A::Mode]),
        0x1001 => (
            O::Image(I::Load),
            None,
            if glyph_width == 2 {
                &[A::Layer, A::ResourceId]
            } else {
                &[A::Mode, A::Layer, A::ResourceId]
            },
        ),
        0x1002 | 0x1006 => (O::Image(I::Configure), None, &[A::Left, A::Right]),
        0x1003 => (O::Image(I::Draw), None, &[A::Layer, A::Color]),
        0x1005 if glyph_width == 4 => (O::Image(I::Clear), None, &[A::Layer]),
        0x1007 => (O::Image(I::Configure), None, &[A::Source, A::Destination]),
        0x100f if glyph_width == 4 => (
            O::Image(I::Load),
            Some(Q::Animation),
            &[A::Mode, A::Layer, A::ResourceId],
        ),
        0x103c => (
            O::Image(I::Load),
            Some(Q::Animation),
            &[A::Mode, A::Layer, A::ResourceId],
        ),
        0x1010 | 0x103d => (O::Image(I::Clear), Some(Q::Animation), &[A::Layer]),
        0x1011 if glyph_width == 2 => (O::Image(I::Clear), Some(Q::Animation), &[A::Layer]),
        0x100b => (O::Runtime(R::NoOp), None, &[]),
        0x1022 => (
            O::Runtime(R::EngineCall),
            Some(Q::Configuration),
            &[A::Mode, A::Id],
        ),
        0x1029 => (
            O::Runtime(R::MarkSeen),
            Some(Q::Image),
            &[A::Mode, A::ResourceId],
        ),
        0x102c if glyph_width == 4 => (
            O::Runtime(R::EngineCall),
            Some(Q::Animation),
            match mode {
                Some(0) => &[A::Mode, A::Id, A::Type, A::Duration],
                Some(1) => &[A::Mode, A::Id, A::VariableId],
                Some(2) => &[A::Mode, A::Id],
                Some(3) => &[A::Mode, A::Id, A::Flags],
                Some(4) => &[A::Mode, A::Mode, A::Id],
                _ => &[A::Mode],
            },
        ),
        0x1033 => (
            O::Runtime(R::EngineCall),
            None,
            &[A::Mode, A::LabelBase, A::LabelBase],
        ),
        0x2000 if dialogue_extension => (O::Text(T::Configure), None, &[A::Mode]),
        _ => (O::Unknown, None, &[]),
    };
    i.opcode.operation = operation;
    i.opcode.variant = variant;
    for (arg, &name) in i.args.iter_mut().zip(names) {
        arg.name = name;
    }
    // Optional arguments stay in their actual wire order. StringIndex addresses
    // embedded SCX strings; MessageIndex selects the external MES message bank.
    if i.opcode.code == 0x010c
        && let Some(flags) = mode
    {
        let mut next = 1;
        if flags & 1 != 0 {
            i.args[next].name = A::VoiceId;
            next += 1;
        }
        i.args[next].name = A::SpeakerId;
        next += 1;
        if flags & 2 != 0 {
            i.args[next].name = A::VoiceSpeakerId;
        }
    }
    if i.opcode.code == 0x0112
        && let Some(mode) = mode
    {
        if mode == 0 {
            i.args[1].name = A::Id;
        } else if mode & 0x7f == 2 {
            i.args[2].name = A::Condition;
        }
    }
    if i.opcode.code == 0x0125
        && mode.is_some_and(|m| m & 0xf == 1 || (extended_context && m & 0xf == 5))
    {
        i.args[1].name = A::VoiceId;
        i.args[2].name = A::SpeakerId;
    }
    if matches!(i.opcode.code, 0x0012 | 0x0013) && mode.is_some_and(|m| m <= 2) {
        i.args.push(super::arg(
            A::Value,
            i.span.offset as usize,
            i.span.offset as usize,
            Value::Boolean(i.opcode.code == 0x0012),
        ));
    }
    // Runtime snapshot/input paths skip instructions, not operand payloads.
    // Both continuations remain reachable; waiting retries the same opcode.
    let skip = match (i.opcode.code, mode) {
        (0x0035, Some(0)) => 3,
        (0x0113, Some(0)) => 12,
        (0x1022, Some(0)) if glyph_width == 4 => 15,
        (0x1022, Some(2)) => 3,
        (0x2000, Some(10)) if dialogue_extension => 12,
        _ => 0,
    };
    if skip != 0 {
        let end = i.span.offset + i.span.size;
        let target = end
            .checked_add(skip)
            .ok_or_else(|| super::corrupt(i.span.offset as usize, "SC3 branch address overflow"))?;
        i.args.push(super::arg(
            A::NextBranchTarget,
            end as usize,
            end as usize,
            Value::CodeAddress(target),
        ));
    }
    Ok(())
}
