//! ADV procedure semantics from adv/adv.c::script_task and adv/proc_*.inc.
//! The registry is read on demand, never inferred from numeric IDs alone.
//! Reviewed token-stream fingerprints guard mappings against changed bodies;
//! source text stays external. Stack operands are derived zero-length fields.
use super::*;
use crate::ir::{
    ArgName as A, AudioOperation as U, BasicOperation as B, ControlFlowOperation as C,
    EffectOperation as E, ImageOperation as I, Operation as O, Qualifier as Q,
    RuntimeOperation as R, StorageOperation as S, TextOperation as T,
};
use std::collections::BTreeMap;

pub(super) fn resolve(script: &mut Script, resources: &dyn ResourceResolver) -> Result<()> {
    let Some(registry) = resources.read_resource("adv/adv.c")? else {
        return Ok(());
    };
    let registry = decode_envelope(&registry)?;
    let tokens = source::tokens(&registry)?;
    let Some(names) = source::registry(&tokens) else {
        return Ok(());
    };
    // The registered functions use this accessor ABI; other interpreters retain
    // their native IDs until their stack conventions have also been reviewed.
    let Some(vm) = resources.read_resource("misc/script.inc")? else {
        return Ok(());
    };
    let vm = decode_envelope(&vm)?;
    if source::fingerprint(&source::tokens(&vm)?) != VM {
        return Ok(());
    }
    let targets: std::collections::BTreeSet<_> = script
        .instructions
        .iter()
        .flat_map(|i| &i.args)
        .filter_map(|a| {
            if let Value::CodeAddress(v) = a.value {
                Some(v)
            } else {
                None
            }
        })
        .collect();
    let mut checked = BTreeMap::new();
    for index in 0..script.instructions.len() {
        if script.instructions[index].opcode.namespace != "escude.scenario"
            || script.instructions[index].opcode.code != 44
        {
            continue;
        }
        let Some(Value::Unsigned(id)) = script.instructions[index].args.first().map(|a| &a.value)
        else {
            continue;
        };
        let Some(name) = names.get(*id as usize) else {
            continue;
        };
        script.instructions[index].args[0].name = A::ProcedureId;
        script.instructions[index].args[0].native_name = Some(name.clone());
        script.instructions[index].opcode.native_mnemonic = Some(name.clone());
        let Some(definition) = definition(name) else {
            continue;
        };
        let file = definition.file;
        if !checked.contains_key(file) {
            let valid = match resources.read_resource(file)? {
                Some(bytes) => {
                    let bytes = decode_envelope(&bytes)?;
                    source::fingerprint(&source::tokens(&bytes)?) == file_fingerprint(file)
                }
                None => false,
            };
            checked.insert(file, valid);
        }
        let at = script.instructions[index].span.offset;
        let count = if !targets.contains(&at) {
            index
                .checked_sub(1)
                .and_then(|i| script.instructions.get(i))
                .filter(|i| i.opcode.code == 4 && i.opcode.namespace == "escude.scenario")
                .and_then(|i| i.args.first())
                .and_then(|a| {
                    if let Value::Integer(v) = a.value {
                        usize::try_from(v).ok()
                    } else {
                        None
                    }
                })
        } else {
            None
        };
        let known = if count.is_some() && !targets.contains(&at) {
            stack_literals(&script.instructions, index, &targets)
        } else {
            Vec::new()
        };
        let instruction = &mut script.instructions[index];
        if !checked[file] {
            continue;
        }
        instruction.opcode.operation = definition.operation;
        instruction.opcode.variant = definition.variant;
        let at = at as usize;
        instruction.args.push(arg(
            A::ArgumentCount,
            at,
            0,
            count.map_or_else(
                || stack_value(at, None, None),
                |count| Value::Unsigned(count as u64),
            ),
        ));
        let len = if definition.variadic && count.is_some_and(|n| n <= known.len()) {
            count.unwrap_or(0)
        } else {
            definition.args.len()
        };
        let mut arguments = Vec::new();
        for i in 0..len {
            let role = if name == "proc_rand" && count == Some(1) {
                A::Maximum
            } else {
                definition
                    .args
                    .get(i)
                    .copied()
                    .unwrap_or(A::ValueAt(i as u64))
            };
            arguments.push(arg(
                role,
                at,
                0,
                stack_value(
                    at,
                    Some(i),
                    known
                        .get(i)
                        .filter(|_| count.is_some_and(|n| i < n))
                        .cloned()
                        .flatten(),
                ),
            ));
        }
        if definition.variadic && count.is_none_or(|n| n > known.len()) {
            // Keep a symbolic sequence when the runtime count is not backed by
            // visible stack producers; never allocate from an arbitrary value.
            arguments.push(arg(
                A::Values,
                at,
                0,
                Value::Expression(vec![Token {
                    opcode: Opcode {
                        operation: O::Storage(S::GetArguments),
                        variant: Some(Q::StackArgument),
                        namespace: "escude.scenario".into(),
                        code: 44,
                        native_mnemonic: None,
                    },
                    span: span(at, 0),
                    args: vec![arg(
                        A::ArgumentCount,
                        at,
                        0,
                        count.map_or_else(
                            || stack_value(at, None, None),
                            |n| Value::Unsigned(n as u64),
                        ),
                    )],
                    raw: Vec::new(),
                }]),
            ));
        }
        instruction
            .args
            .push(arg(A::Arguments, at, 0, Value::Group(arguments)));
    }
    Ok(())
}

fn stack_literals(
    instructions: &[Instruction],
    index: usize,
    targets: &std::collections::BTreeSet<u64>,
) -> Vec<Option<Value>> {
    let mut values = Vec::new();
    let Some(count_index) = index.checked_sub(1) else {
        return values;
    };
    if targets.contains(&instructions[count_index].span.offset) {
        return values;
    }
    for instruction in instructions[..count_index].iter().rev() {
        if instruction.opcode.namespace != "escude.scenario" {
            break;
        }
        let value = match instruction.opcode.code {
            4 | 5 => instruction.args.first().map(|a| a.value.clone()),
            7 => instruction
                .args
                .iter()
                .find(|a| a.name == A::Text)
                .map(|a| a.value.clone()),
            6 | 8..=10 => None,
            _ => break,
        };
        values.push(value);
        if targets.contains(&instruction.span.offset) {
            break;
        }
    }
    values
}

fn stack_value(at: usize, index: Option<usize>, value: Option<Value>) -> Value {
    let mut args = Vec::new();
    if let Some(index) = index {
        args.push(arg(A::StackIndex, at, 0, Value::Unsigned(index as u64)));
    }
    if let Some(value) = value {
        args.push(arg(A::Value, at, 0, value));
    }
    Value::Expression(vec![Token {
        opcode: Opcode {
            operation: O::Storage(if index.is_some() {
                S::GetArgument
            } else {
                S::GetArgumentCount
            }),
            variant: Some(Q::StackArgument),
            namespace: "escude.scenario".into(),
            code: 44,
            native_mnemonic: None,
        },
        span: span(at, 0),
        args,
        raw: Vec::new(),
    }])
}

struct Definition {
    file: &'static str,
    operation: O,
    variant: Option<Q>,
    args: &'static [A],
    variadic: bool,
}
fn definition(name: &str) -> Option<Definition> {
    let (file, operation, variant, args, variadic) = match name {
        "proc_end" => (SYS, O::ControlFlow(C::Halt), None, &[A::Id][..], false),
        "proc_call" => (
            SYS,
            O::ControlFlow(C::Call),
            Some(Q::ScriptFile),
            &[A::ScriptId][..],
            false,
        ),
        "proc_argv" => (
            SYS,
            O::Storage(S::GetArgument),
            None,
            &[A::Index][..],
            false,
        ),
        "proc_argc" => (SYS, O::Storage(S::GetArgumentCount), None, &[][..], false),
        "proc_typeof" => (SYS, O::Basic(B::TypeOf), None, &[A::Value][..], false),
        "proc_int" => (
            SYS,
            O::Basic(B::Convert),
            Some(Q::Integer),
            &[A::Value][..],
            false,
        ),
        "proc_float" => (
            SYS,
            O::Basic(B::Convert),
            Some(Q::Float32),
            &[A::Value][..],
            false,
        ),
        "proc_abs" => (SYS, O::Basic(B::Absolute), None, &[A::Value][..], false),
        "proc_rand" => (
            SYS,
            O::Basic(B::Random),
            None,
            &[A::Minimum, A::Maximum][..],
            true,
        ),
        "proc_min" => (SYS, O::Basic(B::Minimum), None, &[][..], true),
        "proc_max" => (SYS, O::Basic(B::Maximum), None, &[][..], true),
        "proc_rgb" => (
            SYS,
            O::Basic(B::PackColor),
            None,
            &[A::Red, A::Green, A::Blue, A::Opacity][..],
            false,
        ),
        "proc_refer" => (SYS, O::Runtime(R::EngineCall), None, &[A::Index][..], true),
        "proc_credit" => (SYS, O::Runtime(R::EngineCall), None, &[A::Id][..], false),
        "proc_log_new" => (
            SYS,
            O::Runtime(R::EngineCall),
            None,
            &[A::Resource][..],
            false,
        ),
        "proc_log_out" => (
            SYS,
            O::Runtime(R::EngineCall),
            None,
            &[A::Resource, A::Text][..],
            true,
        ),
        "proc_title" => (SYS, O::Text(T::Configure), None, &[A::Title][..], false),
        "proc_auto_save" => (SYS, O::Runtime(R::Save), None, &[][..], false),
        "proc_is_pass" => (
            SYS,
            O::Runtime(R::EngineCall),
            None,
            &[A::ScriptId][..],
            false,
        ),
        "proc_event" => (
            SYS,
            O::Runtime(R::MarkSeen),
            Some(Q::Image),
            &[A::ResourceId][..],
            false,
        ),
        "proc_scene" => (
            SYS,
            O::Runtime(R::MarkSeen),
            Some(Q::ScriptFile),
            &[A::Id][..],
            false,
        ),
        "proc_named" => (
            SYS,
            O::Runtime(R::MarkSeen),
            Some(Q::Speaker),
            &[A::SpeakerId][..],
            false,
        ),
        "proc_notice" => (
            SYS,
            O::Text(T::Show),
            None,
            &[A::Text, A::Duration, A::Flags][..],
            false,
        ),
        "proc_log_img" => (SYS, O::Runtime(R::NoOp), None, &[][..], false),
        "proc_wait" => (
            SYS,
            O::Runtime(R::Wait),
            None,
            &[A::Duration, A::Flags][..],
            false,
        ),
        "proc_msg_opt" => (
            TXT,
            O::Text(T::Configure),
            None,
            &[A::Id, A::Flags][..],
            false,
        ),
        "proc_cf" => (
            TXT,
            O::Text(T::Configure),
            Some(Q::Image),
            &[A::ResourceId, A::ImageFrame][..],
            false,
        ),
        "proc_cv" => (TXT, O::Audio(U::Configure), Some(Q::Voice), &[][..], true),
        "proc_vt" => (
            TXT,
            O::Audio(U::Wait),
            Some(Q::Voice),
            &[A::Duration, A::Channel][..],
            false,
        ),
        "proc_frame" => (
            TXT,
            O::Text(T::Configure),
            Some(Q::Frame),
            &[A::Id][..],
            false,
        ),
        "proc_text" => (
            TXT,
            O::Text(T::Configure),
            None,
            &[A::Enabled, A::Duration][..],
            false,
        ),
        "proc_vals" => (TXT, O::Text(T::Configure), None, &[][..], true),
        "proc_clear" => (TXT, O::Text(T::Clear), None, &[A::Duration][..], false),
        "proc_gap" => (
            TXT,
            O::Text(T::Configure),
            None,
            &[A::OffsetX, A::OffsetY][..],
            false,
        ),
        "proc_menu_opt" => (
            TXT,
            O::Runtime(R::EngineCall),
            None,
            &[A::Enabled][..],
            false,
        ),
        "proc_menu" => (
            TXT,
            O::ControlFlow(C::ShowChoices),
            None,
            &[A::Flags, A::Mode][..],
            false,
        ),
        "proc_click_map" => (
            TXT,
            O::ControlFlow(C::ShowChoices),
            Some(Q::Image),
            &[A::Resource, A::Flags][..],
            false,
        ),
        "proc_lsf_init" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[A::ResourceId][..],
            false,
        ),
        "proc_lsf_set" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[A::ResourceId][..],
            true,
        ),
        "proc_lsf_get" => (
            GFX,
            O::Runtime(R::EngineCall),
            Some(Q::Layer),
            &[A::ResourceId, A::Index][..],
            false,
        ),
        "proc_dt" => (GFX, O::Runtime(R::EngineCall), None, &[A::Value][..], false),
        "proc_ps" => (
            GFX,
            O::Runtime(R::EngineCall),
            Some(Q::Layer),
            &[][..],
            true,
        ),
        "proc_cg" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[
                A::Layer,
                A::ResourceId,
                A::ImageFrame,
                A::Mode,
                A::EffectId,
                A::Priority,
                A::OffsetX,
                A::OffsetY,
                A::ScaleX,
                A::ScaleY,
                A::Rotation,
                A::Opacity,
            ][..],
            false,
        ),
        "proc_cg_p" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[A::Layer][..],
            true,
        ),
        "proc_cg_org" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[A::Layer, A::OriginX, A::OriginY][..],
            false,
        ),
        "proc_cg_set" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[A::Layer, A::Id, A::Value][..],
            false,
        ),
        "proc_cg_get" => (
            GFX,
            O::Runtime(R::EngineCall),
            Some(Q::Layer),
            &[A::Layer, A::Id][..],
            false,
        ),
        "proc_cg_em" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[
                A::Layer,
                A::ResourceId,
                A::Index,
                A::OffsetX,
                A::OffsetY,
                A::Priority,
            ][..],
            false,
        ),
        "proc_cg_clr" => (
            GFX,
            O::Image(I::Clear),
            Some(Q::Layer),
            &[A::Layer][..],
            false,
        ),
        "proc_cg_disp" => (
            GFX,
            O::Effect(E::Transition),
            None,
            &[
                A::Mode,
                A::Duration,
                A::Easing,
                A::Flags,
                A::Flags,
                A::Color,
            ][..],
            false,
        ),
        "proc_path" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Animation),
            &[
                A::Layer,
                A::Duration,
                A::OffsetX,
                A::OffsetY,
                A::ScaleX,
                A::ScaleY,
                A::Rotation,
                A::Opacity,
            ][..],
            false,
        ),
        "proc_tween" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Animation),
            &[A::Layer, A::Id][..],
            false,
        ),
        "proc_trans" => (
            GFX,
            O::Effect(E::Transition),
            Some(Q::Animation),
            &[][..],
            false,
        ),
        "proc_mot_set" => (
            GFX,
            O::Storage(S::Store),
            Some(Q::Animation),
            &[A::Layer, A::VariableId, A::Value][..],
            false,
        ),
        "proc_mot_get" => (
            GFX,
            O::Storage(S::Load),
            Some(Q::Animation),
            &[A::Layer, A::VariableId][..],
            false,
        ),
        "proc_quake" => (
            GFX,
            O::Effect(E::Shake),
            None,
            &[A::Layer, A::OffsetX, A::OffsetY, A::Duration][..],
            false,
        ),
        "proc_flash" => (
            GFX,
            O::Effect(E::Flash),
            None,
            &[A::Color, A::Count][..],
            false,
        ),
        "proc_flt" => (
            GFX,
            O::Effect(E::Configure),
            None,
            &[A::EffectId, A::Mode, A::Color, A::Width, A::Height][..],
            false,
        ),
        "proc_ptcl" => (
            GFX,
            O::Effect(E::Configure),
            None,
            &[
                A::EffectId,
                A::Count,
                A::ValueAt(1),
                A::ValueAt(2),
                A::Opacity,
                A::ValueAt(4),
                A::Color,
                A::Rotation,
                A::ValueAt(7),
                A::OriginX,
                A::OriginY,
                A::Priority,
            ][..],
            false,
        ),
        "proc_sync" => (
            GFX,
            O::Runtime(R::Wait),
            None,
            &[A::Flags, A::Enabled][..],
            false,
        ),
        "proc_auto_kill" => (
            GFX,
            O::Image(I::Configure),
            Some(Q::Layer),
            &[A::Layer, A::Enabled][..],
            false,
        ),
        "proc_movie" => (
            GFX,
            O::Video(VideoOperation::Play),
            None,
            &[A::ResourceId][..],
            false,
        ),
        "proc_bgm_play" => (
            SND,
            O::Audio(U::Play),
            Some(Q::Music),
            &[A::ResourceId, A::Duration, A::Volume, A::StartTime][..],
            false,
        ),
        "proc_amb_play" => (
            SND,
            O::Audio(U::Play),
            Some(Q::Ambient),
            &[A::ResourceId, A::Duration, A::Volume, A::StartTime][..],
            false,
        ),
        "proc_bgm_stop" => (
            SND,
            O::Audio(U::Stop),
            Some(Q::Music),
            &[A::Duration][..],
            false,
        ),
        "proc_amb_stop" => (
            SND,
            O::Audio(U::Stop),
            Some(Q::Ambient),
            &[A::Duration][..],
            false,
        ),
        "proc_bgm_vol" => (
            SND,
            O::Audio(U::SetVolume),
            Some(Q::Music),
            &[A::Volume, A::Duration][..],
            false,
        ),
        "proc_amb_vol" => (
            SND,
            O::Audio(U::SetVolume),
            Some(Q::Ambient),
            &[A::Volume, A::Duration][..],
            false,
        ),
        "proc_bgm_fx" => (
            SND,
            O::Audio(U::Configure),
            Some(Q::Music),
            &[A::EffectId][..],
            false,
        ),
        "proc_amb_fx" => (
            SND,
            O::Audio(U::Configure),
            Some(Q::Ambient),
            &[A::EffectId][..],
            false,
        ),
        "proc_se_play" => (
            SND,
            O::Audio(U::Play),
            None,
            &[
                A::Channel,
                A::ResourceId,
                A::Flags,
                A::Duration,
                A::Volume,
                A::StartTime,
            ][..],
            false,
        ),
        "proc_se_stop" => (
            SND,
            O::Audio(U::Stop),
            None,
            &[A::Channel, A::Duration][..],
            false,
        ),
        "proc_se_wait" => (SND, O::Audio(U::Wait), None, &[A::Channel][..], false),
        "proc_se_vol" => (
            SND,
            O::Audio(U::SetVolume),
            None,
            &[A::Channel, A::Volume, A::Duration][..],
            false,
        ),
        "proc_se_fx" => (SND, O::Audio(U::Configure), None, &[A::EffectId][..], false),
        "proc_voc_play" => (
            SND,
            O::Audio(U::Play),
            Some(Q::Voice),
            &[
                A::Channel,
                A::ResourceId,
                A::Duration,
                A::Volume,
                A::StartTime,
            ][..],
            false,
        ),
        "proc_bgv_play" => (
            SND,
            O::Audio(U::Play),
            Some(Q::AmbientVoice),
            &[
                A::Channel,
                A::ResourceId,
                A::Duration,
                A::Volume,
                A::StartTime,
            ][..],
            false,
        ),
        "proc_voc_stop" => (
            SND,
            O::Audio(U::Stop),
            Some(Q::Voice),
            &[A::Channel, A::Duration][..],
            false,
        ),
        "proc_bgv_stop" => (
            SND,
            O::Audio(U::Stop),
            Some(Q::AmbientVoice),
            &[A::Channel, A::Duration][..],
            false,
        ),
        "proc_voc_wait" => (
            SND,
            O::Audio(U::Wait),
            Some(Q::Voice),
            &[A::Channel][..],
            false,
        ),
        "proc_voc_vol" => (
            SND,
            O::Audio(U::SetVolume),
            Some(Q::Voice),
            &[A::Channel, A::Volume, A::Duration][..],
            false,
        ),
        "proc_bgv_vol" => (
            SND,
            O::Audio(U::SetVolume),
            Some(Q::AmbientVoice),
            &[A::Channel, A::Volume, A::Duration][..],
            false,
        ),
        "proc_voc_fx" => (
            SND,
            O::Audio(U::Configure),
            Some(Q::Voice),
            &[A::EffectId][..],
            false,
        ),
        "proc_bgv_fx" => (
            SND,
            O::Audio(U::Configure),
            Some(Q::AmbientVoice),
            &[A::EffectId][..],
            false,
        ),
        "proc_set_param" => (
            GAME,
            O::Runtime(R::EngineCall),
            None,
            &[A::Id, A::Index, A::Value][..],
            false,
        ),
        "proc_get_param" => (
            GAME,
            O::Runtime(R::EngineCall),
            None,
            &[A::Id, A::Index][..],
            false,
        ),
        "proc_jump" => (
            GAME,
            O::ControlFlow(C::Jump),
            Some(Q::ScriptFile),
            &[A::ScriptId][..],
            false,
        ),
        "proc_date" => (
            GAME,
            O::Runtime(R::EngineCall),
            None,
            &[A::Value][..],
            false,
        ),
        "proc_flow" => (
            GAME,
            O::Runtime(R::EngineCall),
            None,
            &[A::ScriptId][..],
            false,
        ),
        "proc_episode" => (
            GAME,
            O::ControlFlow(C::ShowChoices),
            Some(Q::ScriptFile),
            &[][..],
            false,
        ),
        _ => return None,
    };
    Some(Definition {
        file,
        operation,
        variant,
        args,
        variadic,
    })
}

const SYS: &str = "adv/proc_sys.inc";
const TXT: &str = "adv/proc_txt.inc";
const GFX: &str = "adv/proc_gfx.inc";
const SND: &str = "adv/proc_snd.inc";
const GAME: &str = "adv/proc_game.inc";
const VM: [u8; 16] = [
    0x3d, 0xe1, 0xba, 0x16, 0x78, 0x2b, 0x96, 0x5a, 0xf9, 0xbe, 0xe3, 0xce, 0x88, 0x44, 0x07, 0xfe,
];
fn file_fingerprint(file: &str) -> [u8; 16] {
    match file {
        SYS => [
            0xfb, 0x64, 0x58, 0x49, 0xa3, 0x74, 0xcf, 0xb3, 0xb6, 0x98, 0xde, 0xab, 0xc7, 0xb0,
            0xe4, 0x84,
        ],
        TXT => [
            0xa6, 0x1e, 0x27, 0x98, 0xc4, 0xa8, 0x1f, 0x98, 0x8b, 0xde, 0xe9, 0x37, 0xdf, 0x01,
            0xfa, 0x3b,
        ],
        GFX => [
            0x14, 0xce, 0x3a, 0x22, 0x42, 0xe8, 0x99, 0xa1, 0x9d, 0x92, 0x10, 0x37, 0x71, 0x5a,
            0xcc, 0x21,
        ],
        SND => [
            0x43, 0x35, 0x08, 0x8c, 0xe6, 0x81, 0x15, 0xbd, 0xc7, 0x44, 0xd7, 0xfc, 0x0c, 0x7a,
            0x0c, 0xd1,
        ],
        GAME => [
            0x41, 0x90, 0x0b, 0x8f, 0xcd, 0x7e, 0x8c, 0x12, 0x02, 0x80, 0x36, 0x19, 0xf8, 0x25,
            0xbc, 0x64,
        ],
        _ => [0; 16],
    }
}

#[cfg(test)]
#[path = "../../tests/escude/procedure.rs"]
mod tests;
