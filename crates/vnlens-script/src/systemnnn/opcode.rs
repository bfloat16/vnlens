//! CScript::Execute (NNN 2012: 0x45bd70), expression VM (0x45d3c0),
//! and CCommonGame callbacks (0x411c60..0x413690). Mapping is by native
//! family and opcode; unverified commands/operands stay explicitly unknown.
use crate::ir::{
    ArgName as A, AudioOperation as Au, BasicOperation as B, ControlFlowOperation as C,
    DataOperation as D, EffectOperation as E, ImageOperation as I, Opcode, Operation as O,
    Qualifier as Q, RuntimeOperation as R, StorageOperation as S, TextOperation as T,
};

pub(super) fn instruction(
    family: u32,
    code: u32,
    first: Option<u32>,
    second: Option<u32>,
) -> Opcode {
    let mut variant = None;
    let operation = match (family, code) {
        (0x66660001, _) => O::Data(D::Record),
        (0x66660002, 0x55560002 | 0x55560003 | 0x55560011) => O::ControlFlow(C::Branch),
        (0x66660002, 0x55560001) => O::Runtime(R::NoOp),
        (0x66660002, 0xa000007b | 0xa000007d) => {
            variant = Some(if code == 0xa000007b {
                Q::BlockBegin
            } else {
                Q::BlockEnd
            });
            O::Data(D::Record)
        }
        (0x66660002, 0x55560004 | 0x55560008) => O::ControlFlow(C::Jump),
        (0x66660002, 0x55560005 | 0x55560006) => O::ControlFlow(C::Halt),
        (0x66660002, 0x5556000b | 0x5556000c | 0x5556000e | 0x55560013) => O::Runtime(R::Yield),
        (0x66660002, 0x55560007) => O::ControlFlow(C::Return),
        (0x66660002, 0x55560009) => O::ControlFlow(C::Call),
        (0x66660002, 0x55560020) => O::ControlFlow(C::Jump),
        (0x66660002, 0x5556000a | 0x55560015 | 0x55560016) => {
            variant = Some(Q::ScriptFile);
            O::ControlFlow(if code == 0x5556000a { C::Call } else { C::Jump })
        }
        (0x66660003 | 0x66660004, _) => O::Unknown,
        (0x66660006, 0x22220001..=0x22220003) => O::Text(T::Show),
        (0x66660006, 0x22220004) => O::Runtime(R::Wait),
        (0x66660006, 0x22220005) => O::Effect(E::Transition),
        (0x66660006, 0x22220006) => O::ControlFlow(C::Branch),
        (0x66660007, 0x33330007) => {
            variant = Some(Q::Music);
            O::Audio(match first {
                Some(u32::MAX) => Au::Stop,
                Some(0xffff_fffe) => Au::SetVolume,
                _ => Au::Play,
            })
        }
        (0x66660007, 0x33330008 | 0x33330009) => O::Audio(if first == Some(u32::MAX) {
            Au::Stop
        } else {
            Au::Play
        }),
        (0x66660007, 0x33330011) => O::Image(I::Capture),
        (0x66660007, 0x33330012) => O::Image(I::Clear),
        // 0x3333005f selects the font-size variant of CCommonMessageWindow;
        // constructor 0x4b9d60 names the dimension windowNumberFontSizeType.
        (0x66660007, 0x33330017 | 0x3333001b | 0x3333001c | 0x3333005f) => O::Text(T::Configure),
        // 0x419d40 stores the per-frame delay, initialized by frameTime.
        (0x66660007, 0x33330028 | 0x33330029) => O::Runtime(R::SetFrameDuration),
        // 0x419b60 formats these two names into the source debug overlay.
        (0x66660007, 0x33330050 | 0x33330051) => O::Data(D::SourceLocation),
        // This host's dispatcher explicitly has no handler for 0x52.
        (0x66660007, 0x33330052) => O::Runtime(R::NoOp),
        // 0x411c60 -> CCommonSystemFile::0x4c89f0 writes cglist bits;
        // 0x411d00 -> 0x4c8b50 writes project/script read-state bits.
        // Their dimensions are initialized from cglist/project at 0x41b170.
        (0x66660007, 0x33330018 | 0x3333001a | 0x33330061) => {
            variant = Some(match code {
                0x33330018 => Q::Image,
                0x3333001a => Q::ScriptFile,
                _ => Q::Conditional,
            });
            O::Runtime(R::MarkSeen)
        }
        (0x66660007, 0x33330057 | 0x33330066 | 0x33330067) => O::Audio(Au::Configure),
        (0x66660007, 0x33330068 | 0x33330069) => O::Audio(Au::SetVolume),
        (0x66660007, 0x3333006a) => {
            variant = Some(Q::Music);
            O::Audio(Au::SetVolume)
        }
        (0x66660007, 0x33330062) => O::Storage(S::Store),
        (0x66660007, 0x33330013) if second == Some(u32::MAX) => O::Image(I::Clear),
        (0x66660007, 0x33330013) => O::Effect(E::Configure),
        (0x66660007, 0x33330014) => O::Image(I::Clear),
        (0x66660007, 0x33330015 | 0x3333001f) => O::Image(I::Load),
        (0x66660007, 0x33330016) => O::Image(I::SetRegion),
        _ => O::Unknown,
    };
    Opcode {
        operation,
        variant,
        namespace: format!("systemnnn/{family:08x}"),
        code,
        native_mnemonic: None,
    }
}

/// Fixed operand words read unconditionally by the verified VM handlers.
pub(super) fn minimum_words(family: u32, code: u32) -> usize {
    match (family, code) {
        (0x66660002, 0x55560009 | 0x5556000a | 0x55560016) => 2,
        (0x66660002, 0x55560008 | 0x55560015 | 0x55560020 | 0xa000007b) => 1,
        (0x66660006, 0x22220001..=0x22220004) => 2,
        (0x66660006, 0x22220005) => 3,
        (0x66660006, 0x22220006) => 1,
        (0x66660007, 0x33330008 | 0x33330009 | 0x33330013) => 3,
        (
            0x66660007,
            0x33330007 | 0x33330014 | 0x33330015 | 0x3333001f | 0x33330050 | 0x33330051,
        ) => 2,
        (0x66660007, 0x33330016) => 10,
        (0x66660007, 0x33330018 | 0x33330062 | 0x33330064 | 0x33330068 | 0x33330069) => 3,
        (0x66660007, 0x33330061) => 6,
        (0x66660007, 0x33330063) => 4,
        (
            0x66660007,
            0x33330019
            | 0x3333001a
            | 0x3333001e
            | 0x33330028
            | 0x33330052..=0x33330060
            | 0x33330065..=0x33330067
            | 0x3333006a,
        ) => 2,
        (0x66660007, 0x33330042) => 1,
        _ => 0,
    }
}

pub(super) fn argument(family: u32, code: u32, index: usize, first: Option<u32>, count: u32) -> A {
    if has_argument_count(family, code) && index as u64 > u64::from(count) {
        return if family == 0x66660007 && code == 0x33330008 && index as u64 == u64::from(count) + 1
        {
            A::Flags
        } else {
            A::Unknown(index as u64)
        };
    }
    if family == 0x66660007 && code == 0x33330007 && index == 2 {
        return match first {
            Some(u32::MAX) => A::Duration,
            Some(0xffff_fffe) => A::Volume,
            _ => A::Mode,
        };
    }
    match (family, code, index) {
        (0x66660002, 0x55560009, 0) => A::LabelId,
        (0x66660002, 0x55560009, 1) => A::ReturnCode,
        (0x66660002, 0x55560008, 0) => A::Value,
        (0x66660002, 0x55560020, 0) => A::Target,
        (0x66660002, 0xa000007b, 0) => A::EndTarget,
        (0x66660002, 0x5556000a | 0x55560015 | 0x55560016, 0) => A::Resource,
        (0x66660002, 0x5556000a | 0x55560016, 1) => A::LabelId,
        (0x66660006, 0x22220001..=0x22220003, 0) => A::Text,
        (0x66660006, 0x22220001..=0x22220003, 1) => A::TextId,
        // CMessage::SetMessage (0x449040) uses this as a name-table index.
        (0x66660006, 0x22220001..=0x22220003, 2) => A::Index,
        (0x66660006, 0x22220005, 0) => A::ArgumentCount,
        (0x66660006, 0x22220004, 1) => A::Duration,
        (0x66660006, 0x22220005, 1) => A::Mode,
        (0x66660006, 0x22220005, 2) => A::Duration,
        (0x66660007, 0x33330015 | 0x3333001f, 0) => A::Index,
        (0x66660007, 0x33330015 | 0x3333001f, 1) => A::Resource,
        (0x66660007, 0x33330050 | 0x33330051, 1) => A::Name,
        (0x66660007, 0x33330042, 0) => A::Message,
        (0x66660007, 0x33330008, 1) => A::Resource,
        (0x66660007, 0x33330008 | 0x33330009, 2) => A::Channel,
        (0x66660007, 0x33330007 | 0x33330009, 1) => A::ResourceId,
        (0x66660007, 0x33330007..=0x33330009, 3) => A::Volume,
        (0x66660007, 0x33330007, 5) => A::Duration,
        (0x66660007, 0x33330013 | 0x33330014 | 0x33330016 | 0x33330063 | 0x33330064, 1) => A::Index,
        (0x66660007, 0x33330062, 1) => A::VariableId,
        (0x66660007, 0x33330062, 2) => A::Value,
        (0x66660007, 0x33330063, 3) => A::VariableId,
        (0x66660007, 0x3333001b | 0x3333001c, 1) => A::TextId,
        (0x66660007, 0x3333001b | 0x3333001c, 2) => A::Mode,
        (0x66660007, 0x33330066 | 0x33330067 | 0x33330028, 1) => A::Duration,
        (0x66660007, 0x33330057, 1) => A::Flags,
        (0x66660007, 0x3333005f, 1) => A::Type,
        (0x66660007, 0x33330068 | 0x33330069, 1) => A::Channel,
        (0x66660007, 0x33330068 | 0x33330069, 2) => A::Volume,
        (0x66660007, 0x3333006a, 1) => A::Volume,
        (0x66660007, 0x3333006a, 2) => A::Duration,
        (0x66660007, 0x33330061, 4) => A::VariableId,
        (0x66660007, 0x33330061, 5) => A::Value,
        (0x66660007, 0x33330018 | 0x33330061, 1 | 3) => A::Index,
        (0x66660007, 0x33330018 | 0x33330061, 2) => A::ResourceId,
        (0x66660007, 0x3333001a, 1) => A::TextId,
        (0x66660007, 0x33330013, 2) => A::Type,
        (
            0x66660007,
            0x33330007..=0x33330009
            | 0x33330013
            | 0x33330016
            | 0x33330018
            | 0x3333001b
            | 0x3333001c
            | 0x33330061..=0x3333006a,
            0,
        ) => A::ArgumentCount,
        _ => A::Unknown(index as u64),
    }
}

pub(super) fn token(code: u32) -> Opcode {
    let mut variant = None;
    let operation = match code & 0xffff0000 {
        0x80000000 => {
            variant = Some(Q::Variable);
            O::Storage(S::Reference)
        }
        0x90000000 => {
            variant = Some(Q::Integer);
            O::Storage(S::Push)
        }
        0xa0000000 => match code & 0xffff {
            0x3d => {
                variant = Some(Q::Assign);
                O::Storage(S::Store)
            }
            // Unary ! writes back when its implicit operand is a variable.
            0x21 => {
                variant = Some(Q::Conditional);
                O::ControlFlow(C::LogicalNot)
            }
            0x25 => O::Basic(B::Remainder),
            0x26 => O::Basic(B::BitAnd),
            0x2a => O::Basic(B::Multiply),
            0x2b => O::Basic(B::Add),
            0x2d => O::Basic(B::Subtract),
            0x2f => O::Basic(B::Divide),
            0x5e => O::Basic(B::BitXor),
            0x7c => O::Basic(B::BitOr),
            _ => O::Unknown,
        },
        0xa2000000 if code == 0xa200003d => O::ControlFlow(C::Equal),
        0xa2000000 => {
            variant = match code & 0xffff {
                0x21 => Some(Q::LogicalNotAssign),
                0x25 => Some(Q::RemainderAssign),
                0x26 => Some(Q::BitAndAssign),
                0x2a => Some(Q::MultiplyAssign),
                0x2b => Some(Q::AddAssign),
                0x2d => Some(Q::SubtractAssign),
                0x2f => Some(Q::DivideAssign),
                0x5e => Some(Q::BitXorAssign),
                0x7c => Some(Q::BitOrAssign),
                _ => None,
            };
            if variant.is_some() {
                O::Storage(S::Store)
            } else {
                O::Unknown
            }
        }
        0xa3000000 => match code & 0xffff {
            0x26 => O::ControlFlow(C::LogicalAnd),
            0x7c => O::ControlFlow(C::LogicalOr),
            0x5e => O::ControlFlow(C::LogicalXor),
            0x3d => O::ControlFlow(C::Equal),
            _ => O::Unknown,
        },
        0xa4000000 => match code & 0xffff {
            0x3c => O::ControlFlow(C::Less),
            0x3e => O::ControlFlow(C::Greater),
            _ => O::Unknown,
        },
        0xa5000000 => match code & 0xffff {
            0x21 => O::ControlFlow(C::NotEqual),
            0x3c => O::ControlFlow(C::LessEqual),
            0x3e => O::ControlFlow(C::GreaterEqual),
            0x3d => O::ControlFlow(C::Equal),
            _ => O::Unknown,
        },
        _ => O::Unknown,
    };
    Opcode {
        operation,
        variant,
        namespace: "systemnnn/expression".into(),
        code,
        native_mnemonic: None,
    }
}

// Name dispatch is verified against CCommonGame initialization at 0x4059c6
// and function handler 0x40b0a0. Numeric IDs come from function.xtx, so an
// unknown/reordered table never acquires semantics from a hard-coded ID.
pub(super) fn named_operation(family: u32, name: &str) -> O {
    match (family, name) {
        (0x66660004, "layer") => O::Image(I::SetVisibility),
        (0x66660004, "stopf5") => O::Runtime(R::StopSkip),
        (0x66660004, "adjustdate" | "setscene" | "savesystemfile") => O::Runtime(R::EngineCall),
        _ => O::Unknown,
    }
}
pub(super) fn named_argument(family: u32, name: Option<&str>, index: u32) -> A {
    match (family, name, index) {
        (0x66660004, Some("layer"), 0) => A::Index,
        (0x66660004, Some("layer"), 1) => A::Flags,
        _ => A::Unknown(u64::from(index)),
    }
}
pub(super) fn signed_argument(family: u32, code: u32, index: usize, first: Option<u32>) -> bool {
    family == 0x66660007
        && ((matches!(code, 0x33330007..=0x33330009) && index == 1)
            || (code == 0x33330007 && index == 2 && first == Some(0xffff_fffe))
            || (matches!(code, 0x33330007..=0x33330009) && index == 3)
            || (matches!(code, 0x33330068 | 0x33330069) && index == 2)
            || (code == 0x3333006a && index == 1)
            || (code == 0x33330062 && index == 2))
}

/// Counted callback payloads in Execute; other leading words can be layer
/// indexes or ignored fields and must not be interpreted as counts.
pub(super) fn has_argument_count(family: u32, code: u32) -> bool {
    (family == 0x66660006 && code == 0x22220005)
        || (family == 0x66660007
            && matches!(code, 0x33330007..=0x33330009 | 0x33330013 | 0x33330016 | 0x33330018 | 0x3333001b | 0x3333001c | 0x33330061..=0x3333006a))
}
