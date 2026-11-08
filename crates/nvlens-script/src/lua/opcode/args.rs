//! Native field layouts and operand kinds from Lua lopcodes.h.
use super::Op;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::lua) enum Field {
    K,
    VB,
    VC,
    SJ,
    Ax54,
    A,
    B,
    C,
    Bx,
    SBx,
    Ax,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::lua) enum Kind {
    Signed,
    Rk54,
    JumpNeg,
    Raw,
    Register,
    Rk,
    Constant,
    Upvalue,
    Function,
    Jump,
}

impl Op {
    pub(in crate::lua) fn args(self) -> &'static [(Field, Kind)] {
        use Field::{A, B, Bx, C, SBx};
        use Kind::{Constant, Function, Jump, Raw, Register, Rk, Upvalue};
        match self {
            Self::Loadi => &[(Field::A, Kind::Register), (Field::SBx, Kind::Raw)],
            Self::Loadf => &[(Field::A, Kind::Register), (Field::SBx, Kind::Raw)],
            Self::Loadfalse => &[(Field::A, Kind::Register)],
            Self::Lfalseskip => &[(Field::A, Kind::Register)],
            Self::Loadtrue => &[(Field::A, Kind::Register)],
            Self::Gettabup54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Upvalue),
                (Field::C, Kind::Constant),
            ],
            Self::Gettable54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Geti => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Raw),
            ],
            Self::Getfield => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Settabup54 => &[
                (Field::A, Kind::Upvalue),
                (Field::B, Kind::Constant),
                (Field::C, Kind::Rk54),
            ],
            Self::Settable54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Rk54),
            ],
            Self::Seti => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Rk54),
            ],
            Self::Setfield => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Constant),
                (Field::C, Kind::Rk54),
            ],
            Self::Newtable54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Self54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Rk54),
            ],
            Self::Addi => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Signed),
            ],
            Self::Addk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Subk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Mulk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Modk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Powk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Divk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Idivk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Bandk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Bork => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Bxork => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Shri => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Signed),
            ],
            Self::Shli => &[
                (Field::A, Kind::Register),
                (Field::C, Kind::Signed),
                (Field::B, Kind::Register),
            ],
            Self::Add54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Sub54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Mul54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Mod54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Pow54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Div54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Idiv54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Band54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Bor54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Bxor54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Shl54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Shr54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Mmbin => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Raw),
            ],
            Self::Mmbini => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Signed),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Mmbink => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Constant),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Concat54 => &[(Field::A, Kind::Register), (Field::B, Kind::Raw)],
            Self::Tbc => &[(Field::A, Kind::Register)],
            Self::Jmp54 => &[(Field::SJ, Kind::Jump)],
            Self::Eq54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::K, Kind::Raw),
            ],
            Self::Lt54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::K, Kind::Raw),
            ],
            Self::Le54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::K, Kind::Raw),
            ],
            Self::Eqk => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Constant),
                (Field::K, Kind::Raw),
            ],
            Self::Eqi => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Signed),
                (Field::K, Kind::Raw),
                (Field::C, Kind::Raw),
            ],
            Self::Lti => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Signed),
                (Field::K, Kind::Raw),
                (Field::C, Kind::Raw),
            ],
            Self::Lei => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Signed),
                (Field::K, Kind::Raw),
                (Field::C, Kind::Raw),
            ],
            Self::Gti => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Signed),
                (Field::K, Kind::Raw),
                (Field::C, Kind::Raw),
            ],
            Self::Gei => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Signed),
                (Field::K, Kind::Raw),
                (Field::C, Kind::Raw),
            ],
            Self::Test54 => &[(Field::A, Kind::Register), (Field::K, Kind::Raw)],
            Self::Testset54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::K, Kind::Raw),
            ],
            Self::Tailcall54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Return54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Return0 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Return1 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Forloop54 => &[(Field::A, Kind::Register), (Field::Bx, Kind::JumpNeg)],
            Self::Forprep54 => &[(Field::A, Kind::Register), (Field::Bx, Kind::Jump)],
            Self::Tforprep54 => &[(Field::A, Kind::Register), (Field::Bx, Kind::Jump)],
            Self::Tforcall54 => &[(Field::A, Kind::Register), (Field::C, Kind::Raw)],
            Self::Tforloop54 => &[(Field::A, Kind::Register), (Field::Bx, Kind::JumpNeg)],
            Self::Setlist54 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Raw),
                (Field::C, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Vararg54 => &[(Field::A, Kind::Register), (Field::C, Kind::Raw)],
            Self::Varargprep => &[(Field::A, Kind::Raw)],
            Self::ExtraArg54 => &[(Field::Ax54, Kind::Raw)],
            Self::Newtable55 => &[
                (Field::A, Kind::Register),
                (Field::VB, Kind::Raw),
                (Field::VC, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Self55 => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Constant),
            ],
            Self::Close55 => &[(Field::A, Kind::Register), (Field::B, Kind::Raw)],
            Self::Forprep55 => &[(Field::A, Kind::Register), (Field::Bx, Kind::Jump)],
            Self::Tforprep55 => &[(Field::A, Kind::Register), (Field::Bx, Kind::Jump)],
            Self::Setlist55 => &[
                (Field::A, Kind::Register),
                (Field::VB, Kind::Raw),
                (Field::VC, Kind::Raw),
                (Field::K, Kind::Raw),
            ],
            Self::Vararg55 => &[(A, Register), (B, Register), (C, Raw), (Field::K, Raw)],
            Self::Getvarg => &[
                (Field::A, Kind::Register),
                (Field::B, Kind::Register),
                (Field::C, Kind::Register),
            ],
            Self::Errnnil => &[(Field::A, Kind::Register), (Field::Bx, Kind::Raw)],

            Self::Move | Self::LoadNil | Self::Unm | Self::Not | Self::Len | Self::Bnot => {
                &[(A, Register), (B, Register)]
            }
            Self::LoadK | Self::GetGlobal | Self::SetGlobal => &[(A, Register), (Bx, Constant)],
            Self::LoadBool | Self::NewTable | Self::Call | Self::SetList => {
                &[(A, Register), (B, Raw), (C, Raw)]
            }
            Self::GetUpval | Self::SetUpval => &[(A, Register), (B, Upvalue)],
            Self::GetTable | Self::SelfCall => &[(A, Register), (B, Register), (C, Rk)],
            Self::SetTable
            | Self::Add
            | Self::Sub
            | Self::Mul
            | Self::Div
            | Self::Mod
            | Self::Pow
            | Self::IDiv
            | Self::Band
            | Self::Bor
            | Self::Bxor
            | Self::Shl
            | Self::Shr => &[(A, Register), (B, Rk), (C, Rk)],
            Self::Concat => &[(A, Register), (B, Register), (C, Register)],
            Self::Jmp => &[(SBx, Jump)],
            Self::Eq | Self::Lt | Self::Le => &[(A, Raw), (B, Rk), (C, Rk)],
            Self::Test | Self::TForLoop => &[(A, Register), (C, Raw)],
            Self::TestSet => &[(A, Register), (B, Register), (C, Raw)],
            Self::TailCall | Self::Return | Self::Vararg => &[(A, Register), (B, Raw)],
            Self::ForLoop | Self::ForPrep => &[(A, Register), (SBx, Jump)],
            Self::Close => &[(A, Register)],
            Self::Closure => &[(A, Register), (Bx, Function)],
            Self::LoadKX => &[(A, Register)],
            Self::LoadNil52 => &[(A, Register), (B, Raw)],
            Self::GetTabUp => &[(A, Register), (B, Upvalue), (C, Rk)],
            Self::SetTabUp => &[(A, Upvalue), (B, Rk), (C, Rk)],
            Self::Jmp52 => &[(A, Raw), (SBx, Jump)],
            Self::TForCall => &[(A, Register), (C, Raw)],
            Self::TForLoop52 | Self::TForPrep50 | Self::ForLoop50 => &[(A, Register), (SBx, Jump)],
            Self::SetList52 | Self::NewTable50 => &[(A, Register), (B, Raw), (C, Raw)],
            Self::ExtraArg => &[(Field::Ax, Raw)],
            Self::Test50 => &[(A, Register), (B, Register), (C, Raw)],
            Self::TForLoop50 => &[(A, Register), (C, Raw)],
            Self::SetList50 | Self::SetListO => &[(A, Register), (Bx, Raw)],
        }
    }
}

pub(in crate::lua) fn native_field(field: Field, kind: Kind) -> crate::ir::NativeArg {
    use crate::ir::NativeArg;
    match (field, kind) {
        (Field::B, Kind::Signed) => NativeArg::SB,
        (Field::C, Kind::Signed) => NativeArg::SC,
        (Field::K, _) => NativeArg::K,
        (Field::VB, _) => NativeArg::VB,
        (Field::VC, _) => NativeArg::VC,
        (Field::SJ, _) => NativeArg::SJ,
        (Field::Ax | Field::Ax54, _) => NativeArg::Ax,
        (Field::A, _) => NativeArg::A,
        (Field::B, _) => NativeArg::B,
        (Field::C, _) => NativeArg::C,
        (Field::Bx, _) => NativeArg::Bx,
        (Field::SBx, _) => NativeArg::SBx,
    }
}
