//! Decoded native Lua instruction words, roles and relative branch targets.
use super::opcode::{Field, Op};

#[derive(Debug, Clone)]
pub(super) struct Instruction {
    pub(super) pc: u32,
    pub(super) raw: u32,
    pub(super) opcode: Option<Op>,
    pub(super) fields: Fields,
    pub(super) role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Code,
    Upvalue,
    ExtraWord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Fields {
    pub(super) a: u32,
    pub(super) b: u32,
    pub(super) c: u32,
    pub(super) bx: u32,
    pub(super) sbx: i32,
}

impl Instruction {
    pub(super) fn field(&self, field: Field) -> i32 {
        match field {
            Field::K => ((self.raw >> 15) & 1) as i32,
            Field::VB => ((self.raw >> 16) & 63) as i32,
            Field::VC => (self.raw >> 22) as i32,
            Field::SJ => (self.raw >> 7) as i32 - 16777215,
            Field::Ax54 => (self.raw >> 7) as i32,
            Field::A => self.fields.a as i32,
            Field::B => self.fields.b as i32,
            Field::C => self.fields.c as i32,
            Field::Bx => self.fields.bx as i32,
            Field::SBx => self.fields.sbx,
            Field::Ax => (self.raw >> 6) as i32,
        }
    }
    pub(super) fn jump_target(&self) -> Option<i64> {
        let delta = match self.opcode {
            Some(Op::Jmp54) => Some(self.field(Field::SJ)),
            Some(Op::Forloop54 | Op::Tforloop54) => Some(-(self.fields.bx as i32)),
            Some(Op::Forprep54 | Op::Forprep55) => Some(self.fields.bx as i32 + 1),
            Some(Op::Tforprep54 | Op::Tforprep55) => Some(self.fields.bx as i32),
            _ => None,
        };
        if let Some(delta) = delta {
            return Some(i64::from(self.pc) + 1 + i64::from(delta));
        }
        if self.opcode.is_some_and(Op::has_jump) && !matches!(self.role, Role::ExtraWord) {
            Some(i64::from(self.pc) + 1 + i64::from(self.fields.sbx))
        } else {
            None
        }
    }
}
