//! CVm instruction mapping to the shared, closed IR vocabulary.
use super::{
    parse::*,
    wire::{self, Class},
};
use crate::ir::*;
use ArgName as A;
use Operation as O;
use vnlens_core::{Error, Result};

impl Parser<'_, '_> {
    pub(super) fn vm(&mut self, class: &Class, tag: u32) -> Result<(Opcode, Vec<Arg>)> {
        let schema = class.schema;
        if !(6..=17).contains(&schema) {
            return Err(Error::Unsupported(format!("RIO VM schema {schema}")));
        }
        let mut args = vec![self.u32(A::NextBranchTarget)?, self.u32(A::Flags)?];
        let flags = match args[1].value {
            Value::Unsigned(n) => n as u32,
            _ => 0,
        };
        let operation = match class.name.as_str() {
            "CVmRet" => O::ControlFlow(ControlFlowOperation::Return),
            "CVmJump" => {
                args.push(self.reference(A::Target)?);
                O::ControlFlow(ControlFlowOperation::Jump)
            }
            "CVmLabel" => {
                args.push(self.reference(A::Label)?);
                O::Data(DataOperation::SourceLocation)
            }
            "CVmCall" => {
                args.push(self.reference(A::Callee)?);
                let count = self.r.bytes.read_u16_le()?;
                let at = self.at();
                let mut values = Vec::new();
                for i in 0..count {
                    values.push(self.variant_inner(A::ValueAt(u64::from(i)), true)?);
                }
                args.push(arg(A::Arguments, at, self.at() - at, Value::Group(values)));
                O::ControlFlow(ControlFlowOperation::Call)
            }
            "CVmMsg" => {
                args.push(self.reference(A::Destination)?);
                args.push(self.text(A::Text)?);
                args.push(self.reference(A::Resource)?);
                if schema >= 13 && flags & 0x4000000 != 0 {
                    args.push(self.reference(A::Source)?);
                }
                if schema >= 15 && flags & 0x200000 != 0 {
                    let value = self.r.bytes.read_u16_le()?;
                    args.push(arg(
                        A::Mode,
                        self.at() - 2,
                        2,
                        Value::Unsigned(u64::from(value)),
                    ));
                    if value & 4 != 0 {
                        args.push(self.text(A::Name)?);
                    }
                    if value & 3 != 0 {
                        let count = self.r.bytes.read_u16_le()?;
                        for i in 0..count {
                            if value & 8 != 0 {
                                args.push(self.u16(A::Unknown(u64::from(i)))?);
                            }
                            args.push(self.reference(A::ValueAt(u64::from(i)))?);
                            if value & 3 == 3 {
                                args.push(self.reference(A::ValueAt(u64::from(i)))?);
                            }
                        }
                    }
                }
                O::Text(TextOperation::Show)
            }
            "CVmSync" => {
                args.push(self.reference(A::Target)?);
                args.push(self.number(A::Mode, if schema < 12 { 4 } else { 1 }, false)?);
                args.push(self.u32(A::Duration)?);
                O::Runtime(RuntimeOperation::Wait)
            }
            "CVmImage" => {
                args.push(self.number(A::OffsetX, 2, true)?);
                args.push(self.number(A::OffsetY, 2, true)?);
                args.push(self.u8(A::Mode)?);
                args.push(self.u8(A::Unknown(0))?);
                args.push(self.variant(A::Resource)?);
                args.push(self.variant(A::Destination)?);
                O::Image(ImageOperation::Draw)
            }
            "CVmFlagOp" => {
                if schema < 9 {
                    return Err(Error::Unsupported(format!("CVmFlagOp schema {schema}")));
                }
                args.push(self.variant(A::Left)?);
                args.push(self.variant(A::Right)?);
                args.push(self.reference(A::Target)?);
                let operator = self.u16(A::Operator)?;
                let value = match operator.value {
                    Value::Unsigned(value) => value,
                    _ => 0,
                };
                args.push(operator);
                args.push(self.u8(A::Mode)?);
                args.push(self.u32(A::EndTarget)?);
                let operation = if matches!(value, 0..=5 | 0x50) {
                    O::Storage(StorageOperation::Store)
                } else if matches!(value, 0x40..=0x47 | 0x51 | 0x52) {
                    O::ControlFlow(ControlFlowOperation::Branch)
                } else {
                    O::Runtime(RuntimeOperation::EngineCall)
                };
                let mut code = opcode(operation, tag, &class.name);
                code.variant = match value {
                    0 | 0x50 => Some(Qualifier::Assign),
                    1 => Some(Qualifier::AddAssign),
                    2 => Some(Qualifier::SubtractAssign),
                    3 => Some(Qualifier::MultiplyAssign),
                    4 => Some(Qualifier::DivideAssign),
                    5 => Some(Qualifier::RemainderAssign),
                    _ => None,
                };
                if matches!(operation, O::Storage(_)) {
                    args[2].name = A::Source;
                    args[3].name = A::Destination;
                } else if matches!(operation, O::ControlFlow(_)) {
                    // CVmFlagOp compares its second value with its first; the
                    // control mode selects external-label versus local target.
                    let comparison = match value {
                        0x41 | 0x42 | 0x51 => ControlFlowOperation::Equal,
                        0x40 | 0x43 | 0x52 => ControlFlowOperation::NotEqual,
                        0x44 => ControlFlowOperation::Greater,
                        0x45 => ControlFlowOperation::GreaterEqual,
                        0x46 => ControlFlowOperation::Less,
                        _ => ControlFlowOperation::LessEqual,
                    };
                    let left = derived(args[3].clone(), A::Left);
                    let right = if matches!(value, 0x40 | 0x41) {
                        constant(A::Right, 0)
                    } else {
                        derived(args[2].clone(), A::Right)
                    };
                    args.push(arg(
                        A::Condition,
                        self.at(),
                        0,
                        Value::Expression(vec![Token {
                            opcode: opcode(O::ControlFlow(comparison), tag, &class.name),
                            span: span(self.at(), 0),
                            args: vec![left, right],
                            raw: Vec::new(),
                        }]),
                    ));
                }
                return Ok((code, args));
            }
            "CVmSound" => {
                args.push(self.reference(A::Resource)?);
                let mode = self.number(A::Mode, if schema <= 6 { 2 } else { 1 }, false)?;
                let operation = match mode.value {
                    Value::Unsigned(2 | 4) => O::Audio(AudioOperation::Play),
                    Value::Unsigned(3) => O::Audio(AudioOperation::Stop),
                    _ => O::Audio(AudioOperation::Configure),
                };
                args.push(mode);
                let flag = self.r.bytes.read_u8()?;
                args.push(arg(
                    A::Flags,
                    self.at() - 1,
                    1,
                    Value::Unsigned(u64::from(flag)),
                ));
                if schema >= 7 {
                    args.push(self.u16(A::Unknown(0))?);
                    args.push(self.u16(A::Unknown(1))?);
                    args.push(self.u16(A::Unknown(2))?);
                    if schema >= 14 && flag & 4 != 0 {
                        if flag & 8 != 0 {
                            args.push(self.reference(A::Source)?);
                        } else {
                            for i in 0..if flag & 16 == 0 { 7 } else { 4 } {
                                args.push(self.number(A::Unknown(i), 2, true)?);
                            }
                        }
                    }
                }
                operation
            }
            "CVmGenericMsg" => {
                args.push(self.variant(A::Target)?);
                let (message, native) = self.message(A::Command)?;
                args.push(message);
                if schema >= 9 {
                    args.push(self.u16(A::Reserved)?);
                    let count = wire::count(&mut self.r.bytes)?;
                    for i in 0..count {
                        args.push(self.named_value(u64::from(i))?);
                    }
                }
                let mut code = opcode(O::Runtime(RuntimeOperation::EngineCall), tag, &class.name);
                if let Some(name) = native {
                    code.native_mnemonic = Some(name);
                }
                return Ok((code, args));
            }
            "CVmBlt" => {
                args.push(self.inline_object(A::Arguments, false)?);
                args.push(self.u16(A::Duration)?);
                args.push(self.u8(A::Mode)?);
                if schema >= 10 {
                    args.push(self.u8(A::Flags)?);
                }
                args.push(self.variant(A::Target)?);
                O::Effect(EffectOperation::Transition)
            }
            name => {
                return Err(Error::Unsupported(format!(
                    "RIO VM command {name} at 0x{:X}",
                    self.at()
                )));
            }
        };
        Ok((opcode(operation, tag, &class.name), args))
    }
}

fn derived(mut arg: Arg, name: A) -> Arg {
    arg.name = name;
    let mut pending = vec![&mut arg];
    while let Some(arg) = pending.pop() {
        arg.span.size = 0;
        match &mut arg.value {
            Value::Group(args) => pending.extend(args),
            Value::Expression(tokens) => {
                for token in tokens {
                    token.span.size = 0;
                    token.raw.clear();
                    pending.extend(&mut token.args);
                }
            }
            _ => {}
        }
    }
    arg
}
