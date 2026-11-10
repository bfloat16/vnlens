// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Static recovery of the Delphi token VM and serialized template VM.
//! No Loader instruction, target process or host API is executed.
use super::super::config::Layout;
use super::cpu::{self, Action, Image, State, Value};
use anyhow::{Context, Result, ensure};
use iced_x86::{Mnemonic, OpKind};
use nvlens_io::BinaryReader;

pub const BASE: u32 = 0x400000;
const STATE: u32 = 0x12000000;
const STACK: u32 = 0x20080000;
const STOP: u32 = 0x30000000;

pub(crate) fn layout(image: &[u8], cancel: &std::sync::atomic::AtomicBool) -> Result<Layout> {
    let tokens = Tokens::parse(image, cancel)?;
    Ok(Layout {
        copies: tokens.projection()?,
        machine_suffix: tokens.section_suffix()?,
    })
}

pub struct Tokens<'a> {
    pub(super) cancel: &'a std::sync::atomic::AtomicBool,
    pub records: Vec<&'a [u8]>,
    pub(super) image: &'a [u8],
}
impl<'a> Tokens<'a> {
    pub fn parse(image: &'a [u8], cancel: &'a std::sync::atomic::AtomicBool) -> Result<Self> {
        let bootstrap = super::layout::Bootstrap::parse(image)?;
        let header = bootstrap.header;
        let table = BinaryReader::u32_le_at(image, header + 4)? as usize;
        ensure!(
            header > table && (header - table).is_multiple_of(4),
            "invalid VM token table"
        );
        let count = (header - table) / 4;
        let mut records = Vec::with_capacity(count);
        for i in 0..count {
            crate::enigma::check(cancel)?;
            records.push(BinaryReader::bytes_at(
                image,
                BinaryReader::u32_le_at(image, table + i * 4)? as usize,
                72,
            )?);
        }
        Ok(Self {
            cancel,
            records,
            image,
        })
    }

    /// Analyze a variable-length 0x231 native callback with the interpreter's
    /// actual register-state / index / payload arguments. No native execution.
    pub(super) fn extension(&self, image: &mut Image, index: usize) -> Result<[Value; 8]> {
        self.extension_inputs(
            image,
            index,
            std::array::from_fn(|r| {
                if r == 4 {
                    Value::constant(STACK - 0x10000)
                } else {
                    Value::input(100 + r as u32)
                }
            }),
        )
    }
    pub(super) fn extension_inputs(
        &self,
        image: &mut Image,
        index: usize,
        inputs: [Value; 8],
    ) -> Result<[Value; 8]> {
        let s = self.extension_state(image, index, inputs)?;
        let mut result: Option<[Value; 8]> = None;
        cpu::analyze(image, s, |im, s| {
            crate::enigma::check(self.cancel)?;
            if s.pc != STOP {
                return Ok(Action::Decode);
            }
            ensure!(
                s.registers[0].get() == Some(index as u32 + 1),
                "extension is not a sequential config operation"
            );
            let registers = std::array::from_fn(|r| s.read(im, STATE + r as u32 * 4, 4));
            if let Some(previous) = result {
                ensure!(
                    previous == registers,
                    "ambiguous extension config operation"
                );
            }
            result = Some(registers);
            Ok(Action::Finish)
        })?;
        result.context("extension did not return")
    }

    fn extension_state(&self, image: &Image, index: usize, inputs: [Value; 8]) -> Result<State> {
        let raw = self.records[index];
        ensure!(
            BinaryReader::u32_le_at(raw, 0)? == 0x231,
            "not a native token extension"
        );
        // The Image uses the original Loader mapping; recover this record's
        // address through the entry table instead of treating payload as x86.
        let at = raw.as_ptr() as usize - self.image.as_ptr() as usize;
        let target = BASE
            .checked_add(BinaryReader::u32_le_at(raw, 4)?)
            .context("extension target overflow")?;
        let mut s = State::new(target, STACK);
        s.exact_memory = true;
        let flags = if inputs.iter().all(|v| v.get().is_some()) {
            Value::constant(0x202)
        } else {
            Value::unknown_flags()
        };
        s.flags = flags;
        s.registers[0] = Value::constant(BASE);
        s.registers[1] = Value::constant(STATE);
        s.registers[2] = Value::constant(BASE);
        s.registers[3] = Value::constant(target);
        for (i, v) in [STOP, index as u32, BASE + at as u32 + 8]
            .into_iter()
            .enumerate()
        {
            s.write(image, STACK + i as u32 * 4, 4, Value::constant(v));
        }
        for (r, value) in inputs.into_iter().enumerate() {
            s.write(image, STATE + r as u32 * 4, 4, value);
        }
        s.write(image, STATE + 0x50, 4, flags);
        Ok(s)
    }

    /// Follow the callback until it dereferences one of the virtual register
    /// inputs. Internal interpreter state and native stack accesses are excluded.
    pub(super) fn extension_access(
        &self,
        image: &mut Image,
        index: usize,
    ) -> Result<Option<(usize, u32, u32)>> {
        let inputs = std::array::from_fn(|r| Value::constant(0x41080000 + r as u32 * 0x100000));
        let state = self.extension_state(image, index, inputs)?;
        let mut access = None;
        cpu::analyze(image, state, |image, state| {
            crate::enigma::check(self.cancel)?;
            if state.pc == STOP {
                return Ok(Action::Finish);
            }
            let i = image.instruction(state.pc)?;
            if i.mnemonic() != Mnemonic::Lea
                && (0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory)
                && let Some(address) = cpu::address(state, &i)?.get()
                && (0x41000000..0x41800000).contains(&address)
            {
                let register = ((address - 0x41000000) / 0x100000) as usize;
                let found = (
                    register,
                    address.wrapping_sub(inputs[register].require("Config register input")?),
                    i.memory_size().size() as u32,
                );
                ensure!(
                    access.is_none_or(|old| old == found),
                    "ambiguous extension memory operand"
                );
                access = Some(found);
                return Ok(Action::Finish);
            }
            Ok(Action::Decode)
        })?;
        Ok(access)
    }
}
