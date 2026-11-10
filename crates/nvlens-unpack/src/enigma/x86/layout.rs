// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Recover the Loader's entry references and serialized configuration projection.
use super::{
    cpu::{Image, Value},
    tokens::{BASE, Tokens},
};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic as M, OpKind, Register};
use nvlens_io::BinaryReader;

pub(super) struct Bootstrap {
    pub header: usize,
}

impl Bootstrap {
    pub fn parse(image: &[u8]) -> Result<Self> {
        let entry =
            BinaryReader::u32_le_at(image, BinaryReader::u32_le_at(image, 0x3c)? as usize + 40)?
                as usize;
        let mut decoder = Decoder::with_ip(
            32,
            image.get(entry..).context("Loader entry exceeds image")?,
            BASE as u64 + entry as u64,
            DecoderOptions::NONE,
        );
        let first = decoder.decode();
        ensure!(
            first.mnemonic() == M::Push && first.op0_kind() == OpKind::Immediate32,
            "Loader entry does not pass a token header"
        );
        let header = first.immediate32() as usize;
        for _ in 0..2 {
            let i = decoder.decode();
            ensure!(
                i.mnemonic() == M::Push && i.op0_kind() == OpKind::Memory,
                "unsupported Loader initializer argument"
            );
        }
        let initializer = decoder.decode();
        ensure!(
            initializer.mnemonic() == M::Call && initializer.op0_kind() == OpKind::NearBranch32,
            "missing Loader initializer call"
        );
        let startup = decoder
            .into_iter()
            .find(|i| i.mnemonic() == M::Call && i.op0_kind() == OpKind::NearBranch32)
            .context("missing Loader startup call")?
            .near_branch32();
        let at = startup
            .checked_sub(BASE)
            .context("Loader startup below base")? as usize;
        let mut decoder = Decoder::with_ip(
            32,
            image.get(at..).context("Loader startup exceeds image")?,
            startup as u64,
            DecoderOptions::NONE,
        );
        let mut references = None;
        while decoder.can_decode() {
            let branch = decoder.decode();
            if branch.mnemonic() != M::Jmp
                || branch.op0_kind() != OpKind::NearBranch32
                || branch.near_branch32() <= branch.next_ip32()
            {
                continue;
            }
            let mut anchors = Vec::new();
            while decoder.ip() < branch.near_branch_target() {
                let i = decoder.decode();
                ensure!(
                    !i.is_invalid() && decoder.ip() <= branch.near_branch_target(),
                    "invalid Loader startup reference block"
                );
                anchors.push(i);
            }
            if anchors.len() == 3
                && anchors
                    .iter()
                    .all(|i| i.mnemonic() == M::Call && i.op0_kind() == OpKind::NearBranch32)
                && anchors[0].near_branch32() == initializer.near_branch32()
            {
                references = Some((anchors[1].near_branch32(), anchors[2].near_branch32()));
                break;
            }
        }
        let (dispatch, trampoline) =
            references.context("Loader startup has no interpreter references")?;
        let dispatch = dispatch
            .checked_sub(BASE)
            .context("dispatcher below base")?;
        let trampoline = trampoline
            .checked_sub(BASE)
            .context("trampoline below base")?;
        let mut d = Decoder::new(
            32,
            BinaryReader::bytes_at(image, dispatch as usize, 2)?,
            DecoderOptions::NONE,
        );
        ensure!(
            d.decode().mnemonic() == M::Pushad && d.decode().mnemonic() == M::Pushfd,
            "interpreter entry does not save the machine state"
        );
        let mut d = Decoder::new(
            32,
            BinaryReader::bytes_at(image, trampoline as usize, 7)?,
            DecoderOptions::NONE,
        );
        let jump = d.decode();
        ensure!(
            jump.mnemonic() == M::Jmp
                && jump.op0_kind() == OpKind::Memory
                && jump.memory_base() == Register::None
                && jump.memory_index() == Register::None
                && d.decode().mnemonic() == M::Ret,
            "invalid template interpreter trampoline"
        );
        Ok(Self { header })
    }
}

impl Tokens<'_> {
    pub(super) fn section_suffix(&self) -> Result<usize> {
        let mut image = Image::default();
        image.add(BASE, self.image)?;
        let mut fields = Vec::new();
        for index in 2..self.records.len().saturating_sub(2) {
            crate::enigma::check(self.cancel)?;
            let compare = self.records[index];
            let branch = self.records[index + 1];
            if BinaryReader::u32_le_at(compare, 0)? != 0x50
                || BinaryReader::u32_le_at(compare, 12)? != 0x8d
                || BinaryReader::u32_le_at(compare, 16)? != 0x25
                || ((BinaryReader::u32_le_at(compare, 24)? >> 8) & 255) != 8
                || BinaryReader::u32_le_at(compare, 32)? != 0x8f
                || BinaryReader::u32_le_at(compare, 48)? != 0
                || BinaryReader::u32_le_at(branch, 0)? != 0x2c
                || (BinaryReader::u32_le_at(self.records[index + 2], 0)? != 0x232
                    && self.native_call(index + 2)?.is_none())
            {
                continue;
            }
            let end = BinaryReader::u32_le_at(branch, 28)? as usize;
            if end <= index + 8 || end > self.records.len() {
                continue;
            }
            for call in index + 8..end - 1 {
                let Some(target) = self.native_call(call)? else {
                    continue;
                };
                if !self.copy_function(target) || self.scalar(&mut image, call - 1, 1)? != Some(16)
                {
                    continue;
                }
                let digest = self.records[call - 8];
                let source = self.records[call - 4];
                if BinaryReader::u32_le_at(digest, 0)? != 0x51
                    || BinaryReader::u32_le_at(digest, 16)? != 0x26
                    || BinaryReader::u32_le_at(digest, 32)? != 0x8d
                    || BinaryReader::u32_le_at(digest, 36)? != 0x29
                    || BinaryReader::u32_le_at(source, 0)? != 0x51
                    || BinaryReader::u32_le_at(source, 16)? != 0x27
                    || BinaryReader::u32_le_at(source, 32)? != 0x8d
                    || BinaryReader::u32_le_at(source, 36)? != 0x29
                    || BinaryReader::u32_le_at(digest, 48)? != BinaryReader::u32_le_at(source, 48)?
                    || self.native_call(call - 5)?.is_none()
                {
                    continue;
                }
                let mut append = false;
                for cursor in [3, 6, 7] {
                    if self.register_offset(&mut image, call + 1, cursor)? != Some(16) {
                        continue;
                    }
                    let add = self.records[call - 2];
                    if BinaryReader::u32_le_at(add, 0)? == 0x4d {
                        append = BinaryReader::u32_le_at(add, 12)? == 0x8c
                            && BinaryReader::u32_le_at(add, 16)? == 0x25
                            && BinaryReader::u32_le_at(add, 32)? == 0x8c
                            && BinaryReader::u32_le_at(add, 36)? == 0x25 + cursor as u32;
                    } else if BinaryReader::u32_le_at(add, 0)? == 0x231 {
                        append = true;
                        for seed in [0x41000000u32, 0x57391820, 0x6b9e207c] {
                            let inputs = std::array::from_fn(|r| {
                                Value::constant(
                                    seed.wrapping_add((r as u32 + 1).wrapping_mul(0x10379)),
                                )
                            });
                            let output = self.extension_inputs(&mut image, call - 2, inputs)?;
                            append &= output[0].get()
                                == Some(
                                    inputs[0].require("Config register input")?.wrapping_add(
                                        inputs[cursor].require("Config cursor input")?,
                                    ),
                                )
                                && output[1..] == inputs[1..];
                        }
                    }
                    if append {
                        break;
                    }
                }
                if append {
                    ensure!(
                        self.source_memory(&mut image, index - 1)? == Some((0, 0, 4)),
                        "section key suffix guard does not use the Loader context"
                    );
                    fields.push(BinaryReader::u32_le_at(compare, 28)? as usize);
                }
            }
        }
        fields.sort_unstable();
        fields.dedup();
        ensure!(
            fields.len() == 1,
            "cannot uniquely derive machine-dependent section key guard"
        );
        Ok(fields[0])
    }

    fn native_call(&self, index: usize) -> Result<Option<u32>> {
        let raw = self.records[index];
        (BinaryReader::u32_le_at(raw, 0)? == 0x60 && BinaryReader::u32_le_at(raw, 12)? == 0x90)
            .then(|| BinaryReader::u32_le_at(raw, 28))
            .transpose()
            .map_err(Into::into)
    }

    fn source_memory(&self, image: &mut Image, index: usize) -> Result<Option<(usize, u32, u32)>> {
        let raw = self.records[index];
        if BinaryReader::u32_le_at(raw, 0)? == 0x231 {
            return self.extension_access(image, index);
        }
        let register = BinaryReader::u32_le_at(raw, 36)?;
        if BinaryReader::u32_le_at(raw, 32)? != 0x8d
            || !(0x25..=0x2c).contains(&register)
            || BinaryReader::u32_le_at(raw, 40)? != 0
            || BinaryReader::u32_le_at(raw, 44)? & 1 != 0
        {
            return Ok(None);
        }
        Ok(Some((
            (register - 0x25) as usize,
            BinaryReader::u32_le_at(raw, 48)?,
            ((BinaryReader::u32_le_at(raw, 44)? >> 8) & 255) / 8,
        )))
    }

    fn scalar(&self, image: &mut Image, index: usize, register: usize) -> Result<Option<u32>> {
        let raw = self.records[index];
        if BinaryReader::u32_le_at(raw, 0)? == 0x231 {
            return Ok(self.extension(image, index)?[register].get());
        }
        (BinaryReader::u32_le_at(raw, 0)? == 0x52
            && BinaryReader::u32_le_at(raw, 12)? == 0x8c
            && BinaryReader::u32_le_at(raw, 16)? == 0x25 + register as u32
            && BinaryReader::u32_le_at(raw, 32)? == 0x8f)
            .then(|| BinaryReader::u32_le_at(raw, 48))
            .transpose()
            .map_err(Into::into)
    }

    fn register_copy(
        &self,
        image: &mut Image,
        index: usize,
        dest: usize,
        source: usize,
    ) -> Result<bool> {
        let raw = self.records[index];
        if BinaryReader::u32_le_at(raw, 0)? == 0x231 {
            return Ok(self.extension(image, index)?[dest] == Value::input(100 + source as u32));
        }
        Ok(BinaryReader::u32_le_at(raw, 0)? == 0x52
            && BinaryReader::u32_le_at(raw, 12)? == 0x8c
            && BinaryReader::u32_le_at(raw, 16)? == 0x25 + dest as u32
            && BinaryReader::u32_le_at(raw, 32)? == 0x8c
            && BinaryReader::u32_le_at(raw, 36)? == 0x25 + source as u32)
    }

    fn register_offset(
        &self,
        image: &mut Image,
        index: usize,
        register: usize,
    ) -> Result<Option<u32>> {
        let raw = self.records[index];
        if BinaryReader::u32_le_at(raw, 0)? == 0x4d
            && BinaryReader::u32_le_at(raw, 12)? == 0x8c
            && BinaryReader::u32_le_at(raw, 16)? == 0x25 + register as u32
            && BinaryReader::u32_le_at(raw, 32)? == 0x8f
        {
            return Ok(Some(BinaryReader::u32_le_at(raw, 48)?));
        }
        if BinaryReader::u32_le_at(raw, 0)? != 0x231 {
            return Ok(None);
        }
        let mut offset = None;
        for seed in [0x41000000u32, 0x57391820, 0x6b9e207c] {
            let input = std::array::from_fn(|r| {
                Value::constant(seed.wrapping_add((r as u32 + 1).wrapping_mul(0x10379)))
            });
            let output = self.extension_inputs(image, index, input)?;
            let Some(value) = output[register].get() else {
                return Ok(None);
            };
            let delta = value.wrapping_sub(input[register].require("Config register input")?);
            if output
                .iter()
                .zip(input)
                .enumerate()
                .any(|(r, (out, input))| r != register && *out != input)
                || offset.is_some_and(|old| old != delta)
            {
                return Ok(None);
            }
            offset = Some(delta);
        }
        Ok(offset)
    }

    fn copy_function(&self, target: u32) -> bool {
        let Some(bytes) = self.image.get(target as usize..target as usize + 8) else {
            return false;
        };
        let mut d = Decoder::with_ip(32, bytes, BASE as u64 + target as u64, DecoderOptions::NONE);
        let exchange = d.decode();
        let call = d.decode();
        let ret = d.decode();
        if exchange.mnemonic() != M::Xchg
            || exchange.op0_register() != Register::EDX
            || exchange.op1_register() != Register::EAX
            || call.mnemonic() != M::Call
            || call.op0_kind() != OpKind::NearBranch32
            || ret.mnemonic() != M::Ret
        {
            return false;
        }
        let Some(at) = call.near_branch32().checked_sub(BASE) else {
            return false;
        };
        let Some(code) = self.image.get(at as usize..) else {
            return false;
        };
        let instructions = Decoder::new(32, code, DecoderOptions::NONE)
            .into_iter()
            .take_while(|i| i.mnemonic() != M::Ret)
            .collect::<Vec<_>>();
        instructions
            .iter()
            .any(|i| i.mnemonic() == M::Movsd && i.has_rep_prefix())
            && instructions
                .iter()
                .any(|i| i.mnemonic() == M::Movsb && i.has_rep_prefix())
    }

    /// The reader passes destination in EAX, stream pointer in EDX and size in
    /// ECX. The writer reverses the first two arguments and is not a projection.
    pub(super) fn projection(&self) -> Result<Vec<(usize, usize)>> {
        let mut image = Image::default();
        image.add(BASE, self.image)?;
        let mut wrappers = std::collections::HashMap::new();
        let mut groups: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut last = None;
        for index in 5..self.records.len() {
            crate::enigma::check(self.cancel)?;
            let raw = self.records[index];
            if BinaryReader::u32_le_at(raw, 0)? != 0x60 || BinaryReader::u32_le_at(raw, 12)? != 0x90
            {
                continue;
            }
            let target = BinaryReader::u32_le_at(raw, 28)?;
            let copy = *wrappers
                .entry(target)
                .or_insert_with(|| self.copy_function(target));
            if !copy {
                continue;
            }
            let address = self.records[index - 3];
            if !matches!(BinaryReader::u32_le_at(address, 0)?, 0x4d | 0x231) {
                continue;
            }
            let Some(size) = self.scalar(&mut image, index - 5, 3)? else {
                continue;
            };
            if size == 0 {
                continue;
            }
            if !self.register_copy(&mut image, index - 2, 1, 3)?
                || !self.register_copy(&mut image, index - 1, 2, 6)?
            {
                continue;
            }
            let Some(dest) = self.register_offset(&mut image, index - 3, 0)? else {
                continue;
            };
            if dest == 0 {
                continue;
            }
            if last.and_then(|previous: usize| previous.checked_add(7)) != Some(index) {
                groups.push(Vec::new());
            }
            groups
                .last_mut()
                .context("Missing projection group")?
                .push((dest as usize, size as usize));
            last = Some(index);
        }
        groups.retain(|g| g.len() >= 3 && g.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0));
        ensure!(
            groups.len() == 1,
            "cannot uniquely derive configuration reader: {} projections",
            groups.len()
        );
        groups.pop().context("Missing configuration projection")
    }
}
