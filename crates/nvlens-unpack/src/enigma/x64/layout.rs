// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! x64 Loader configuration projection; no template code generation.
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic as M, OpKind, Register as R};
use nvlens_io::{BinaryReader, pe::PeImage as Pe};

pub(crate) struct Runtime<'a> {
    records: Vec<&'a [u8]>,
    cancel: &'a std::sync::atomic::AtomicBool,
}
impl<'a> Runtime<'a> {
    pub(crate) fn layout(&self, image: &[u8]) -> Result<super::super::config::Layout> {
        Ok(super::super::config::Layout {
            copies: self.projection(image)?,
            machine_suffix: self.section_suffix()?,
        })
    }
    pub fn parse(image: &'a [u8], cancel: &'a std::sync::atomic::AtomicBool) -> Result<Self> {
        let pe = Pe::parse(image)?.context("Missing Loader PE")?;
        ensure!((pe.machine == 0x8664), "expected x64 runtime");
        let mut header = None;
        for i in Decoder::with_ip(
            64,
            BinaryReader::bytes_at(image, pe.entry_point as usize, 48)?,
            pe.entry_point as u64,
            DecoderOptions::NONE,
        ) {
            if i.mnemonic() == M::Mov
                && i.op0_register() == R::R8
                && matches!(i.op1_kind(), OpKind::Immediate32to64 | OpKind::Immediate64)
            {
                header = Some(i.immediate(1) as usize);
            }
            if i.mnemonic() == M::Call {
                break;
            }
        }
        let header = header.context("x64 runtime header argument missing")?;
        let table = BinaryReader::u32_le_at(image, header + 4)? as usize;
        ensure!(
            table < header && (header - table).is_multiple_of(4),
            "invalid x64 token table"
        );
        let count = (header - table) / 4;
        let mut records = Vec::new();
        for index in 0..count {
            crate::enigma::check(cancel)?;
            records.push(BinaryReader::bytes_at(
                image,
                BinaryReader::u32_le_at(image, table + index * 4)? as usize,
                88,
            )?);
        }
        Ok(Self { records, cancel })
    }
    pub fn projection(&self, image: &[u8]) -> Result<Vec<(usize, usize)>> {
        let mut groups: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut last = None;
        for index in 5..self.records.len() {
            crate::enigma::check(self.cancel)?;
            let raw = self.records[index];
            if BinaryReader::u32_le_at(raw, 0)? != 0x60 || BinaryReader::u32_le_at(raw, 16)? != 0x90
            {
                continue;
            }
            let target = BinaryReader::u64_le_at(raw, 32)?;
            if target >> 32 != 1 {
                continue;
            }
            let at = (target as u32) as usize;
            let Some(code) = image.get(at..at + 40) else {
                continue;
            };
            let decoded = Decoder::new(64, code, DecoderOptions::NONE)
                .into_iter()
                .collect::<Vec<_>>();
            if !decoded.windows(2).any(|w| {
                w[0].mnemonic() == M::Mov
                    && w[0].op0_register() == R::RAX
                    && w[0].op1_register() == R::RCX
                    && w[1].mnemonic() == M::Mov
                    && w[1].op0_register() == R::RCX
                    && w[1].op1_register() == R::RDX
            }) {
                continue;
            }
            let size = self.records[index - 5];
            let dest = self.records[index - 3];
            let len = self.records[index - 2];
            let src = self.records[index - 1];
            if BinaryReader::u32_le_at(size, 0)? != 0x52
                || BinaryReader::u32_le_at(size, 16)? != 0x8d
                || BinaryReader::u32_le_at(size, 20)? != 0x3a
                || BinaryReader::u32_le_at(size, 40)? != 0x8f
                || BinaryReader::u32_le_at(dest, 0)? != 0x51
                || BinaryReader::u32_le_at(dest, 16)? != 0x8c
                || BinaryReader::u32_le_at(dest, 20)? != 0x36
                || BinaryReader::u32_le_at(dest, 40)? != 0x8d
                || BinaryReader::u32_le_at(dest, 44)? != 0x35
                || BinaryReader::u32_le_at(len, 0)? != 0x52
                || BinaryReader::u32_le_at(len, 20)? != 0x2d
                || BinaryReader::u32_le_at(len, 40)? != 0x8d
                || BinaryReader::u64_le_at(len, 56)? != BinaryReader::u64_le_at(size, 32)?
                || BinaryReader::u32_le_at(src, 0)? != 0x52
                || BinaryReader::u32_le_at(src, 20)? != 0x37
                || BinaryReader::u32_le_at(src, 40)? != 0x8d
                || BinaryReader::u32_le_at(src, 44)? != 0x3a
            {
                continue;
            }
            let size = BinaryReader::u64_le_at(size, 56)? as usize;
            let dest = BinaryReader::u64_le_at(dest, 56)? as usize;
            if size == 0 || dest == 0 || dest.checked_add(size).is_none() {
                continue;
            }
            if last != Some(index - 8) {
                groups.push(Vec::new());
            }
            groups
                .last_mut()
                .context("Missing projection group")?
                .push((dest, size));
            last = Some(index);
        }
        groups.retain(|g| g.len() >= 3 && g.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0));
        ensure!(
            groups.len() == 1,
            "ambiguous x64 config projection: {}",
            groups.len()
        );
        groups.pop().context("Missing configuration projection")
    }
    pub fn section_suffix(&self) -> Result<usize> {
        let mut found = Vec::new();
        for index in 1..self.records.len().saturating_sub(3) {
            crate::enigma::check(self.cancel)?;
            let load = self.records[index - 1];
            let compare = self.records[index];
            let branch = self.records[index + 1];
            if BinaryReader::u32_le_at(load, 0)? != 0x52
                || BinaryReader::u32_le_at(load, 20)? != 0x35
                || BinaryReader::u32_le_at(load, 40)? != 0x8d
                || BinaryReader::u32_le_at(load, 44)? != 0
                || BinaryReader::u32_le_at(load, 52)? & 1 == 0
                || BinaryReader::u32_le_at(compare, 0)? != 0x50
                || BinaryReader::u32_le_at(compare, 16)? != 0x8d
                || BinaryReader::u32_le_at(compare, 20)? != 0x35
                || BinaryReader::u32_le_at(compare, 24)? != 0
                || (BinaryReader::u32_le_at(compare, 28)? >> 8) & 255 != 8
                || BinaryReader::u32_le_at(compare, 40)? != 0x8f
                || BinaryReader::u64_le_at(compare, 56)? != 0
                || BinaryReader::u32_le_at(branch, 0)? != 0x2c
                || BinaryReader::u32_le_at(branch, 16)? != 0x90
                || BinaryReader::u32_le_at(self.records[index + 2], 0)? != 0x232
            {
                continue;
            }
            let end = usize::try_from(BinaryReader::u64_le_at(branch, 32)?)?;
            if end <= index + 12 || end > self.records.len() {
                continue;
            }
            let append = self.records[end - 2];
            let length = self.records[end - 4];
            let source = self.records[end - 5];
            if BinaryReader::u32_le_at(append, 0)? != 0x4d
                || BinaryReader::u32_le_at(append, 16)? != 0x8d
                || BinaryReader::u32_le_at(append, 20)? != 0x3a
                || BinaryReader::u32_le_at(append, 40)? != 0x8f
                || BinaryReader::u64_le_at(append, 56)? != 16
                || BinaryReader::u32_le_at(length, 0)? != 0x52
                || BinaryReader::u32_le_at(length, 20)? != 0x2d
                || BinaryReader::u32_le_at(length, 40)? != 0x8f
                || BinaryReader::u64_le_at(length, 56)? != 16
                || BinaryReader::u32_le_at(source, 0)? != 0x51
                || BinaryReader::u32_le_at(source, 20)? != 0x37
                || BinaryReader::u32_le_at(source, 40)? != 0x8d
                || BinaryReader::u32_le_at(source, 44)? != 0x3a
                || BinaryReader::u32_le_at(self.records[end - 3], 0)? != 0x60
            {
                continue;
            }
            let digest = self.records[index + 3..end - 5].iter().any(|raw| {
                BinaryReader::u32_le_at(raw, 0).ok() == Some(0x51)
                    && BinaryReader::u32_le_at(raw, 20).ok() == Some(0x3d)
                    && BinaryReader::u32_le_at(raw, 40).ok() == Some(0x8d)
                    && BinaryReader::u32_le_at(raw, 44).ok() == Some(0x3a)
                    && BinaryReader::u64_le_at(raw, 56).ok()
                        == BinaryReader::u64_le_at(source, 56).ok()
            });
            if digest {
                found.push(usize::try_from(BinaryReader::u64_le_at(compare, 32)?)?);
            }
        }
        found.sort_unstable();
        found.dedup();
        ensure!(
            found.len() == 1,
            "cannot uniquely derive x64 machine-dependent section key guard"
        );
        Ok(found[0])
    }
}
