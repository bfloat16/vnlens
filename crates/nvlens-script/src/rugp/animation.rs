//! CRsi frame index from rvmm::Serialize (10058580/10058280). Frame
//! offsets are relative to the payload following the complete index.
use super::{parse::*, wire};
use crate::ir::*;
use ArgName as A;
use nvlens_core::Result;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct Animation {
    pub width: u16,
    pub height: u16,
    pub frames: Vec<AnimationFrame>,
}

#[derive(Debug)]
pub struct AnimationFrame {
    pub span: Span,
    pub mode: u8,
    pub flags: u16,
    pub threshold: u16,
}

/// Reads the shared geometry and per-frame codec parameters, without decoding
/// pixels. Offsets refer to the original compact object's bytes.
pub fn animation_index(data: &[u8]) -> Result<Animation> {
    let mut r = wire::Reader::new(data, true);
    wire::compact_header(&mut r.bytes)?;
    let definitions = BTreeMap::new();
    let mut parser = Parser {
        r,
        base: 0,
        definitions: &definitions,
        embedded: Vec::new(),
    };
    Ok(parser.animation_fields()?.1)
}

impl Parser<'_, '_> {
    pub(super) fn animation_fields(&mut self) -> Result<(Vec<Arg>, Animation)> {
        let mut args = Vec::new();
        args.push(self.u16(A::Version)?);
        self.scalars(&mut args, &[1, 1, 4])?;
        let at = self.at();
        let width = self.r.bytes.read_u16_le()?;
        let height = self.r.bytes.read_u16_le()?;
        args.push(arg(A::Width, at, 2, Value::Unsigned(u64::from(width))));
        args.push(arg(
            A::Height,
            at + 2,
            2,
            Value::Unsigned(u64::from(height)),
        ));
        self.scalars(&mut args, &[4, 2])?;
        let count = self.count_field(&mut args)?;
        let start = self.at();
        let mut rows = Vec::new();
        let mut extents = Vec::new();
        for i in 0..count {
            let at = self.at();
            let mode = self.r.bytes.read_u8()?;
            let mut fields = vec![arg(A::Mode, at, 1, Value::Unsigned(u64::from(mode)))];
            let offset = self.r.bytes.read_u32_le()?;
            fields.push(arg(
                A::DataOffset,
                self.at() - 4,
                4,
                Value::Unsigned(u64::from(offset)),
            ));
            fields.push(self.u16(A::Duration)?);
            let flags = self.r.bytes.read_u16_le()?;
            fields.push(arg(
                A::Flags,
                self.at() - 2,
                2,
                Value::Unsigned(u64::from(flags)),
            ));
            let threshold = if flags & 0x1c00 == 0x400 {
                let at = self.at();
                let value = self.r.bytes.read_u16_le()?;
                fields.push(arg(A::Unknown(0), at, 2, Value::Unsigned(u64::from(value))));
                value
            } else {
                0
            };
            let length = self.r.bytes.read_u32_le()?;
            fields.push(arg(
                A::ByteCount,
                self.at() - 4,
                4,
                Value::Unsigned(u64::from(length)),
            ));
            extents.push((offset, length, mode, flags, threshold));
            rows.push(arg(
                A::Row(u64::from(i)),
                at,
                self.at() - at,
                Value::Group(fields),
            ));
        }
        let data_start = self.at();
        let mut frames = Vec::new();
        let payload = self.r.bytes.read_bytes(self.r.bytes.remaining())?;
        for (row, (offset, length, mode, flags, threshold)) in rows.iter_mut().zip(extents) {
            let end = u64::from(offset) + u64::from(length);
            if end > payload.len() as u64 {
                return Err(wire::corrupt(
                    data_start,
                    "CRsi frame exceeds its data section",
                ));
            }
            frames.push(AnimationFrame {
                span: span(data_start + offset as usize, length as usize),
                mode,
                flags,
                threshold,
            });
            if let Value::Group(fields) = &mut row.value {
                fields.push(arg(
                    A::Data,
                    data_start + offset as usize,
                    0,
                    Value::DataAddress(data_start as u64 + u64::from(offset)),
                ));
            }
        }
        args.push(arg(
            A::Frames,
            start,
            data_start - start,
            Value::Group(rows),
        ));
        Ok((
            args,
            Animation {
                width,
                height,
                frames,
            },
        ))
    }
}

#[cfg(test)]
#[path = "../../tests/rugp/animation.rs"]
mod tests;
