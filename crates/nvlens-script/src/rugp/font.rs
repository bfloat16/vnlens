//! CFontAttr (UnivUI_690) and CS5RFont (UnivUI_696) serialized fields.
//! The glyph pool is a counted series of code/length/raster records; glyph
//! raster bytes remain encoded and are never interpreted as VM instructions.
use super::{parse::*, wire};
use crate::ir::*;
use ArgName as A;
use nvlens_core::Result;

impl Parser<'_, '_> {
    pub(super) fn font_fields(&mut self, schema: u16) -> Result<Vec<Arg>> {
        let mut args = Vec::new();
        for i in 0..5 {
            args.push(self.number(A::Unknown(i), 4, true)?);
        }
        for i in 0..8 {
            args.push(self.u8(A::Unknown(5 + i))?);
        }
        let at = self.at();
        let bytes = self.r.bytes.read_bytes(32)?;
        let end = bytes.iter().position(|&v| v == 0).unwrap_or(bytes.len());
        let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(&bytes[..end]);
        args.push(arg(
            A::Name,
            at,
            32,
            if errors {
                Value::Bytes(bytes.to_vec())
            } else {
                Value::Text(name.into_owned())
            },
        ));
        self.scalars(&mut args, &[4, 4, 4, 4, 2, 2, 1])?;
        let at = self.at();
        let raster = self.r.bytes.read_u8()?;
        args.push(arg(A::Enabled, at, 1, Value::Unsigned(u64::from(raster))));
        self.scalars(&mut args, &[1, 1])?;
        if schema >= 2 {
            args.push(self.u8(A::Enabled)?);
        }
        if raster != 0 {
            let start = self.at();
            let mut original = self.r.bytes.clone();
            args.extend(self.font_raster()?);
            let raw = original.read_bytes(self.at() - start)?.to_vec();
            let class = wire::Class {
                name: "CS5RFont".into(),
                schema: 1,
                encoded: None,
            };
            let data = wire::envelope(&raw, &class, 1, 20, 1)?;
            self.embedded.push(super::Embedded {
                class,
                span: span(start, raw.len()),
                raw,
                data,
            });
        }
        Ok(args)
    }

    pub(super) fn font_raster(&mut self) -> Result<Vec<Arg>> {
        let mut args = Vec::new();
        let at = self.at();
        if self.r.bytes.read_u32_le()? != 0x4652_3553 {
            return Err(wire::corrupt(at, "Invalid S5RF signature"));
        }
        let size = self.r.bytes.read_u32_le()?;
        if size < 44 {
            return Err(wire::corrupt(
                at + 4,
                "S5RF header is shorter than its fields",
            ));
        }
        args.push(arg(
            A::ByteCount,
            at + 4,
            4,
            Value::Unsigned(u64::from(size)),
        ));
        self.scalars(&mut args, &[4; 8])?;
        let at = self.at();
        let count = self.r.bytes.read_u32_le()?;
        args.push(arg(A::Count, at, 4, Value::Unsigned(u64::from(count))));
        self.scalars(&mut args, &[4, 4])?;
        if size > 44 {
            args.push(self.bytes(A::Metadata, (size - 44) as usize)?);
        }
        if count == 0 {
            return Ok(args);
        }
        let at = self.at();
        if self.r.bytes.read_u32_le()? != 0x6c6f_6f70 {
            return Err(wire::corrupt(at, "Invalid S5RF pool signature"));
        }
        let length = self.r.bytes.read_u32_le()?;
        if self.r.bytes.read_u32_le()? != !length {
            return Err(wire::corrupt(at + 8, "Invalid S5RF pool length complement"));
        }
        args.push(arg(
            A::ByteCount,
            at + 4,
            4,
            Value::Unsigned(u64::from(length)),
        ));
        let start = self.at();
        let mut rows = Vec::new();
        for i in 0..count {
            let at = self.at();
            let mut glyph = vec![self.u32(A::TextId)?];
            let length = self.r.bytes.read_u16_le()?;
            glyph.push(arg(
                A::ByteCount,
                self.at() - 2,
                2,
                Value::Unsigned(u64::from(length)),
            ));
            glyph.push(self.bytes(A::Data, usize::from(length))?);
            rows.push(arg(
                A::Row(u64::from(i)),
                at,
                self.at() - at,
                Value::Group(glyph),
            ));
        }
        if self.at() - start != length as usize {
            return Err(wire::corrupt(
                start,
                "S5RF glyph records disagree with pool length",
            ));
        }
        args.push(arg(A::Rows, start, self.at() - start, Value::Group(rows)));
        Ok(args)
    }
}
