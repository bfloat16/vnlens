//! Layouts of inline rUGP objects and media metadata referenced by scripts.
use super::{
    parse::*,
    wire::{self, Class},
};
use crate::ir::*;
use ArgName as A;
use vnlens_core::{Error, Result};

impl Parser<'_, '_> {
    pub(super) fn object_fields(&mut self, class: &Class) -> Result<Option<Vec<Arg>>> {
        let start = self.at();
        let original = self.r.bytes.clone();
        let mut args = Vec::new();
        if let Some(program) = super::fade::fields(&class.name, class.schema) {
            for width in program {
                let index = args.len() as u64;
                if width == 0 {
                    let count = self.r.bytes.read_u16_le()?;
                    args.push(arg(
                        A::Count,
                        self.at() - 2,
                        2,
                        Value::Unsigned(u64::from(count)),
                    ));
                    args.push(self.u16(A::Mode)?);
                    for role in [A::Target, A::Source, A::Destination] {
                        args.push(self.reference(role)?);
                    }
                    for i in 0..6 {
                        args.push(self.u32(A::Unknown(i))?);
                    }
                    args.push(self.bytes(A::Data, usize::from(count) * 4)?);
                } else if width == 8 {
                    args.push(self.reference(A::ValueAt(index))?);
                } else {
                    args.push(self.number(A::Unknown(index), width, false)?);
                }
            }
            return Ok(Some(args));
        }
        match class.name.as_str() {
            "CObjectOcean" | "CRio" => {}
            "CStdb" => args.push(self.text(A::Text)?),
            "CBool" | "CByte" => args.push(self.u8(A::Value)?),
            "CInt" | "CUInt" | "CLabel" => args.push(self.u32(A::Value)?),
            "CProcessOcean" => {
                let version = self.r.bytes.read_u32_le()?;
                args.push(arg(
                    A::Version,
                    self.at() - 4,
                    4,
                    Value::Unsigned(u64::from(version)),
                ));
                for role in [
                    A::Destination,
                    A::Scope,
                    A::Callee,
                    A::Variable,
                    A::Source,
                    A::Unknown(0),
                ]
                .into_iter()
                .take(match version {
                    0x1e => 1,
                    0x1f => 3,
                    0x20 => 4,
                    0x21 => 5,
                    0x22 => 6,
                    _ => {
                        return Err(Error::Unsupported(format!(
                            "CProcessOcean version {version}"
                        )));
                    }
                }) {
                    args.push(self.reference(role)?);
                }
            }
            "CBoxOcean" => {
                let target = self.reference(A::Destination)?;
                let has_target = !matches!(target.value, Value::Unsigned(0));
                args.push(target);
                if class.schema >= 8 {
                    for i in 0..2 {
                        let at = self.at();
                        let bits = self.r.bytes.read_u64_le()?;
                        args.push(arg(A::ValueAt(i), at, 8, Value::Float64Bits(bits)));
                    }
                }
                if class.schema < 3 {
                    for i in 0..32 {
                        args.push(self.reference(A::ValueAt(i))?);
                    }
                }
                if class.schema >= 2 {
                    args.push(self.reference(A::Resource)?);
                    let count = if class.schema < 6 {
                        1
                    } else if class.schema < 7 {
                        12
                    } else {
                        32
                    };
                    for i in 0..count {
                        args.push(self.reference(A::ValueAt(i))?);
                    }
                    if class.schema >= 7 {
                        for i in 0..32 {
                            args.push(self.text(A::StringAt(i))?);
                        }
                    }
                    args.push(self.reference(A::Target)?);
                    if class.schema >= 4 && has_target {
                        self.ui_refs(&mut args)?;
                        if class.schema >= 5 {
                            let ui = self.reference(A::Source)?;
                            let has_ui = !matches!(ui.value, Value::Unsigned(0));
                            args.push(ui);
                            if has_ui {
                                self.ui_refs(&mut args)?;
                            }
                        }
                    }
                }
            }
            "CCommandRef" => {
                args.push(self.reference(A::Callee)?);
                args.push(self.u32(A::LabelId)?);
            }
            "CPmBgm" | "CPmEffect" => {
                args.push(self.u16(A::Version)?);
                args.push(self.reference(A::Resource)?);
                args.push(self.text(A::Name)?);
                args.push(self.u16(A::Flags)?);
            }
            "CSinpleSequence" => {
                args.push(self.text(A::Name)?);
                args.push(self.u16(A::Mode)?);
                args.push(self.u16(A::Flags)?);
                args.push(self.reference(A::Target)?);
                args.push(self.u8(A::Version)?);
                let name = self.data_type()?;
                args.push(arg(A::ValueType, self.at(), 0, Value::Text(name.clone())));
                let count = wire::count(&mut self.r.bytes)?;
                for i in 0..count {
                    if name == "CSbm" {
                        args.push(self.reference(A::ValueAt(u64::from(i)))?);
                    } else {
                        let field = self
                            .definitions
                            .values()
                            .flat_map(|d| &d.fields)
                            .find(|f| f.native_type == name)
                            .ok_or_else(|| {
                                Error::UnknownScheme(Some(format!("RIO sequence element {name}")))
                            })?;
                        args.push(self.native_field(field, A::ValueAt(u64::from(i)))?);
                    }
                }
            }
            "CRmt" => {
                for name in match class.schema {
                    1 | 2 => &["CRip008", "CRimp"][..],
                    3 => &["CRmti", "CRimp"][..],
                    _ => &["CRmti", "CRimp", "Cr6Ti"][..],
                } {
                    let schema = if class.schema == 1 {
                        1
                    } else {
                        self.r.bytes.read_u16_le()?
                    };
                    self.r.map_class(Class {
                        name: (*name).into(),
                        schema,
                        encoded: None,
                    });
                }
                let version = self.r.bytes.read_u16_le()?;
                args.push(arg(
                    A::Version,
                    self.at() - 2,
                    2,
                    Value::Unsigned(u64::from(version)),
                ));
                args.push(self.number(A::Width, 2, true)?);
                args.push(self.number(A::Height, 2, true)?);
                if version != 0 {
                    args.push(self.u32(A::Flags)?);
                    if version >= 4 {
                        if version >= 5 {
                            args.push(self.u32(A::Unknown(0))?);
                            args.push(self.u32(A::Unknown(1))?);
                        }
                        args.push(self.u8(A::Mode)?);
                        args.push(self.u16(A::Unknown(2))?);
                        if version >= 7 {
                            args.push(self.u32(A::Unknown(3))?);
                        }
                    }
                }
                args.push(self.reference(A::Resource)?);
                let layers = self.r.bytes.read_u8()?;
                args.push(arg(
                    A::Count,
                    self.at() - 1,
                    1,
                    Value::Unsigned(u64::from(layers)),
                ));
                // The serialized loop is explicitly min(layer byte, 6).
                for i in 0..layers.min(6) {
                    args.push(self.reference(A::ValueAt(u64::from(i)))?);
                }
                if version >= 2 {
                    if version >= 6 {
                        args.push(self.reference(A::Source)?);
                    }
                    args.push(self.u8(A::Unknown(4))?);
                    if version >= 3 {
                        self.object_array(&mut args)?;
                    }
                    if version >= 8 {
                        args.push(self.u16(A::Unknown(5))?);
                        for i in 0..9 {
                            args.push(self.u32(A::Unknown(6 + i))?);
                        }
                        args.push(self.reference(A::Target)?);
                        self.object_array(&mut args)?;
                    }
                }
            }
            "CAcsPos" => {
                for i in 0..6 {
                    args.push(self.u32(A::Unknown(i))?);
                }
                args.push(self.u16(A::Unknown(6))?);
                args.push(self.u16(A::Unknown(7))?);
                if class.schema >= 2 {
                    args.push(self.u32(A::Unknown(8))?);
                }
            }
            "CMN_Time_2G" => {
                args.push(self.u32(A::EasingParameter)?);
            }
            "CMN_Time_Bezier" => {
                let count = self.r.bytes.read_u16_le()?;
                for i in 0..u64::from(count) * 6 {
                    args.push(self.u32(A::ValueAt(i))?);
                }
            }
            "CRmti" => {
                args.push(self.u16(A::Width)?);
                args.push(self.u16(A::Height)?);
                for i in 0..4 {
                    args.push(self.u8(A::Unknown(i))?);
                }
                let length = self.r.bytes.read_u32_le()? as usize;
                args.push(self.u32(A::Unknown(4))?);
                args.push(self.u16(A::Unknown(5))?);
                args.push(self.bytes(A::Data, length)?);
            }
            "CSbm" => {
                args.push(self.u32(A::Version)?);
                args.push(self.u16(A::Width)?);
                args.push(self.u16(A::Height)?);
                args.push(self.u32(A::Unknown(0))?);
                let length = self.r.bytes.read_u32_le()?;
                args.push(arg(
                    A::ByteCount,
                    self.at() - 4,
                    4,
                    Value::Unsigned(u64::from(length)),
                ));
                args.push(self.bytes(A::Data, length as usize)?);
            }
            "CRip" | "CRip007" | "CRip008" => {
                args.push(self.u32(A::Version)?);
                let roles = if class.name == "CRip" {
                    [
                        A::OffsetX,
                        A::OffsetY,
                        A::Width,
                        A::Height,
                        A::Width,
                        A::Height,
                    ]
                } else {
                    [
                        A::Width,
                        A::Height,
                        A::OffsetX,
                        A::OffsetY,
                        A::Width,
                        A::Height,
                    ]
                };
                for role in roles {
                    args.push(self.u16(role)?);
                }
                args.push(self.u32(A::Flags)?);
                let widths = match class.name.as_str() {
                    "CRip" => &[][..],
                    "CRip007" => &[1; 7][..],
                    _ if class.schema < 2 => &[1; 7][..],
                    _ => &[1; 4][..],
                };
                self.scalars(&mut args, widths)?;
                if (class.name == "CRip007" && class.schema >= 2)
                    || (class.name == "CRip008" && class.schema >= 3)
                {
                    args.push(self.reference(A::Resource)?);
                }
                let length = self.r.bytes.read_u32_le()?;
                args.push(arg(
                    A::ByteCount,
                    self.at() - 4,
                    4,
                    Value::Unsigned(u64::from(length)),
                ));
                args.push(self.u32(A::Unknown(0))?);
                args.push(self.bytes(A::Data, length as usize)?);
            }
            "Cr6Ti" => {
                args.push(self.u32(A::Flags)?);
                for role in [
                    A::Width,
                    A::Height,
                    A::OffsetX,
                    A::OffsetY,
                    A::Width,
                    A::Height,
                ] {
                    args.push(self.u16(role)?);
                }
                args.push(self.u32(A::Mode)?);
                args.push(self.bytes(A::Metadata, if class.schema < 2 { 4 } else { 7 })?);
                args.push(self.reference(A::Resource)?);
                let length = self.r.bytes.read_u32_le()? as usize;
                if class.schema >= 3 {
                    args.push(self.u32(A::Unknown(0))?);
                }
                args.push(self.u32(A::Unknown(1))?);
                args.push(self.bytes(A::Data, length.div_ceil(2) * 2 + 2)?);
            }
            "Cr6Tix" => {
                args.push(self.u8(A::Version)?);
                let count = self.count_field(&mut args)?;
                for i in 0..count {
                    args.push(self.text(A::StringAt(u64::from(i)))?);
                    args.push(self.u32(A::ValueAt(u64::from(i)))?);
                }
                let image = Class {
                    name: "Cr6Ti".into(),
                    schema: class.schema,
                    encoded: None,
                };
                let image_start = self.at() as u64;
                if let Some(fields) = self.object_fields(&image)? {
                    args.extend(fields);
                }
                // The Cr6Ti base is part of this image, not a nested object.
                self.embedded
                    .retain(|item| item.span.offset != image_start || item.class.name != "Cr6Ti");
            }
            "CPostureMoment" => {
                args.push(self.u8(A::Mode)?);
                let mode = if class.schema >= 3 {
                    let mode = self.r.bytes.read_u8()?;
                    args.push(arg(
                        A::Version,
                        self.at() - 1,
                        1,
                        Value::Unsigned(u64::from(mode)),
                    ));
                    args.push(self.u8(A::Flags)?);
                    mode
                } else {
                    0
                };
                for i in 0..5 {
                    args.push(self.reference(A::ValueAt(i))?);
                }
                for i in 0..3 {
                    args.push(self.u32(A::Unknown(i))?);
                }
                for i in 0..if mode < 3 { 1 } else { 2 } {
                    args.push(self.u32(A::Unknown(3 + i))?);
                }
                let floats = if mode < 4 {
                    if class.schema >= 4 || mode != 0 {
                        if mode >= 2 { 9 } else { 6 }
                    } else {
                        0
                    }
                } else {
                    let present = self.r.bytes.read_u8()?;
                    args.push(arg(
                        A::Enabled,
                        self.at() - 1,
                        1,
                        Value::Unsigned(u64::from(present)),
                    ));
                    if present != 0 { 18 } else { 0 }
                };
                for i in 0..floats {
                    args.push(self.u32(A::Unknown(5 + i))?);
                }
                args.push(self.u16(A::Unknown(23))?);
                args.push(self.u16(A::Unknown(24))?);
                if mode >= 2 {
                    args.push(self.u16(A::Unknown(25))?);
                }
                if class.schema >= 2 {
                    for i in 0..3 {
                        args.push(self.u32(A::Unknown(26 + i))?);
                    }
                }
                if mode >= 5 {
                    args.push(self.text(A::Name)?);
                }
            }
            "CMoveAcsOngen" => {
                for i in 0..3 {
                    args.push(self.u32(A::Unknown(i))?);
                }
                let start = self.at();
                let mut frames = Vec::new();
                loop {
                    let at = self.at();
                    let kind = self.r.bytes.read_u8()?;
                    if kind == 0x70 {
                        break;
                    }
                    if !matches!(kind, 2 | 3) {
                        return Err(wire::corrupt(at, "Unknown RIO sound-motion key type"));
                    }
                    let flags = self.r.bytes.read_u8()?;
                    let mut frame = vec![
                        arg(A::Type, at, 1, Value::Unsigned(u64::from(kind))),
                        arg(A::Flags, at + 1, 1, Value::Unsigned(u64::from(flags))),
                        self.u32(A::Duration)?,
                    ];
                    let dimensions = if flags & 1 != 0 { 3 } else { 2 };
                    for i in 0..dimensions {
                        frame.push(self.u32(A::ValueAt(i))?);
                    }
                    if kind == 3 {
                        let count = self.r.bytes.read_u16_le()?;
                        for i in 0..u64::from(count) * dimensions {
                            frame.push(self.u32(A::ValueAt(i))?);
                        }
                    }
                    if kind == 2 || flags & 2 != 0 {
                        frame.push(self.inline_object(A::Command, true)?);
                    }
                    frames.push(arg(
                        A::Row(frames.len() as u64),
                        at,
                        self.at() - at,
                        Value::Group(frame),
                    ));
                }
                args.push(arg(
                    A::Frames,
                    start,
                    self.at() - start,
                    Value::Group(frames),
                ));
                if class.schema >= 2 {
                    args.push(self.u32(A::StartTime)?);
                    args.push(self.u32(A::Duration)?);
                }
                if class.schema >= 3 {
                    args.push(self.u32(A::Unknown(3))?);
                    args.push(self.u8(A::Mode)?);
                    args.push(self.u16(A::Flags)?);
                }
            }
            "CDcAgesModelQsT" => {
                let mode = self.r.bytes.read_u8()?;
                args.push(arg(
                    A::Mode,
                    self.at() - 1,
                    1,
                    Value::Unsigned(u64::from(mode)),
                ));
                args.push(self.u32(A::Version)?);
                if mode != 0 {
                    for i in 0..3 {
                        args.push(self.u32(A::Unknown(i))?);
                    }
                }
                for i in 0..2 {
                    let length = self.r.bytes.read_u32_le()?;
                    args.push(self.bytes(A::ValueAt(i), length as usize)?);
                }
                let count = wire::count(&mut self.r.bytes)?;
                let at = self.at();
                let mut rows = Vec::new();
                for i in 0..count {
                    let start = self.at();
                    let mut values = vec![self.reference(A::Resource)?, self.u32(A::Color)?];
                    for j in 0..4 {
                        values.push(self.u32(A::Unknown(j))?);
                    }
                    rows.push(arg(
                        A::Row(u64::from(i)),
                        start,
                        self.at() - start,
                        Value::Group(values),
                    ));
                }
                args.push(arg(A::Rows, at, self.at() - at, Value::Group(rows)));
                args.push(self.reference(A::Resource)?);
            }
            _ => return self.structure_fields(class),
        }
        if matches!(
            class.name.as_str(),
            "Cr6Ti" | "CRmti" | "CSbm" | "CRip008" | "CRip007" | "CRip"
        ) {
            let mut original = original;
            let raw = original.read_bytes(self.at() - start)?.to_vec();
            let mut body = raw.clone();
            if class.name == "Cr6Ti"
                || (class.name == "CRip008" && class.schema >= 3)
                || (class.name == "CRip007" && class.schema >= 2)
            {
                let at = 20
                    + if class.name == "CRip007" {
                        7
                    } else if class.name == "CRip008" || class.schema < 2 {
                        4
                    } else {
                        7
                    };
                // Inline images share the parent's reference table. A null
                // attachment needs an explicit empty prelude when exported.
                let null = args
                    .iter()
                    .find(|a| a.name == A::Resource)
                    .is_some_and(|a| matches!(a.value, Value::Unsigned(0)));
                if null {
                    body.insert(at, 0);
                } else {
                    return Ok(Some(args));
                }
            }
            let data = wire::envelope(&body, class, class.schema, 0x14, 1)?;
            self.embedded.push(super::Embedded {
                class: class.clone(),
                span: span(start, raw.len()),
                raw,
                data,
            });
        }
        Ok(Some(args))
    }

    pub(super) fn ui_refs(&mut self, args: &mut Vec<Arg>) -> Result<()> {
        loop {
            let marker = self.u8(A::Flags)?;
            let more = !matches!(marker.value, Value::Unsigned(0));
            args.push(marker);
            if !more {
                return Ok(());
            }
            args.push(self.reference(A::Resource)?);
        }
    }
    pub(super) fn object_array(&mut self, args: &mut Vec<Arg>) -> Result<()> {
        for i in 0..wire::count(&mut self.r.bytes)? {
            args.push(self.inline_object(A::ValueAt(u64::from(i)), false)?);
        }
        Ok(())
    }
}
