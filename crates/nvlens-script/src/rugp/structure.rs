//! Object layouts from UnivUI::Serialize and Vm60/rvmm virtual Serialize
//! slots. Collection counts are MFC ReadCount; references share the enclosing
//! CPmArchive class/object table. Scalar slots retain their original widths.
use super::{
    parse::*,
    wire::{self, Class},
};
use crate::ir::*;
use ArgName as A;
use nvlens_core::{Error, Result};

impl Parser<'_, '_> {
    pub(super) fn scalars(&mut self, args: &mut Vec<Arg>, widths: &[u8]) -> Result<()> {
        for &width in widths {
            args.push(self.number(A::Unknown(args.len() as u64), width, false)?);
        }
        Ok(())
    }

    pub(super) fn count_field(&mut self, args: &mut Vec<Arg>) -> Result<u32> {
        let start = self.at();
        let count = wire::count(&mut self.r.bytes)?;
        args.push(arg(
            A::Count,
            start,
            self.at() - start,
            Value::Unsigned(u64::from(count)),
        ));
        Ok(count)
    }

    fn reference_list(&mut self, args: &mut Vec<Arg>) -> Result<()> {
        let count = self.count_field(args)?;
        for i in 0..count {
            args.push(self.reference(A::ValueAt(u64::from(i)))?);
        }
        Ok(())
    }

    fn box_fields(&mut self, args: &mut Vec<Arg>, schema: u16) -> Result<()> {
        self.scalars(args, &[2, 2, 4, 1])?;
        // Five native RECT/POINT pairs, each stored as four signed shorts.
        for i in 0..5 {
            let at = self.at();
            let mut values = Vec::new();
            for role in [A::OffsetX, A::OffsetY, A::Width, A::Height] {
                values.push(self.number(role, 2, true)?);
            }
            args.push(arg(A::ValueAt(i), at, self.at() - at, Value::Group(values)));
        }
        args.push(self.text(A::Name)?);
        if (6..9).contains(&schema) {
            for i in 0..if schema >= 7 { 5 } else { 4 } {
                args.push(self.reference(A::ValueAt(i))?);
            }
        }
        self.reference_list(args)?;
        self.scalars(args, &[2, 2, 4, 4, 4, 4])?;
        for role in [A::OffsetX, A::OffsetY, A::Width, A::Height] {
            args.push(self.number(role, 2, true)?);
        }
        self.scalars(args, &[2, 2])?;
        if schema >= 4 {
            args.push(self.reference(A::Target)?);
        }
        if schema >= 16 {
            for i in 0..3 {
                args.push(self.reference(A::ValueAt(i))?);
            }
        }
        Ok(())
    }

    fn image_box_fields(&mut self, args: &mut Vec<Arg>, schema: u16) -> Result<()> {
        self.box_fields(args, schema)?;
        if schema >= 5 {
            args.push(self.u8(A::Mode)?);
        }
        if schema < 3 {
            return Err(Error::Unsupported("RIO legacy image-box payload".into()));
        }
        Ok(())
    }

    fn message_box_fields(&mut self, args: &mut Vec<Arg>, schema: u16) -> Result<()> {
        self.box_fields(args, schema)?;
        let at = self.at();
        let version = self.r.bytes.read_u32_le()?;
        args.push(arg(A::Version, at, 4, Value::Unsigned(u64::from(version))));
        if !(0x120..=0x123).contains(&version) {
            return Err(wire::corrupt(at, "Invalid RIO text-box version"));
        }
        self.scalars(args, &[2, 1])?;
        if version > 0x121 {
            args.push(self.reference(A::Resource)?);
        }
        if version > 0x122 {
            args.push(self.reference(A::Target)?);
            self.scalars(args, &[4])?;
            self.reference_list(args)?;
        }
        if schema >= 14 {
            let at = self.at();
            let mode = self.r.bytes.read_u8()?;
            args.push(arg(A::Version, at, 1, Value::Unsigned(u64::from(mode))));
            args.push(self.u32(A::Flags)?);
            if mode >= 3 {
                args.push(self.u32(A::Color)?);
                args.push(self.reference(A::Resource)?);
                self.scalars(args, &[2, 4, 4])?;
                args.push(self.reference(A::Resource)?);
                let at = self.at();
                let present = self.r.bytes.read_u8()?;
                args.push(arg(A::Enabled, at, 1, Value::Unsigned(u64::from(present))));
                if present != 0 {
                    self.scalars(args, &[1, 4, 4, 4])?;
                    args.push(self.reference(A::Source)?);
                    args.push(self.reference(A::Destination)?);
                }
            }
            if mode >= 2 {
                self.scalars(args, &[1, 1, 1, 2, 2, 2, 2])?;
            }
        }
        Ok(())
    }

    pub(super) fn structure_fields(&mut self, class: &Class) -> Result<Option<Vec<Arg>>> {
        let mut args = Vec::new();
        match class.name.as_str() {
            "CrelicUnitedGameProject" => {
                let at = self.at();
                let version = self.r.bytes.read_u32_le()?;
                args.push(arg(A::Version, at, 4, Value::Unsigned(u64::from(version))));
                if version < 0x24 {
                    return Err(Error::Unsupported(format!("RIO project version {version}")));
                }
                for i in 0..6 {
                    args.push(self.reference(A::ValueAt(i))?);
                }
                for (minimum, i) in [(0x25, 6), (0x26, 7), (0x27, 8), (0x29, 9)] {
                    if version >= minimum {
                        args.push(self.reference(A::ValueAt(i))?);
                    }
                }
                let at = self.at();
                let metadata_version = self.r.bytes.read_u32_le()?;
                args.push(arg(
                    A::Version,
                    at,
                    4,
                    Value::Unsigned(u64::from(metadata_version)),
                ));
                if metadata_version >= 2 {
                    args.push(self.text(A::Name)?);
                }
                for i in 0..4 {
                    args.push(self.text(A::StringAt(i))?);
                }
                args.push(self.u32(A::Flags)?);
                if metadata_version != 0 {
                    if metadata_version >= 2 {
                        self.scalars(&mut args, &[2, 2, 2, 2, 2, 2, 2, 2, 4])?;
                    }
                    for i in 4..6 {
                        args.push(self.text(A::StringAt(i))?);
                    }
                    if metadata_version >= 3 {
                        args.push(self.text(A::StringAt(6))?);
                    }
                    if metadata_version >= 4 {
                        args.push(self.text(A::StringAt(7))?);
                        args.push(self.u32(A::Flags)?);
                    }
                    if metadata_version >= 5 {
                        args.push(self.u32(A::Mode)?);
                    }
                    if metadata_version >= 6 {
                        for i in 8..11 {
                            args.push(self.text(A::StringAt(i))?);
                        }
                    }
                }
                if version >= 0x28 {
                    args.push(self.reference(A::Resource)?);
                }
            }
            "CFontAttr" => args = self.font_fields(class.schema)?,
            "CS5RFont" => args = self.font_raster()?,
            "CVmVarObj" => args.push(self.variant(A::Value)?),
            "CCharVoiceRegistOb" => {
                args.push(self.text(A::Name)?);
                args.push(self.u32(A::Value)?);
            }
            "CCharVoiceOcean" => {
                args.push(self.reference(A::Source)?);
                if class.schema >= 2 {
                    args.push(self.reference(A::Destination)?);
                }
                if class.schema >= 3 {
                    self.scalars(&mut args, &[1, 1, 2])?;
                }
            }
            "CNormalCamera" => self.scalars(&mut args, &[4; 9])?,
            "CMimeFlat16LimitOne" => self.scalars(&mut args, &[2; 17])?,
            "CWaitableTimer" => {
                args.push(self.u8(A::Mode)?);
                args.push(self.u32(A::StartTime)?);
                args.push(self.u32(A::Duration)?);
            }
            "CKiminozoEffectManager" | "CGenericUso" => {}
            "CBox" => self.box_fields(&mut args, class.schema)?,
            "CImgBox" | "CImgAreaBox" => self.image_box_fields(&mut args, class.schema)?,
            "CFrameBuffer" => {
                self.image_box_fields(&mut args, class.schema)?;
                args.push(self.inline_object(A::Resource, true)?);
                if class.schema >= 10 {
                    args.push(self.reference(A::Source)?);
                }
            }
            "CCharBox" | "CCharBox2" => {
                self.image_box_fields(&mut args, class.schema)?;
                if class.schema >= 8 {
                    args.push(self.reference(A::Resource)?);
                }
                if class.schema >= 11 {
                    self.scalars(&mut args, &[4, 4])?;
                }
                if class.schema >= 15 {
                    self.scalars(&mut args, &[1, 1, 2, 2, 4, 4])?;
                }
            }
            "CParseBgBox" => {
                self.image_box_fields(&mut args, class.schema)?;
                if class.schema >= 12 {
                    let at = self.at();
                    let version = self.r.bytes.read_u16_le()?;
                    args.push(arg(A::Version, at, 2, Value::Unsigned(u64::from(version))));
                    if version >= 2 {
                        args.push(self.reference(A::Resource)?);
                    }
                }
            }
            "CMessBox" | "CMsgSelBox" | "CFloatingRedirectMessBox" => {
                self.message_box_fields(&mut args, class.schema)?
            }
            "CVideoSeq" if class.schema >= 2 => {
                args.push(self.reference(A::Resource)?);
                args.push(self.reference(A::Target)?);
                self.scalars(&mut args, &[2, 2, 2, 2, 4, 4, 4, 4])?;
                if class.schema >= 3 {
                    self.scalars(&mut args, &[4, 4, 4])?;
                }
                if class.schema >= 4 {
                    args.push(self.u8(A::Mode)?);
                }
            }
            "CVideoSeq" => {}
            "CTextStaffrollSeq" => {
                args.push(self.reference(A::Resource)?);
                args.push(self.reference(A::Target)?);
                self.scalars(&mut args, &[2, 2, 2, 2, 4, 4, 4])?;
                if class.schema >= 2 {
                    self.scalars(&mut args, &[4, 4])?;
                }
                self.scalars(&mut args, &[4, 4])?;
            }
            "CFlashLayerEffect" if class.schema > 1 => {
                args.push(self.reference(A::Target)?);
                self.scalars(
                    &mut args,
                    &[4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 4, 4, 4, 4, 4, 4, 4, 2, 2, 4],
                )?;
                for _ in 0..3 {
                    args.push(self.u32(A::Color)?);
                }
                self.scalars(&mut args, &[4, 4, 4])?;
            }
            "CFlashLayerEffect" => {}
            "CLayerSimpleFlush" => {
                args.push(self.reference(A::Target)?);
                args.push(self.u32(A::Color)?);
                self.scalars(&mut args, &[4; 5])?;
                if class.schema >= 2 {
                    self.scalars(&mut args, &[4])?;
                    args.push(self.u32(A::Color)?);
                    if class.schema >= 4 {
                        self.scalars(&mut args, &[4])?;
                    }
                    self.scalars(&mut args, &[4; 8])?;
                    args.push(self.reference(A::Resource)?);
                }
                if class.schema >= 3 {
                    self.scalars(&mut args, &[2, 2])?;
                }
            }
            "CMenuAvatar" => {
                let at = self.at();
                let version = self.r.bytes.read_u16_le()?;
                args.push(arg(A::Version, at, 2, Value::Unsigned(u64::from(version))));
                self.scalars(&mut args, &[2, 4, 4])?;
                args.push(self.text(A::Name)?);
                args.push(self.reference(A::Resource)?);
                if version >= 2 {
                    for i in 0..3 {
                        args.push(self.reference(A::ValueAt(i))?);
                    }
                }
            }
            "CRbx" => {
                args.push(self.u32(A::Flags)?);
                args.push(self.reference(A::Resource)?);
                args.push(self.reference(A::Source)?);
                let count = self.count_field(&mut args)?;
                for i in 0..count {
                    args.push(self.inline_object(A::ValueAt(u64::from(i)), false)?);
                }
                let bitmap = Class {
                    name: "CSbm".into(),
                    schema: 1,
                    encoded: None,
                };
                if let Some(fields) = self.object_fields(&bitmap)? {
                    args.extend(fields);
                }
            }
            "CRsi" => args = self.animation_fields()?.0,
            "CImgSel" => {
                self.scalars(&mut args, &[4, 4, 4])?;
                for i in 0..4 {
                    args.push(self.reference(A::ValueAt(i))?);
                }
                args.push(self.text(A::Name)?);
                args.push(self.u16(A::Flags)?);
                if class.schema >= 2 {
                    self.scalars(&mut args, &[2, 2, 2, 2])?;
                }
            }
            "CBg2d" => {
                let names: &[&str] = if class.schema == 1 {
                    &["CRip008", "CRimp"]
                } else if class.schema < 5 {
                    &["CRip008"]
                } else if class.schema == 5 {
                    &["CRip008", "Cr6Ti"]
                } else {
                    &["Cr6Ti"]
                };
                for &name in names {
                    let schema = if class.schema == 1 {
                        1
                    } else {
                        self.r.bytes.read_u16_le()?
                    };
                    self.r.map_class(Class {
                        name: name.into(),
                        schema,
                        encoded: None,
                    });
                }
                args.push(self.u16(A::Version)?);
                args.push(self.number(A::Width, 2, true)?);
                args.push(self.number(A::Height, 2, true)?);
                self.scalars(&mut args, &[2, 4, 2, 4, 4, 4])?;
                if class.schema >= 4 {
                    let at = self.at();
                    let flags = self.r.bytes.read_u32_le()?;
                    args.push(arg(A::Flags, at, 4, Value::Unsigned(u64::from(flags))));
                    if flags & 2 != 0 {
                        self.scalars(&mut args, &[2, 2, 2])?;
                    }
                    if flags & 8 != 0 {
                        self.scalars(&mut args, &[2])?;
                    }
                    if flags & 4 != 0 {
                        self.scalars(&mut args, &[4, 4, 4])?;
                    }
                }
                let count = self.count_field(&mut args)?;
                let start = self.at();
                let mut rows = Vec::new();
                for i in 0..count {
                    let at = self.at();
                    let mut fields = Vec::new();
                    self.scalars(&mut fields, &[4, 4, 4])?;
                    fields.push(self.reference(A::Resource)?);
                    rows.push(arg(
                        A::Row(u64::from(i)),
                        at,
                        self.at() - at,
                        Value::Group(fields),
                    ));
                }
                args.push(arg(A::Rows, start, self.at() - start, Value::Group(rows)));
                if class.schema >= 3 {
                    let at = self.at();
                    let present = self.r.bytes.read_u8()?;
                    args.push(arg(A::Enabled, at, 1, Value::Unsigned(u64::from(present))));
                    if present != 0 {
                        args.push(self.reference(A::Resource)?);
                    }
                }
                if class.schema >= 6 {
                    self.scalars(&mut args, &[1, 4, 2, 2, 4, 4, 4])?;
                    args.push(self.inline_object(A::Command, false)?);
                    self.scalars(&mut args, &[4])?;
                }
            }
            "CBg2dLayerParam" | "CBg2dLayerRip007Image" => {
                if class.name == "CBg2dLayerRip007Image" {
                    self.scalars(&mut args, &[2, 2, 4, 4, 4, 4, 4, 4, 4])?;
                    args.push(self.reference(A::Resource)?);
                }
                args.push(self.inline_object(A::Source, false)?);
                args.push(self.text(A::Name)?);
                self.scalars(&mut args, &[2, 1, 1, 4, 4, 4, 4])?;
            }
            "CLayoutTextImg" => {
                let at = self.at();
                let version = self.r.bytes.read_u16_le()?;
                args.push(arg(A::Version, at, 2, Value::Unsigned(u64::from(version))));
                self.scalars(&mut args, &[4, 4, 4])?;
                if version >= 2 {
                    args.push(self.text(A::Name)?);
                    args.push(self.text(A::Text)?);
                    self.scalars(&mut args, &[4, 4])?;
                }
                self.scalars(&mut args, &[4, 4, 4, 4, 4, 4, 4])?;
                args.push(self.text(A::Text)?);
                args.push(self.u8(A::Version)?);
                let name = self.data_type()?;
                let count = self.count_field(&mut args)?;
                if name == "CSbm" {
                    for i in 0..count {
                        args.push(self.reference(A::ValueAt(u64::from(i)))?);
                    }
                } else if count != 0 {
                    return Err(Error::Unsupported(format!(
                        "RIO text layout element {name}"
                    )));
                }
            }
            "CRimp" => {
                let count = self.count_field(&mut args)?;
                for i in 0..count {
                    let at = self.at();
                    let mut fields = vec![self.text(A::Name)?];
                    fields.push(if class.schema > 2 {
                        self.variant_inner(A::Value, true)?
                    } else {
                        self.u32(A::Value)?
                    });
                    args.push(arg(
                        A::Row(u64::from(i)),
                        at,
                        self.at() - at,
                        Value::Group(fields),
                    ));
                }
                if class.schema >= 4 {
                    self.reference_list(&mut args)?;
                    args.push(self.reference(A::Resource)?);
                    args.push(self.text(A::Name)?);
                }
            }
            _ => return Ok(None),
        }
        Ok(Some(args))
    }
}
