//! CRsa bytecode and CPmArchive values. VM layouts follow Vm60's serializers
//! 1002F610/1002FB30 and CVm*::Serialize (100786D0 onwards). Runtime message
//! fields come from the host's PE descriptors, never from guessed lengths.
use super::wire::{self, Class, Object, Reader, Reference};
use crate::ir::*;
use ArgName as A;
use Operation as O;
use serde::Deserialize;
use std::collections::BTreeMap;
use vnlens_core::{ArchiveOptions, Error, Result};
use vnlens_io::{BinaryReader, Endian};

#[derive(Debug, Deserialize)]
pub(super) struct Field {
    pub(super) name: String,
    #[serde(rename = "type")]
    pub(super) code: u32,
    pub(super) size: usize,
    pub(super) native_type: String,
}
#[derive(Debug, Deserialize)]
pub(super) struct Definition {
    pub(super) schema: u16,
    pub(super) fields: Vec<Field>,
}

pub(super) fn span(at: usize, size: usize) -> Span {
    Span {
        offset: at as u64,
        size: size as u64,
    }
}
pub(super) fn arg(name: A, at: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(at, size),
        value,
        attributes: Vec::new(),
    }
}
pub(super) fn constant(name: A, value: u64) -> Arg {
    arg(name, 0, 0, Value::Unsigned(value))
}
pub(super) fn opcode(operation: O, code: u32, name: &str) -> Opcode {
    Opcode {
        operation,
        variant: None,
        namespace: "rugp.vm".into(),
        code,
        native_mnemonic: Some(name.into()),
    }
}
fn record(at: usize, size: usize, name: &str, args: Vec<Arg>) -> Instruction {
    let mut opcode = opcode(O::Data(DataOperation::Record), 0, name);
    opcode.variant = Some(Qualifier::Configuration);
    Instruction {
        id: 0,
        span: span(at, size),
        source_line: None,
        opcode,
        args,
        attributes: Vec::new(),
    }
}

#[derive(Debug)]
pub struct Parsed {
    pub script: Script,
    pub objects: Vec<Object>,
    pub embedded: Vec<super::Embedded>,
}

pub(super) struct Parser<'a, 'b> {
    pub(super) r: Reader<'a>,
    pub(super) base: usize,
    pub(super) definitions: &'b BTreeMap<String, Definition>,
    pub(super) embedded: Vec<super::Embedded>,
}

impl Parser<'_, '_> {
    pub(super) fn at(&self) -> usize {
        self.base + self.r.bytes.position()
    }
    pub(super) fn number(&mut self, name: A, width: u8, signed: bool) -> Result<Arg> {
        let at = self.at();
        let value = if signed {
            Value::Integer(self.r.bytes.read_compact_i64(width, Endian::Little)?)
        } else {
            Value::Unsigned(self.r.bytes.read_compact_u64(width, Endian::Little)?)
        };
        Ok(arg(name, at, usize::from(width), value))
    }
    pub(super) fn u8(&mut self, name: A) -> Result<Arg> {
        self.number(name, 1, false)
    }
    pub(super) fn u16(&mut self, name: A) -> Result<Arg> {
        self.number(name, 2, false)
    }
    pub(super) fn u32(&mut self, name: A) -> Result<Arg> {
        self.number(name, 4, false)
    }
    pub(super) fn text(&mut self, name: A) -> Result<Arg> {
        let at = self.at();
        let (wide, bytes) = self.r.bytes.read_mfc_string()?;
        let value = if wide {
            let mut r = BinaryReader::new(bytes);
            let mut units = Vec::new();
            while r.remaining() != 0 {
                units.push(r.read_u16_le()?);
            }
            String::from_utf16(&units)
                .map(Value::Text)
                .unwrap_or_else(|_| Value::Bytes(bytes.to_vec()))
        } else {
            let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
            if errors {
                Value::Bytes(bytes.to_vec())
            } else {
                Value::Text(text.into_owned())
            }
        };
        Ok(arg(name, at, self.at() - at, value))
    }
    pub(super) fn bytes(&mut self, name: A, size: usize) -> Result<Arg> {
        let at = self.at();
        Ok(arg(
            name,
            at,
            size,
            Value::Bytes(self.r.bytes.read_bytes(size)?.to_vec()),
        ))
    }

    pub(super) fn reference(&mut self, name: A) -> Result<Arg> {
        let at = self.at();
        let reference = self.r.reference()?;
        let value = match reference {
            Reference::Existing(id) => Value::Unsigned(u64::from(id)),
            Reference::External(object) => Value::Group(vec![
                arg(A::Resource, at, 0, Value::Text(super::object_name(&object))),
                constant(A::Version, u64::from(object.class.schema)),
                constant(A::Flags, u64::from(object.flags)),
                constant(A::DataOffset, u64::from(object.offset)),
                constant(A::ByteCount, u64::from(object.size)),
            ]),
            Reference::Inline(class, flags) => {
                let start = self.at();
                let mut fields = vec![
                    constant(A::Version, u64::from(class.schema)),
                    constant(A::Flags, u64::from(flags)),
                ];
                fields.extend(self.object_fields(&class)?.ok_or_else(|| {
                    wire::corrupt(start, &format!("Unknown inline RIO class {}", class.name))
                })?);
                Value::Expression(vec![Token {
                    opcode: opcode(O::Storage(StorageOperation::Reference), 0, &class.name),
                    span: span(start, self.at() - start),
                    args: fields,
                    raw: Vec::new(),
                }])
            }
        };
        Ok(arg(name, at, self.at() - at, value))
    }

    pub(super) fn inline_object(&mut self, name: A, plain: bool) -> Result<Arg> {
        let at = self.at();
        let encrypted = self.r.encrypted;
        if plain {
            self.r.encrypted = false;
        }
        let (class, tag) = self.r.class()?;
        self.r.encrypted = encrypted;
        let value = if let Some(class) = class {
            self.r.map_object();
            let fields = self.object_fields(&class)?.ok_or_else(|| {
                wire::corrupt(at, &format!("Unknown inline RIO class {}", class.name))
            })?;
            Value::Expression(vec![Token {
                opcode: opcode(O::Data(DataOperation::Record), tag, &class.name),
                span: span(at, self.at() - at),
                args: fields,
                raw: Vec::new(),
            }])
        } else {
            Value::Unsigned(u64::from(tag))
        };
        Ok(arg(name, at, self.at() - at, value))
    }

    pub(super) fn variant(&mut self, name: A) -> Result<Arg> {
        self.variant_inner(name, false)
    }
    pub(super) fn variant_inner(&mut self, name: A, extended: bool) -> Result<Arg> {
        let at = self.at();
        let tag = self.r.bytes.read_u32_le()?;
        let value = if extended && tag == 4 {
            let native_type = self.data_type()?;
            if matches!(native_type.as_str(), "ロングベクトル" | "点") {
                let mut values = vec![arg(A::Type, at, 4, Value::Unsigned(u64::from(tag)))];
                for i in 0..if native_type == "点" { 2 } else { 3 } {
                    values.push(self.number(A::ValueAt(i), 4, true)?);
                }
                let mut value = arg(name, at, self.at() - at, Value::Group(values));
                value.native_name = Some(native_type);
                return Ok(value);
            }
            let field = self
                .definitions
                .values()
                .flat_map(|d| &d.fields)
                .find(|f| f.native_type == native_type)
                .ok_or_else(|| {
                    Error::UnknownScheme(Some(format!("RIO native value type {native_type}")))
                })?;
            self.native_field(field, A::Value)?
        } else {
            match tag & 3 {
                0 => self.reference(A::Value)?,
                1 => self.text(A::Value)?,
                2 => arg(
                    A::Value,
                    at,
                    0,
                    Value::Integer(i64::from((tag as i32) >> 2)),
                ),
                _ => {
                    let mut fields = vec![self.u32(A::Type)?];
                    if matches!(fields[0].value, Value::Unsigned(0x137)) {
                        fields.push(self.u32(A::Value)?);
                    }
                    arg(A::Value, at + 4, self.at() - at - 4, Value::Group(fields))
                }
            }
        };
        Ok(arg(
            name,
            at,
            self.at() - at,
            Value::Group(vec![
                arg(A::Type, at, 4, Value::Unsigned(u64::from(tag))),
                value,
            ]),
        ))
    }

    pub(super) fn data_type(&mut self) -> Result<String> {
        match self.r.bytes.read_u16_le()? {
            0x1e57 => Ok(self
                .r
                .class()?
                .0
                .ok_or_else(|| wire::corrupt(self.at(), "Missing RIO value class"))?
                .name),
            0x2d6b | 0x2f1a => {
                self.r.bytes.read_u16_le()?;
                let length = usize::from(self.r.bytes.read_u16_le()?);
                let bytes = self.r.bytes.read_bytes(length)?;
                let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
                if errors {
                    return Err(wire::corrupt(self.at(), "Invalid RIO type name"));
                }
                Ok(name.into_owned())
            }
            0x369e => self
                .message_class()?
                .0
                .map(|c| c.name)
                .ok_or_else(|| wire::corrupt(self.at(), "Missing RIO message type")),
            value => Err(Error::Unsupported(format!("RIO type tag 0x{value:04X}"))),
        }
    }

    pub(super) fn named_value(&mut self, index: u64) -> Result<Arg> {
        let at = self.at();
        let data_type = self.data_type()?;
        let word = self.r.bytes.read_u16_le()?;
        let tag = if word == 0x7fff {
            self.r.bytes.read_u32_le()?
        } else {
            u32::from(word & 0x7fff) | (u32::from(word & 0x8000) << 16)
        };
        let field = if word == 0xffff {
            let length = usize::from(self.r.bytes.read_u16_le()?);
            let bytes = self.r.bytes.read_bytes(length)?;
            let (&marker, name) = bytes
                .split_first()
                .ok_or_else(|| wire::corrupt(at, "Empty RIO parameter descriptor"))?;
            let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(name);
            if errors {
                return Err(wire::corrupt(at, "Invalid RIO parameter name"));
            }
            let field = Class {
                name: name.into_owned(),
                schema: u16::from(marker),
                encoded: None,
            };
            self.r.map_class(field.clone());
            field
        } else {
            self.r.cached_class(tag)?
        };
        let value = self.variant(A::Value)?;
        let mut result = arg(
            A::NamedArgument(index),
            at,
            self.at() - at,
            Value::Group(vec![
                arg(A::ValueType, at, 0, Value::Text(data_type)),
                constant(A::Flags, u64::from(field.schema)),
                value,
            ]),
        );
        result.native_name = Some(field.name);
        Ok(result)
    }

    pub(super) fn native_field(&mut self, field: &Field, name: A) -> Result<Arg> {
        let at = self.at();
        let code = field.code & 0x7fff_ffff;
        let mut value = if code & 0x70000000 >= 0x60000000 {
            self.reference(name)?
        } else {
            match code {
                0x10000000 => self.text(name)?,
                0x1b000000 => self.variant(name)?,
                0x18000000 => {
                    let bits = self.r.bytes.read_u32_le()?;
                    arg(name, at, 4, Value::Float32Bits(bits))
                }
                0x19000000 => {
                    let bits = self.r.bytes.read_u64_le()?;
                    arg(name, at, 8, Value::Float64Bits(bits))
                }
                0x1a000000 if field.native_type == "色" => self.u32(name)?,
                0x11000000 | 0x12000000 | 0x13000000 | 0x14000000 | 0x15000000 | 0x16000000
                | 0x17000000 => {
                    let width = u8::try_from(field.size)
                        .map_err(|_| wire::corrupt(at, "RIO scalar width exceeds its encoding"))?;
                    self.number(
                        name,
                        width,
                        matches!(code, 0x12000000 | 0x14000000 | 0x16000000),
                    )?
                }
                _ => {
                    return Err(Error::Unsupported(format!(
                        "RIO field serializer {} (0x{code:08X}) at 0x{at:X}",
                        field.native_type
                    )));
                }
            }
        };
        value.native_name = Some(field.name.clone());
        value.attributes.push(Attribute {
            name: "native_type".into(),
            value: u64::from(field.code),
        });
        Ok(value)
    }

    pub(super) fn message_class(&mut self) -> Result<(Option<Class>, u32)> {
        let word = self.r.bytes.read_u16_le()?;
        let tag = if word == 0x7fff {
            self.r.bytes.read_u32_le()?
        } else {
            u32::from(word & 0x7fff) | (u32::from(word & 0x8000) << 16)
        };
        if tag & 0x80000000 == 0 {
            return Ok((None, tag));
        }
        let class = if word == 0xffff {
            let schema = u16::from(self.r.bytes.read_u8()?);
            let mut len = usize::from(self.r.bytes.read_u8()?);
            if len == 255 {
                len = usize::from(self.r.bytes.read_u16_le()?);
            }
            let bytes = self.r.bytes.read_bytes(len)?;
            let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
            if errors {
                return Err(wire::corrupt(self.at(), "Invalid RIO message name"));
            }
            let class = Class {
                name: text.trim_end_matches('\0').into(),
                schema,
                encoded: None,
            };
            self.r.map_class(class.clone());
            class
        } else {
            self.r.cached_class(tag)?
        };
        Ok((Some(class), tag))
    }

    pub(super) fn message(&mut self, name: A) -> Result<(Arg, Option<String>)> {
        let at = self.at();
        let (class, tag) = self.message_class()?;
        let Some(class) = class else {
            return Ok((
                arg(name, at, self.at() - at, Value::Unsigned(u64::from(tag))),
                None,
            ));
        };
        self.r.map_object();
        let definition = self.definitions.get(&class.name).ok_or_else(|| {
            Error::UnknownScheme(Some(format!(
                "Missing rUGP message definition: {}",
                class.name
            )))
        })?;
        if definition.schema != class.schema {
            return Err(Error::Unsupported(format!(
                "RIO message schema {} for {}",
                class.schema, class.name
            )));
        }
        let mut args = vec![
            arg(A::Name, at, 0, Value::Text(class.name.clone())),
            constant(A::Version, u64::from(class.schema)),
        ];
        for (i, field) in definition.fields.iter().enumerate() {
            args.push(self.native_field(field, A::ValueAt(i as u64))?);
        }
        Ok((
            arg(name, at, self.at() - at, Value::Group(args)),
            Some(class.name),
        ))
    }
}

pub(super) fn parse(data: &[u8], options: &ArchiveOptions) -> Result<Parsed> {
    let definitions: BTreeMap<String, Definition> =
        if let Some(key) = options.keys.get("rugp_messages") {
            serde_json::from_slice(key.bytes())
                .map_err(|e| Error::Unsupported(format!("Invalid rUGP message descriptors: {e}")))?
        } else {
            BTreeMap::new()
        };
    let mut r = Reader::new(data, false);
    let (signature, version, _, class) = r.header()?;
    let mut objects = if matches!(
        signature,
        wire::ENCRYPTED_SIGNATURE | wire::RIO_SIGNATURE | wire::ICI_SIGNATURE
    ) {
        r.children()?
            .into_iter()
            .filter(|object| object.parent.is_none())
            .collect()
    } else {
        Vec::new()
    };
    if class.name != "CrelicUnitedGameProject" {
        r.map_object();
    }
    let mut body = r.bytes.position();
    let mut sections = vec![Section {
        name: "resource".into(),
        span: span(0, data.len()),
        raw: data.to_vec(),
    }];
    let mut instructions = vec![record(
        0,
        body,
        &class.name,
        vec![
            constant(A::Version, u64::from(class.schema)),
            arg(A::Name, 0, 0, Value::Text(class.name.clone())),
        ],
    )];
    let project = if class.name == "CrelicUnitedGameProject" && class.schema >= 4 {
        Some(vnlens_crypto::cipher::rugp::decrypt_chunk(
            &mut r.bytes,
            0x7e6b_8ce2,
        )?)
    } else {
        None
    };
    let base = if let Some(data) = &project {
        body = sections[0].raw.len();
        sections.push(Section {
            name: "project".into(),
            span: span(body, data.len()),
            raw: data.clone(),
        });
        r = r.with_data(data);
        body
    } else {
        0
    };
    let mut p = Parser {
        r,
        base,
        definitions: &definitions,
        embedded: Vec::new(),
    };
    let mut embedded = Vec::new();
    if class.name == "CRsa" {
        let marker = p.r.bytes.read_u16_le()?;
        let mut metadata = vec![
            arg(A::Type, body, 2, Value::Unsigned(u64::from(marker))),
            p.u16(A::Flags)?,
            p.u8(A::Unknown(0))?,
        ];
        if class.schema >= 5 {
            metadata.push(p.u32(A::Unknown(1))?);
        }
        let start = p.at();
        let decoded = if marker == 0x36e {
            vnlens_crypto::cipher::rugp::decrypt_chunk(&mut p.r.bytes, 0x7e6b_8ce2).map_err(
                |e| {
                    if e.kind() == std::io::ErrorKind::InvalidInput {
                        wire::corrupt(start, &e.to_string())
                    } else {
                        e.into()
                    }
                },
            )?
        } else {
            let len = p.r.bytes.read_u32_le()?;
            p.r.bytes.read_bytes(len as usize)?.to_vec()
        };
        // The IR resource is the decoded stream; the original compact/cipher
        // bytes remain available through the archive's raw extraction path.
        sections = vec![
            Section {
                name: "header".into(),
                span: span(0, start),
                raw: data[..start].to_vec(),
            },
            Section {
                name: "bytecode".into(),
                span: span(start, decoded.len()),
                raw: decoded.clone(),
            },
        ];
        let mut vm = Parser {
            r: Reader::new(&decoded, true),
            base: start,
            definitions: &definitions,
            embedded: Vec::new(),
        };
        metadata.push(vm.u16(A::Version)?);
        metadata.push(vm.u16(A::Flags)?);
        let first = vm.r.bytes.read_u32_le()?;
        if first >= 0xffff0000 {
            metadata.push(vm.u32(A::Version)?);
            metadata.push(vm.u32(A::ByteCount)?);
        } else {
            metadata.push(constant(A::ByteCount, u64::from(first)));
        }
        let count = vm.r.bytes.read_u32_le()?;
        metadata.push(arg(
            A::Count,
            vm.at() - 4,
            4,
            Value::Unsigned(u64::from(count)),
        ));
        metadata.push(vm.u32(A::MaximumVariableId)?);
        instructions.push(record(body, vm.at() - body, "CRsa", metadata));
        for _ in 0..count {
            let at = vm.at();
            let (class, tag) = vm.r.class()?;
            let class = class.ok_or_else(|| wire::corrupt(at, "Missing RIO instruction class"))?;
            let (opcode, args) = vm.vm(&class, tag).map_err(|e| match e {
                Error::Corrupt { offset, reason } => Error::Corrupt {
                    offset,
                    reason: format!("{} at 0x{at:X}: {reason}", class.name),
                },
                error => error,
            })?;
            instructions.push(Instruction {
                id: instructions.len() as u64,
                span: span(at, vm.at() - at),
                source_line: None,
                opcode,
                args,
                attributes: vec![Attribute {
                    name: "schema".into(),
                    value: u64::from(class.schema),
                }],
            });
        }
        if vm.r.bytes.remaining() != 0 {
            instructions.push(record(
                vm.at(),
                vm.r.bytes.remaining(),
                "CRsa tail",
                vec![vm.bytes(A::Data, vm.r.bytes.remaining())?],
            ));
        }
        objects.extend(vm.r.objects);
        embedded.extend(vm.embedded);
    } else {
        let fields = if p.r.bytes.remaining() != 0 {
            p.object_fields(&class)?.unwrap_or_default()
        } else {
            Vec::new()
        };
        if p.at() != body {
            instructions.push(record(body, p.at() - body, &class.name, fields));
        }
        if p.r.bytes.remaining() != 0 {
            // UnivUI::sub_1000BC80 returns immediately after the class's
            // Serialize call. These verified serializers consume their final
            // fields before the indexed storage extent ends; keep the unused
            // bytes explicitly instead of inventing extra object fields.
            let unused = matches!(
                (class.name.as_str(), class.schema),
                ("CMoveAcsOngen", 3) | ("CRmt", 4)
            );
            instructions.push(record(
                p.at(),
                p.r.bytes.remaining(),
                if unused {
                    "RIO storage tail"
                } else {
                    &class.name
                },
                vec![p.bytes(
                    if unused { A::Padding } else { A::Data },
                    p.r.bytes.remaining(),
                )?],
            ));
        }
        objects.extend(p.r.objects);
        embedded.extend(p.embedded);
    }
    // A top-level image is already a resource. Only nested image bodies
    // belong in its child list, otherwise expansion invents a duplicate.
    embedded.retain(|item| item.span.offset != body as u64 || item.class.name != class.name);
    for (i, instruction) in instructions.iter_mut().enumerate() {
        instruction.id = i as u64;
    }
    Ok(Parsed {
        script: Script {
            ir_version: VERSION,
            format: "object/rugp".into(),
            format_version: u32::from(version),
            sections,
            instructions,
        },
        objects,
        embedded,
    })
}

#[cfg(test)]
#[path = "../../tests/rugp/parse.rs"]
mod tests;
