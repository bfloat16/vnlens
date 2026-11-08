//! Iterative PSB tagged value traversal with reference-cycle detection.
use super::read::{
    read_array_payload, read_array_with_tag, read_index, read_integer, usize_from_u32,
};
use super::{PsbHeader, PsbNumber, PsbValue, corrupt};
use nvlens_core::Result;
use nvlens_io::{BinarySourceReader, ReadAt};
use std::collections::BTreeMap;

pub(super) struct ValueParser<'a> {
    pub(super) data: &'a dyn ReadAt,
    pub(super) header: &'a PsbHeader,
    pub(super) names: &'a [String],
    pub(super) strings: &'a [String],
    pub(super) resource_count: usize,
    pub(super) extra_resource_count: usize,
}

enum ValueTask {
    Read(usize),
    List(usize),
    Object(Vec<String>),
}

impl ValueParser<'_> {
    pub(super) fn read_value(&mut self, reader: &mut BinarySourceReader<'_>) -> Result<PsbValue> {
        let mut tasks = vec![ValueTask::Read(reader.position())];
        let mut values = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                ValueTask::List(count) => {
                    let start = values
                        .len()
                        .checked_sub(count)
                        .ok_or_else(|| corrupt(0, "incomplete PSB list"))?;
                    let children = values.split_off(start);
                    values.push(PsbValue::List(children));
                    continue;
                }
                ValueTask::Object(names) => {
                    let start = values
                        .len()
                        .checked_sub(names.len())
                        .ok_or_else(|| corrupt(0, "incomplete PSB object"))?;
                    let children = values.split_off(start);
                    let mut object = BTreeMap::new();
                    for (name, child) in names.into_iter().zip(children) {
                        if object.insert(name, child).is_some() {
                            return Err(corrupt(0, "duplicate PSB object key"));
                        }
                    }
                    values.push(PsbValue::Object(object));
                    continue;
                }
                ValueTask::Read(offset) => {
                    let mut reader = BinarySourceReader::new_at(self.data, offset)?;
                    let tag = reader.read_u8()?;
                    let value = match tag {
                        0x00 | 0x01 => PsbValue::Null,
                        0x02 => PsbValue::Bool(true),
                        0x03 => PsbValue::Bool(false),
                        0x04 => PsbValue::Number(PsbNumber::Integer(0)),
                        0x05..=0x0C => PsbValue::Number(PsbNumber::Integer(read_integer(
                            &mut reader,
                            usize::from(tag - 4),
                        )?)),
                        0x0D..=0x14 => PsbValue::Array(read_array_payload(
                            &mut reader,
                            usize::from(tag - 0x0C),
                        )?),
                        0x15..=0x18 => {
                            let index = read_index(&mut reader, usize::from(tag - 0x14))?;
                            let value = self
                                .strings
                                .get(usize_from_u32(index)?)
                                .ok_or_else(|| {
                                    corrupt(offset as u64, "PSB string index out of range")
                                })?
                                .clone();
                            PsbValue::String { index, value }
                        }
                        0x19..=0x1C | 0x22..=0x25 => {
                            let is_extra = tag >= 0x22;
                            let width = usize::from(tag - if is_extra { 0x21 } else { 0x18 });
                            let index = read_index(&mut reader, width)?;
                            let count = if is_extra {
                                self.extra_resource_count
                            } else {
                                self.resource_count
                            };
                            if usize_from_u32(index)? >= count {
                                return Err(corrupt(
                                    offset as u64,
                                    "PSB resource index out of range",
                                ));
                            }
                            PsbValue::Resource { index, is_extra }
                        }
                        0x1D => PsbValue::Number(PsbNumber::Float(0.0)),
                        0x1E => PsbValue::Number(PsbNumber::Float(f32::from_bits(
                            reader.read_u32_le()?,
                        ))),
                        0x1F => PsbValue::Number(PsbNumber::Double(f64::from_bits(
                            reader.read_u64_le()?,
                        ))),
                        0x20 | 0x21 => {
                            let name_indexes = if tag == 0x21 && self.header.version != 1 {
                                Some(read_array_with_tag(&mut reader)?)
                            } else {
                                None
                            };
                            let offsets = read_array_with_tag(&mut reader)?;
                            if name_indexes
                                .as_ref()
                                .is_some_and(|names| names.len() != offsets.len())
                            {
                                return Err(corrupt(
                                    offset as u64,
                                    "PSB object name/offset count mismatch",
                                ));
                            }
                            let base = reader.position();
                            let mut names = Vec::new();
                            let mut targets = Vec::with_capacity(offsets.len());
                            for (i, relative) in offsets.iter().enumerate() {
                                // PSB container offsets are unsigned and based after their
                                // arrays, so each child strictly follows its parent.
                                let mut target =
                                    base.checked_add(usize_from_u32(*relative)?).ok_or_else(
                                        || corrupt(base as u64, "PSB child offset overflow"),
                                    )?;
                                if tag == 0x21 {
                                    let name_index = match &name_indexes {
                                        Some(indexes) => usize_from_u32(indexes[i])?,
                                        None => {
                                            let mut key_reader =
                                                BinarySourceReader::new_at(self.data, target)?;
                                            let key_tag = key_reader.read_u8()?;
                                            if !(4..=0x0C).contains(&key_tag) {
                                                return Err(corrupt(
                                                    target as u64,
                                                    "PSB v1 key tag is invalid",
                                                ));
                                            }
                                            let index = read_integer(
                                                &mut key_reader,
                                                usize::from(key_tag - 4),
                                            )?;
                                            target = key_reader.position();
                                            usize::try_from(index).map_err(|_| {
                                                corrupt(
                                                    target as u64,
                                                    "PSB v1 key index is negative or too large",
                                                )
                                            })?
                                        }
                                    };
                                    names.push(
                                        self.names
                                            .get(name_index)
                                            .ok_or_else(|| {
                                                corrupt(
                                                    target as u64,
                                                    "PSB name index out of range",
                                                )
                                            })?
                                            .clone(),
                                    );
                                }
                                targets.push(target);
                            }
                            tasks.push(if tag == 0x20 {
                                ValueTask::List(targets.len())
                            } else {
                                ValueTask::Object(names)
                            });
                            tasks.extend(targets.into_iter().rev().map(ValueTask::Read));
                            continue;
                        }
                        _ => {
                            return Err(corrupt(
                                offset as u64,
                                format!("unknown PSB object tag 0x{tag:02X}"),
                            ));
                        }
                    };
                    values.push(value);
                }
            }
        }
        values.pop().ok_or_else(|| corrupt(0, "missing PSB root"))
    }
}
