//! PSB index nodes are read once in source order. The native object tree is
//! then assembled iteratively from those nodes without further source reads.
use super::read::{
    read_array_payload, read_array_with_tag, read_index, read_integer, usize_from_u32,
    usize_from_u64,
};
use super::{
    ParseOptions, PsbChild, PsbHeader, PsbNode, PsbNumber, PsbValue, check_cancelled, corrupt,
};
use std::collections::{BTreeMap, BTreeSet};
use vnlens_core::Result;
use vnlens_io::{BinarySourceReader, ReadAt};

pub(super) struct ValueParser<'a> {
    pub(super) data: &'a dyn ReadAt,
    pub(super) header: &'a PsbHeader,
    pub(super) names: &'a [String],
    pub(super) strings: &'a [String],
    pub(super) resource_count: usize,
    pub(super) extra_resource_count: usize,
    pub(super) nodes: BTreeMap<u64, PsbNode>,
    pub(super) options: ParseOptions<'a>,
}

enum ValueTask {
    Read(usize),
    List(usize),
    Object(Vec<String>),
}

impl ValueParser<'_> {
    pub(super) fn read_value(&mut self, reader: &mut BinarySourceReader<'_>) -> Result<PsbValue> {
        let leaves = self.read_nodes(reader.position())?;
        let mut tasks = vec![ValueTask::Read(reader.position())];
        let mut values = Vec::new();
        while let Some(task) = tasks.pop() {
            check_cancelled(self.options)?;
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
                    if let Some(value) = leaves.get(&offset) {
                        values.push(value.clone());
                        continue;
                    }
                    let node = self
                        .nodes
                        .get(&(offset as u64))
                        .ok_or_else(|| corrupt(offset as u64, "missing PSB index node"))?;
                    if node.tag == 0x20 {
                        tasks.push(ValueTask::List(node.children.len()));
                    } else {
                        let names = node
                            .children
                            .iter()
                            .map(|child| {
                                child
                                    .name_index
                                    .and_then(|index| usize::try_from(index).ok())
                                    .and_then(|index| self.names.get(index))
                                    .cloned()
                                    .ok_or_else(|| {
                                        corrupt(child.offset, "PSB name index out of range")
                                    })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        tasks.push(ValueTask::Object(names));
                    }
                    for child in node.children.iter().rev() {
                        tasks.push(ValueTask::Read(usize_from_u64(child.offset)?));
                    }
                }
            }
        }
        values.pop().ok_or_else(|| corrupt(0, "missing PSB root"))
    }

    fn read_nodes(&mut self, root: usize) -> Result<BTreeMap<usize, PsbValue>> {
        let mut pending = BTreeSet::from([root]);
        let mut leaves = BTreeMap::new();
        while let Some(offset) = pending.pop_first() {
            check_cancelled(self.options)?;
            let mut reader = BinarySourceReader::new_at(self.data, offset)?;
            let tag = reader.read_u8()?;
            let value = match tag {
                0x00 => PsbValue::Void,
                0x01 => PsbValue::Null,
                0x02 => PsbValue::Bool(true),
                0x03 => PsbValue::Bool(false),
                0x04 => PsbValue::Number(PsbNumber::Integer(0)),
                0x05..=0x0C => PsbValue::Number(PsbNumber::Integer(read_integer(
                    &mut reader,
                    usize::from(tag - 4),
                )?)),
                0x0D..=0x14 => {
                    PsbValue::Array(read_array_payload(&mut reader, usize::from(tag - 0x0C))?)
                }
                0x15..=0x18 => {
                    let index = read_index(&mut reader, usize::from(tag - 0x14))?;
                    let value = self
                        .strings
                        .get(usize_from_u32(index)?)
                        .ok_or_else(|| corrupt(offset as u64, "PSB string index out of range"))?
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
                        return Err(corrupt(offset as u64, "PSB resource index out of range"));
                    }
                    PsbValue::Resource { index, is_extra }
                }
                0x1D => PsbValue::Number(PsbNumber::Float(0.0)),
                0x1E => PsbValue::Number(PsbNumber::Float(f32::from_bits(reader.read_u32_le()?))),
                0x1F => PsbValue::Number(PsbNumber::Double(f64::from_bits(reader.read_u64_le()?))),
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
                    let mut children = Vec::with_capacity(offsets.len());
                    for (i, relative) in offsets.iter().enumerate() {
                        check_cancelled(self.options)?;
                        // PSB container offsets are unsigned and based after their
                        // arrays, so each child strictly follows its parent.
                        let mut target = base
                            .checked_add(usize_from_u64(*relative)?)
                            .ok_or_else(|| corrupt(base as u64, "PSB child offset overflow"))?;
                        let mut child = PsbChild {
                            offset: target as u64,
                            name_index: None,
                            key_offset: None,
                            key_tag: None,
                        };
                        if tag == 0x21 {
                            let name_index = match &name_indexes {
                                Some(indexes) => indexes[i],
                                None => {
                                    child.key_offset = Some(target as u64);
                                    let mut key_reader =
                                        BinarySourceReader::new_at(self.data, target)?;
                                    let key_tag = key_reader.read_u8()?;
                                    child.key_tag = Some(key_tag);
                                    // Native v1 dictionary access (0x1000BB70)
                                    // uses unsigned key tags 0x11..0x14.
                                    // Number tags are also emitted by PSB writers.
                                    let index = match key_tag {
                                        0x11..=0x14 => u64::from(read_index(
                                            &mut key_reader,
                                            usize::from(key_tag - 0x10),
                                        )?),
                                        4..=0x0c => u64::try_from(read_integer(
                                            &mut key_reader,
                                            usize::from(key_tag - 4),
                                        )?)
                                        .map_err(|_| {
                                            corrupt(target as u64, "negative PSB v1 key index")
                                        })?,
                                        _ => {
                                            return Err(corrupt(
                                                target as u64,
                                                "PSB v1 key tag is invalid",
                                            ));
                                        }
                                    };
                                    target = key_reader.position();
                                    child.offset = target as u64;
                                    index
                                }
                            };
                            child.name_index = Some(name_index);
                            self.names.get(usize_from_u64(name_index)?).ok_or_else(|| {
                                corrupt(target as u64, "PSB name index out of range")
                            })?;
                        }
                        children.push(child);
                        pending.insert(target);
                    }
                    self.nodes.insert(
                        offset as u64,
                        PsbNode {
                            offset: offset as u64,
                            size: (base - offset) as u64,
                            tag,
                            children,
                        },
                    );
                    continue;
                }
                _ => {
                    return Err(corrupt(
                        offset as u64,
                        format!("unknown PSB object tag 0x{tag:02X}"),
                    ));
                }
            };
            self.nodes.insert(
                offset as u64,
                PsbNode {
                    offset: offset as u64,
                    size: (reader.position() - offset) as u64,
                    tag,
                    children: Vec::new(),
                },
            );
            leaves.insert(offset, value);
        }
        Ok(leaves)
    }
}
