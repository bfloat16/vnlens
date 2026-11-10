//! Resolves rUGP message serializers from PE data descriptors and their static
//! field initializers. UnivUI_347 iterates (name, type, offset) triples until
//! offset 0xffff0000, optionally continuing in a base message descriptor.
//! Only decoded x86 MOV/LEA/XOR operands contribute initializer values;
//! conflicting stores never silently select a layout. No target code runs.
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result, Secret};
use vnlens_io::{
    BinaryReader,
    pe::{ImportSymbol, PeImage},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Pointer {
    module: usize,
    address: u64,
}

struct Tables<'a, 'b> {
    images: &'a [PeImage<'b>],
    stores: BTreeMap<Pointer, Option<Pointer>>,
    imports: BTreeMap<Pointer, Pointer>,
}

impl Tables<'_, '_> {
    fn word(&self, pointer: Pointer) -> Option<Pointer> {
        if let Some(value) = self.imports.get(&pointer) {
            return Some(*value);
        }
        if let Some(value) = self.stores.get(&pointer) {
            return *value;
        }
        self.images[pointer.module]
            .u32_at_va(pointer.address)
            .ok()
            .map(|v| Pointer {
                module: pointer.module,
                address: u64::from(v),
            })
    }
    fn at(&self, pointer: Pointer, offset: u64) -> Option<Pointer> {
        self.word(Pointer {
            address: pointer.address.checked_add(offset)?,
            ..pointer
        })
    }
    fn name(&self, pointer: Pointer) -> Option<String> {
        let bytes = self.images[pointer.module].c_string_at_va(pointer.address)?;
        let (s, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
        (!errors).then(|| s.into_owned())
    }
    fn initialize(&mut self, module: usize, cancel: &AtomicBool) -> Result<()> {
        let image = &self.images[module];
        for section in image.sections.iter().filter(|s| s.executable) {
            let mut decoder = Decoder::with_ip(
                32,
                image.section_data(section)?,
                image.image_base + u64::from(section.virtual_address),
                DecoderOptions::NONE,
            );
            let mut registers = HashMap::new();
            while decoder.can_decode() {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let instruction = decoder.decode();
                let mut value = None;
                match instruction.mnemonic() {
                    Mnemonic::Mov | Mnemonic::Lea => {
                        value = match instruction.op1_kind() {
                            OpKind::Immediate32 => Some(Pointer {
                                module,
                                address: u64::from(instruction.immediate32()),
                            }),
                            OpKind::Register => registers.get(&instruction.op1_register()).copied(),
                            OpKind::Memory if absolute(&instruction) => {
                                let pointer = Pointer {
                                    module,
                                    address: instruction.memory_displacement64(),
                                };
                                if instruction.mnemonic() == Mnemonic::Lea {
                                    Some(pointer)
                                } else {
                                    self.word(pointer)
                                }
                            }
                            _ => None,
                        };
                        if instruction.op0_kind() == OpKind::Memory
                            && absolute(&instruction)
                            && instruction.memory_size().size() == 4
                            && let Some(value) = value
                        {
                            let pointer = Pointer {
                                module,
                                address: instruction.memory_displacement64(),
                            };
                            if image.at_va(pointer.address).is_some() {
                                self.stores
                                    .entry(pointer)
                                    .and_modify(|old| {
                                        if *old != Some(value) {
                                            *old = None;
                                        }
                                    })
                                    .or_insert(Some(value));
                            }
                        }
                    }
                    Mnemonic::Xor
                        if instruction.op0_kind() == OpKind::Register
                            && instruction.op1_kind() == OpKind::Register
                            && instruction.op0_register() == instruction.op1_register() =>
                    {
                        value = Some(Pointer { module, address: 0 });
                    }
                    _ => {}
                }
                if instruction.op_count() != 0 && instruction.op0_kind() == OpKind::Register {
                    let register = instruction.op0_register();
                    registers.remove(&register.full_register32());
                    if register.size() == 4
                        && let Some(value) = value
                    {
                        registers.insert(register, value);
                    }
                }
                if instruction.flow_control() != FlowControl::Next {
                    registers.clear();
                }
            }
        }
        Ok(())
    }

    fn fields(&self, mut class: Pointer) -> Option<Vec<serde_json::Value>> {
        let mut seen = BTreeSet::new();
        let mut fields = Vec::new();
        while class.address != 0 {
            if !seen.insert(class) {
                return None;
            }
            let mut table = self.at(class, 4)?;
            if table.address == 0 {
                break;
            }
            loop {
                let offset = self.at(table, 8)?.address;
                if offset >= 0xffff0000 {
                    if offset != 0xffff0000 {
                        return None;
                    }
                    class = self.at(table, 0)?;
                    break;
                }
                let name = self.name(self.at(table, 0)?)?;
                let kind = self.at(table, 4)?;
                let code = self.at(kind, 8)?.address;
                let width = self.at(kind, 4)?.address;
                let native = self.name(self.at(kind, 0)?).unwrap_or_default();
                fields.push(
                    serde_json::json!({"name":name,"type":code,"size":width,"native_type":native}),
                );
                table.address = table.address.checked_add(12)?;
            }
        }
        Some(fields)
    }
}

fn absolute(instruction: &Instruction) -> bool {
    instruction.memory_base() == Register::None && instruction.memory_index() == Register::None
}

pub(super) fn resolve(
    context: &crate::context::Context,
    _: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut paths = Vec::new();
    for dir in [context.root.clone(), context.root.join("Plugins")] {
        if !context.files.is_dir(&dir) {
            continue;
        }
        for entry in context.files.read_dir(&dir)? {
            let path = entry.path;
            if !entry.metadata.directory
                && path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("rpo"))
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    let mut views = Vec::new();
    let mut names = Vec::new();
    for path in &paths {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        if context.image(&view, cancel)?.is_some() {
            views.push(view);
            names.push(
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase(),
            );
        }
    }
    let images = views
        .iter()
        .map(|v| context.image(v, cancel)?.ok_or(Error::InvalidFormat))
        .collect::<vnlens_core::Result<Vec<_>>>()?;
    let mut tables = Tables {
        images: &images,
        stores: BTreeMap::new(),
        imports: BTreeMap::new(),
    };
    for (module, image) in images.iter().enumerate() {
        if image.machine != 0x14c {
            continue;
        }
        for import in image.imports()? {
            let Some(target) = names
                .iter()
                .position(|name| name.as_bytes().eq_ignore_ascii_case(&import.library))
            else {
                continue;
            };
            let address = match import.symbol {
                ImportSymbol::Name(name) => images[target].export(&name)?,
                ImportSymbol::Ordinal(ordinal) => images[target].export_ordinal(ordinal)?,
            };
            if let Some(address) = address {
                tables.imports.insert(
                    Pointer {
                        module,
                        address: import.slot,
                    },
                    Pointer {
                        module: target,
                        address,
                    },
                );
            }
        }
    }
    for (module, image) in images.iter().enumerate() {
        if image.machine == 0x14c {
            tables.initialize(module, cancel)?;
        }
    }
    let mut definitions = BTreeMap::new();
    for (module, image) in images.iter().enumerate() {
        for section in image.sections.iter().filter(|s| !s.executable) {
            let data = image.section_data(section)?;
            for (offset, bytes) in data.as_chunks::<4>().0.iter().enumerate() {
                let pointer = Pointer {
                    module,
                    address: u64::from(BinaryReader::u32_le(bytes)),
                };
                let Some(name) = tables.name(pointer) else {
                    continue;
                };
                if !name.starts_with("OM_") && !name.starts_with("ONM_") {
                    continue;
                }
                let class = Pointer {
                    module,
                    address: image.image_base
                        + u64::from(section.virtual_address)
                        + offset as u64 * 4,
                };
                let Some(flags) = tables.at(class, 8).map(|p| p.address) else {
                    continue;
                };
                if flags & 0x70000000 != 0x30000000 {
                    continue;
                }
                let name = name.split('/').next().unwrap_or(&name);
                let Some(fields) = tables.fields(class) else {
                    continue;
                };
                let definition = serde_json::json!({"schema":(flags>>24)&15,"fields":fields});
                let name = format!("&-{name}");
                if definitions.get(&name).is_some_and(|old| old != &definition) {
                    return Err(Error::UnknownScheme(Some(format!(
                        "Conflicting rUGP message definition: {name}"
                    ))));
                }
                definitions.insert(name, definition);
            }
        }
    }
    if definitions.is_empty() {
        return Err(Error::UnknownScheme(Some(
            "rUGP message definitions were not resolved".into(),
        )));
    }
    let mut options = ArchiveOptions::default();
    options.keys.insert(
        "rugp_messages",
        Secret::new(serde_json::to_vec(&definitions).map_err(|e| {
            Error::Unsupported(format!("Cannot encode rUGP message definitions: {e}"))
        })?),
    );
    Ok(options)
}

#[cfg(test)]
#[path = "../../tests/rugp/key.rs"]
mod tests;
