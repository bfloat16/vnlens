//! MES glyph readers mask the high tag bit and shift the remaining seven bits
//! by 8 (16-bit glyphs) or 24 (32-bit glyphs). Follow the decoded register's
//! value within its basic block, as in libMgs message and width readers; collect
//! consistent evidence across engine modules, without probing script payloads.
use crate::context::Context;
use iced_x86::{
    Decoder, DecoderOptions, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result};
use vnlens_io::pe::PeImage;

pub(super) fn resolve(
    context: &Context,
    executables: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut found = None;
    let mut dialogue_root = None;
    let mut extended_context = false;
    let mut layouts = None;
    for path in executables {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        if let Some(pe) = context.image(&view, cancel)?
            && super::pe(&pe)?
        {
            // The Maybe module's resource binder declares DataMB and installs
            // the extended 0x2000 dialogue handler (sub_1800DEEB0).
            if crate::detect::has(&pe, b"DataMB\0")? {
                dialogue_root = Some(context.root.join("DataMB"));
                extended_context = true;
            }
            // Both resource binders use the extended context and the 0x002A
            // subcommand B4 expression (sub_180095910/sub_180096240).
            extended_context |= crate::detect::has(&pe, b"DataMA\0")?;
            if let Some(value) = super::dispatch::layouts(&pe, cancel)? {
                if layouts.is_some_and(|old| old != value) {
                    return Err(Error::Unsupported(
                        "Conflicting MAGES opcode layouts".into(),
                    ));
                }
                layouts = Some(value);
            }
            if let Some(width) = glyph_width(&pe, cancel)? {
                if found.is_some_and(|v| v != width) {
                    return Err(Error::Unsupported("Conflicting MAGES glyph widths".into()));
                }
                found = Some(width);
            }
        }
    }
    let mut options = ArchiveOptions::default();
    if let Some(width) = found {
        options.numbers.insert("mages_glyph_width", width);
    }
    if let Some(path) = dialogue_root {
        options.paths.insert("mages_dialogue_root", path);
    }
    if extended_context {
        options.numbers.insert("mages_extended_context", 1);
    }
    if let Some((surface, layer)) = layouts {
        options.numbers.insert("mages_surface_operands", surface);
        options.numbers.insert("mages_layer_operands", layer);
    }
    Ok(options)
}

fn glyph_width(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<u64>> {
    if pe.machine != 0x8664 {
        return Ok(None);
    }
    let mut found = None;
    let mut info = InstructionInfoFactory::new();
    for section in pe.sections.iter().filter(|s| s.executable) {
        let mut decoder = Decoder::with_ip(
            64,
            pe.section_data(section)?,
            pe.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        let mut tagged = Register::None;
        while decoder.can_decode() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let i = decoder.decode();
            if i.mnemonic() == Mnemonic::And
                && i.op0_kind() == OpKind::Register
                && matches!(
                    i.op1_kind(),
                    OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate32
                )
                && i.immediate(1) == 0x7f
            {
                tagged = i.op0_register();
                continue;
            }
            if tagged == Register::None {
                continue;
            }
            if i.mnemonic() == Mnemonic::Shl
                && i.op0_register() == tagged
                && i.op1_kind() == OpKind::Immediate8
                && matches!(i.immediate8(), 8 | 24)
            {
                let width = if i.immediate8() == 8 { 2 } else { 4 };
                if found.is_some_and(|v| v != width) {
                    return Err(Error::Unsupported(
                        "Ambiguous MAGES glyph reader layout".into(),
                    ));
                }
                found = Some(width);
                tagged = Register::None;
            } else if i.flow_control() != iced_x86::FlowControl::Next
                || info.info(&i).used_registers().iter().any(|r| {
                    r.register().full_register() == tagged.full_register()
                        && matches!(
                            r.access(),
                            OpAccess::Write
                                | OpAccess::CondWrite
                                | OpAccess::ReadWrite
                                | OpAccess::ReadCondWrite
                        )
                })
            {
                tagged = Register::None;
            }
        }
    }
    Ok(found)
}
