//! KiriKiri's compressed internal V2Link module. Host sub_43A160 loads two
//! LE size fields and passes a zlib body to sub_43AAC0, which resolves V2Link
//! and V2Unlink. Recover only its static Cxdec PARAMS/TABLE records in memory;
//! neither host nor module code is executed, mapped as code, or saved.
use super::*;
use vnlens_core::Secret;
use vnlens_crypto::compress::zlib;
use vnlens_io::BinaryReader;

fn missing(reason: &str) -> Error {
    Error::UnknownScheme(Some(format!("KiriKiri internal module: {reason}")))
}

pub(super) fn resolve(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<ArchiveOptions>> {
    if is_cxdec(image)? {
        return parameters(image).map(Some);
    }
    if image.machine != 0x14c || !has(image, b"internal module\0")? {
        return Ok(Option::None);
    }
    let mut found = Option::None;
    for section in image.sections.iter().filter(|section| section.executable) {
        let code = image.section_data(section)?;
        let mut decoder = Decoder::with_ip(
            32,
            code,
            image.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let instruction = decoder.decode();
            if instruction.mnemonic() != Mov || instruction.op0_register() != EDI {
                continue;
            }
            let Some((packed, unpacked, body)) = loader(image, instruction.ip()) else {
                continue;
            };
            let sizes = (packed, unpacked, body);
            if found.is_some_and(|previous| previous != sizes) {
                return Err(missing("Ambiguous internal-module loader"));
            }
            found = Some(sizes);
        }
    }
    let (packed, unpacked, body) =
        found.ok_or_else(|| missing("Unsupported internal-module loader"))?;
    let packed = image.u32_at_va(u64::from(packed))?;
    if packed == 0 {
        return Ok(Option::None);
    }
    let unpacked = image.u32_at_va(u64::from(unpacked))?;
    let packed =
        usize::try_from(packed).map_err(|_| missing("Module size exceeds address space"))?;
    let body = image
        .at_va(u64::from(body))
        .and_then(|data| data.get(..packed))
        .ok_or_else(|| vnlens_io::BinaryIo::unexpected_eof("Truncated KiriKiri internal module"))?;
    let size =
        usize::try_from(unpacked).map_err(|_| missing("Module size exceeds address space"))?;
    let bytes = zlib::inflate_with_limit(body, size)
        .map_err(|_| missing("Invalid internal-module zlib data"))?;
    if bytes.len() != size {
        return Err(missing("Internal-module decoded length mismatch"));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let module = PeImage::parse(&bytes)?.ok_or_else(|| missing("Internal module is not PE"))?;
    // The host also embeds non-filter modules (for example SHIELD-9's
    // initialization module). Only extraction-filter evidence selects crypto.
    if !has(&module, API.as_bytes())? {
        return Ok(Option::None);
    }
    if !is_cxdec(&module)? {
        return Err(missing("Unsupported internal extraction filter"));
    }
    parameters(&module).map(Some)
}

fn loader(image: &PeImage<'_>, entry: u64) -> Option<(u32, u32, u32)> {
    let mut c = Code::new(image, entry);
    let packed = c.load_global(EDI)?;
    let unpacked = c.load_global(EBX)?;
    c.expect(Test, &[Reg(EDI), Reg(EDI)])?;
    let empty = c.branch(Je)?;
    c.branch(Call)?;
    c.expect(Mov, &[Reg(ESI), Reg(EAX)])?;
    if image.c_string_at_va(u64::from(c.constant()?))? != b"internal module" {
        return Option::None;
    }
    c.expect(Mov, &[Reg(ECX), Reg(ESI)])?;
    c.branch(Call)?;
    c.expect(Mov, &[mem(EBP, 0xffff_fff0), Reg(ESI)])?;
    c.expect(Mov, &[mem(EBP, 0xffff_fffc), Imm(0)])?;
    c.expect(Push, &[Imm(20)])?;
    c.branch(Call)?;
    c.expect(Add, &[Reg(ESP), Imm(4)])?;
    c.expect(Mov, &[mem(EBP, 0xffff_ffec), Reg(EAX)])?;
    c.expect(
        Mov,
        &[Mem(EBP, None, 1, 0xffff_fffc, MemorySize::UInt8), Imm(1)],
    )?;
    c.expect(Test, &[Reg(EAX), Reg(EAX)])?;
    c.branch(Je)?;
    c.expect(Push, &[Reg(EBX)])?;
    c.expect(Push, &[Reg(EDI)])?;
    let body = c.constant()?;
    c.expect(Lea, &[Reg(ECX), mem(EBP, 0xffff_fff0)])?;
    c.expect(Push, &[Reg(ECX)])?;
    c.expect(Mov, &[Reg(ECX), Reg(EAX)])?;
    let constructor = c.branch(Call)?;
    if c.pc >= empty || !links_module(image, constructor) {
        return Option::None;
    }
    Some((packed, unpacked, body))
}

fn links_module(image: &PeImage<'_>, entry: u64) -> bool {
    let mut c = Code::new(image, entry);
    while let Some(i) = c.next() {
        if i.mnemonic() == Ret {
            break;
        }
        if i.mnemonic() == Mov
            && i.op0_kind() == OpKind::Register
            && i.op0_register() == EDX
            && let Some(address) = immediate(&i, 1)
            && image.c_string_at_va(u64::from(address)) == Some(b"V2Link")
            && link_exports(image, c.pc).is_some()
        {
            return true;
        }
    }
    false
}

// sub_43AAC0 uses sub_43A990's register ABI: ECX is the memory module,
// EDX is the export name. Both lookups use the same resolver; the V2Link
// result is then called with the host function exporter as its argument.
fn link_exports(image: &PeImage<'_>, entry: u64) -> Option<()> {
    let mut c = Code::new(image, entry);
    c.expect(Mov, &[Reg(ECX), mem(EDI, 4)])?;
    let resolver = c.branch(Call)?;
    c.expect(Mov, &[mem(EDI, 12), Reg(EAX)])?;
    let name = c.next()?;
    if name.mnemonic() != Mov
        || name.op0_kind() != OpKind::Register
        || name.op0_register() != EDX
        || image.c_string_at_va(u64::from(immediate(&name, 1)?))? != b"V2Unlink"
    {
        return Option::None;
    }
    c.expect(Mov, &[Reg(ECX), mem(EDI, 4)])?;
    if c.branch(Call)? != resolver {
        return Option::None;
    }
    c.expect(Mov, &[mem(EDI, 16), Reg(EAX)])?;
    c.expect(Cmp, &[mem(EDI, 12), Imm(0)])?;
    let absent = c.branch(Je)?;
    c.branch(Call)?;
    c.expect(Push, &[Reg(EAX)])?;
    c.expect(Mov, &[Reg(EAX), mem(EDI, 12)])?;
    c.expect(Call, &[Reg(EAX)])?;
    (c.pc == absent).then_some(())
}

fn is_cxdec(image: &PeImage<'_>) -> Result<bool> {
    if image.machine != 0x14c
        || image.export(b"V2Link")?.is_none()
        || !has(image, API.as_bytes())?
        || !has(image, b".?AVTImplCryptFile@@\0")?
        || !has(image, b"unknown oder RO_8\0")?
        || !has(image, b"unknown oder RO_6\0")?
    {
        return Ok(false);
    }
    // Verify the classic generator's decoded LCG state transition. The MT
    // branch in this same revision uses standard MT19937 tempering.
    for section in image.sections.iter().filter(|section| section.executable) {
        let code = image.section_data(section)?;
        let mut decoder = Decoder::with_ip(
            32,
            code,
            image.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let i = decoder.decode();
            if i.mnemonic() != Mov || i.op0_register() != EDX {
                continue;
            }
            if classic_rng(image, i.ip()).is_some() {
                return Ok(true);
            }
        }
    }
    Err(missing("Unsupported Cxdec generator"))
}

fn classic_rng(image: &PeImage<'_>, entry: u64) -> Option<()> {
    let mut c = Code::new(image, entry);
    c.expect(Mov, &[Reg(EDX), mem(ESI, 0x9d8)])?;
    c.expect(Mov, &[Reg(ECX), Reg(EDX)])?;
    c.expect(Imul, &[Reg(ECX), Reg(ECX), Imm(0x41c6_4e6d)])?;
    c.expect(Mov, &[Reg(EAX), Reg(EDX)])?;
    c.expect(Shr, &[Reg(EAX), Imm(16)])?;
    c.expect(Add, &[Reg(ECX), Imm(0x3039)])?;
    c.expect(Shl, &[Reg(EDX), Imm(16)])?;
    c.expect(Xor, &[Reg(EAX), Reg(EDX)])?;
    c.expect(Mov, &[mem(ESI, 0x9d8), Reg(ECX)])?;
    c.expect(Xor, &[Reg(EAX), Reg(ECX)])?;
    c.expect(Pop, &[Reg(ESI)])?;
    c.expect(Ret, &[])?;
    Some(())
}

fn parameters(image: &PeImage<'_>) -> Result<ArchiveOptions> {
    let mut result = Option::None;
    for section in &image.sections {
        let data = image.section_data(section)?;
        for (offset, tag) in data.windows(7).enumerate() {
            if tag != b"PARAMS\0" {
                continue;
            }
            let mut r = BinaryReader::new(&data[offset + 7..]);
            let Ok(size) = r.read_u16_le() else {
                continue;
            };
            let Ok(params) = r.read_bytes(usize::from(size)) else {
                continue;
            };
            if params.len() < 22
                || ![(0, 8), (8, 6), (14, 3)].iter().all(|&(start, size)| {
                    let mut map = params[start..start + size].to_vec();
                    map.sort();
                    map.iter().copied().eq(0..size as u8)
                })
            {
                continue;
            }
            if r.read_bytes(6)? != b"TABLE\0" {
                return Err(missing("Cxdec TABLE record is absent"));
            }
            let size = r.read_u16_le()?;
            let table = r.read_bytes(usize::from(size))?;
            if table.len() < 4096 {
                return Err(missing("Truncated Cxdec TABLE"));
            }
            let mut options = ArchiveOptions::default();
            options.numbers.insert("xp3_cxdec", 1);
            options.keys.insert("cxdec_params", Secret::new(params));
            options.keys.insert("cxdec_table", Secret::new(table));
            if result.as_ref().is_some_and(|old| old != &options) {
                return Err(missing("Conflicting Cxdec parameter records"));
            }
            result = Some(options);
        }
    }
    result.ok_or_else(|| missing("Cxdec PARAMS record is absent or unsupported"))
}
