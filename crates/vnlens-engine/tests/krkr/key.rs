use super::*;
use std::collections::BTreeMap;
use vnlens_io::BinaryWriter;

// Synthetic PE assembled from independent ABI/algorithm examples. Labels,
// absolute operands and near branches are relocated for every fixture.
struct Fixture {
    bytes: Vec<u8>,
    base: u32,
    at: usize,
    labels: BTreeMap<&'static str, usize>,
    branches: Vec<(usize, &'static str)>,
}
impl Fixture {
    fn emit(&mut self, bytes: &[u8]) {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
    fn word(&mut self, value: u32) {
        BinaryWriter::u32_le(value, &mut self.bytes[self.at..]);
        self.at += 4;
    }
    fn va(&self, at: usize) -> u32 {
        self.base + 0x1000 + (at - 0x200) as u32
    }
    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.at);
    }
    fn branch(&mut self, opcode: &[u8], label: &'static str) {
        self.emit(opcode);
        self.branches.push((self.at, label));
        self.word(0);
    }
    fn new(base: u32) -> Self {
        let mut f = Self {
            bytes: vec![0; 0x2200],
            base,
            at: 0x600,
            labels: BTreeMap::new(),
            branches: Vec::new(),
        };
        f.bytes[..2].copy_from_slice(b"MZ");
        f.bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (at, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
            BinaryWriter::u16_le(value, &mut f.bytes[at..]);
        }
        for (at, value) in [
            (0x3c, 0x80),
            (0xb4, base),
            (0xd4, 0x200),
            (0xf4, 16),
            (0xf8, 0x1000),
            (0xfc, 0x100),
            (0x180, 0x3000),
            (0x184, 0x1000),
            (0x188, 0x2000),
            (0x18c, 0x200),
            (0x19c, 0xe0000020),
            (0x214, 1),
            (0x218, 1),
            (0x21c, 0x1060),
            (0x220, 0x1064),
            (0x224, 0x1068),
            (0x260, 0x1400),
            (0x264, 0x1080),
        ] {
            BinaryWriter::u32_le(value, &mut f.bytes[at..]);
        }
        f.bytes[0x280..0x287].copy_from_slice(b"V2Link\0");
        f.bytes[0x400..0x400 + API.len()].copy_from_slice(API.as_bytes());
        let exporter = base + 0x3900;
        let cache = base + 0x3904;
        let cookie = base + 0x3908;
        // V2Link and the function-exporter query.
        f.emit(&[0x90, 0x8b, 0x44, 0x24, 4, 0xa3]);
        f.word(exporter);
        f.emit(&[0xa1]);
        f.word(cache);
        f.emit(&[0x85, 0xc0]);
        f.branch(&[0x0f, 0x85], "cached");
        f.emit(&[0x68]);
        f.word(f.va(0x400));
        f.branch(&[0xe8], "query");
        f.emit(&[0x83, 0xc4, 4, 0xa3]);
        f.word(cache);
        f.label("cached");
        f.emit(&[0x68]);
        f.label("callback_pointer");
        f.word(0);
        f.emit(&[0xff, 0xd0, 0x31, 0xc0, 0xc3]);
        f.label("query");
        f.emit(&[0x51, 0xa1]);
        f.word(exporter);
        f.emit(&[
            0x8b, 8, 0x6a, 1, 0x8d, 0x54, 0x24, 4, 0x52, 0x8d, 0x54, 0x24, 16, 0x52, 0x50, 0x8b,
            0x41, 4, 0xff, 0xd0, 0x83, 0xc4, 16, 0x84, 0xc0,
        ]);
        f.branch(&[0x0f, 0x85], "queried");
        f.emit(&[0xcc]);
        f.label("queried");
        f.emit(&[0x8b, 4, 0x24, 0x59, 0xc3]);
        // Callback ABI, cookie and size guard.
        f.label("filter");
        f.emit(&[0x83, 0xec, 0x24, 0xa1]);
        f.word(cookie);
        f.emit(&[
            0x31, 0xe0, 0x89, 0x44, 0x24, 0x20, 0x56, 0x57, 0x8b, 0x7c, 0x24, 0x30, 0x83, 0x3f, 24,
        ]);
        f.branch(&[0x0f, 0x84], "body");
        f.emit(&[0xcc]);
        f.label("body");
        f.emit(&[0x8b, 0x47, 20, 0x25]);
        f.word(0x7fffffff);
        // MOV uses the opposite direction encoding from the local plugin.
        f.emit(&[0x8b, 0xc8, 0xc1, 0xe1, 31, 0x09, 0xc8, 0x31, 0xc9]);
        f.label("key");
        f.emit(&[
            0x89, 0xc2, 0x88, 0x44, 0x0c, 8, 0x83, 0xe2, 0xfe, 0xc1, 0xe2, 23, 0xc1, 0xe8, 8, 0x41,
            0x09, 0xd0, 0x83, 0xf9,
        ]);
        f.label("period");
        f.emit(&[31]);
        f.branch(&[0x0f, 0x8c], "key");
        f.emit(&[0x31, 0xf6, 0x39, 0x77, 16]);
        f.branch(&[0x0f, 0x86], "end");
        f.emit(&[0x53]);
        f.label("data");
        f.emit(&[
            0x8b, 0x47, 12, 0x31, 0xd2, 0x89, 0xf1, 0x03, 0x4f, 4, 0x6a, 0, 0x13, 0x57,
        ]);
        f.label("offset_high");
        f.emit(&[8, 0x6a, 31, 0x52, 0x51, 0x8d, 0x1c, 0x30]);
        f.branch(&[0xe8], "remainder");
        f.emit(&[0x8a, 0x44, 4, 12]);
        f.label("xor");
        f.emit(&[0x30, 3, 0x46, 0x3b, 0x77, 16]);
        f.branch(&[0x0f, 0x82], "data");
        f.emit(&[0x5b]);
        f.label("end");
        f.emit(&[0x8b, 0x4c, 0x24, 0x28, 0x5f, 0x5e, 0x31, 0xe1]);
        f.branch(&[0xe8], "cookie");
        f.emit(&[0x83, 0xc4, 0x24, 0xc2, 4, 0]);
        // The reachable 64-bit dividend / 32-bit divisor CRT path.
        f.label("remainder");
        f.emit(&[0x53, 0x8b, 0x44, 0x24, 20, 0x09, 0xc0]);
        f.branch(&[0x0f, 0x85], "unsupported");
        f.emit(&[
            0x8b, 0x4c, 0x24, 16, 0x8b, 0x44, 0x24, 12, 0x31, 0xd2, 0xf7, 0xf1, 0x8b, 0x44, 0x24,
            8, 0xf7, 0xf1, 0x89, 0xd0, 0x31, 0xd2,
        ]);
        f.branch(&[0xe9], "remainder_end");
        f.label("unsupported");
        f.emit(&[0xcc]);
        f.label("remainder_end");
        f.emit(&[0x5b, 0xc2, 16, 0]);
        f.label("cookie");
        f.emit(&[0x3b, 0x0d]);
        f.word(cookie);
        f.branch(&[0x0f, 0x85], "unsupported");
        f.emit(&[0xc3]);
        for &(at, label) in &f.branches {
            BinaryWriter::u32_le(
                (f.labels[label] as u32).wrapping_sub(at as u32 + 4),
                &mut f.bytes[at..],
            );
        }
        let callback = f.va(f.labels["filter"]);
        BinaryWriter::u32_le(callback, &mut f.bytes[f.labels["callback_pointer"]..]);
        f
    }
}
#[test]
fn follows_relocated_registration_and_rejects_changed_semantics() -> Result<()> {
    for base in [0x400000, 0x10000000] {
        let f = Fixture::new(base);
        let identify = |bytes: &[u8]| -> Result<bool> {
            xor31(&PeImage::parse(bytes)?.ok_or(Error::InvalidFormat)?)
        };
        assert!(identify(&f.bytes)?);
        for (label, value) in [("period", 30), ("offset_high", 4), ("xor", 0x00)] {
            let mut bytes = f.bytes.clone();
            bytes[f.labels[label]] = value;
            assert!(
                matches!(identify(&bytes), Err(Error::UnknownScheme(_))),
                "{label}"
            );
        }
        let mut bytes = f.bytes.clone();
        BinaryWriter::u32_le(
            f.va(f.labels["unsupported"]),
            &mut bytes[f.labels["callback_pointer"]..],
        );
        assert!(matches!(identify(&bytes), Err(Error::UnknownScheme(_))));
        bytes[0x400] = b'?';
        assert!(!identify(&bytes)?);
    }
    Ok(())
}

fn zlib_stored(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut chunks = raw.chunks(u16::MAX as usize).peekable();
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let len = chunk.len() as u16;
        let p = out.len();
        out.resize(p + 4, 0);
        BinaryWriter::u16_le(len, &mut out[p..]);
        BinaryWriter::u16_le(!len, &mut out[p + 2..]);
        out.extend_from_slice(chunk);
    }
    let adler = vnlens_crypto::checksum::adler32::checksum(raw);
    let p = out.len();
    out.resize(p + 4, 0);
    BinaryWriter::u32_be(adler, &mut out[p..]);
    out
}

fn cxdec_module(base: u32, with_api: bool, with_table: bool) -> Vec<u8> {
    let mut f = Fixture::new(base);
    f.bytes.resize(0x4000, 0);
    BinaryWriter::u32_le(0x3e00, &mut f.bytes[0x180..]);
    BinaryWriter::u32_le(0x3e00, &mut f.bytes[0x188..]);
    if !with_api {
        f.bytes[0x400] = b'?';
    }
    let at = f.at;
    // classic_rng in executable .text section, immediately following Fixture code.
    let rng = [
        0x8b, 0x96, 0xd8, 0x09, 0x00, 0x00, // mov edx, [esi+0x9d8]
        0x8b, 0xca, // mov ecx, edx
        0x69, 0xc9, 0x6d, 0x4e, 0xc6, 0x41, // imul ecx, ecx, 0x41c64e6d
        0x8b, 0xc2, // mov eax, edx
        0xc1, 0xe8, 16, // shr eax, 16
        0x81, 0xc1, 0x39, 0x30, 0x00, 0x00, // add ecx, 0x3039
        0xc1, 0xe2, 16, // shl edx, 16
        0x33, 0xc2, // xor eax, edx
        0x89, 0x8e, 0xd8, 0x09, 0x00, 0x00, // mov [esi+0x9d8], ecx
        0x33, 0xc1, // xor eax, ecx
        0x5e, // pop esi
        0xc3, // ret
    ];
    f.bytes[at..at + rng.len()].copy_from_slice(&rng);
    let mut at = 0x1000;
    for text in [
        &b".?AVTImplCryptFile@@\0"[..],
        b"unknown oder RO_8\0",
        b"unknown oder RO_6\0",
    ] {
        f.bytes[at..at + text.len()].copy_from_slice(text);
        at += text.len();
    }
    f.bytes[at..at + 7].copy_from_slice(b"PARAMS\0");
    at += 7;
    BinaryWriter::u16_le(22, &mut f.bytes[at..]);
    at += 2;
    let params = [
        2, 0, 6, 5, 1, 4, 3, 7, 1, 5, 3, 2, 0, 4, 1, 0, 2, 0, 0xe2, 2, 0x83, 2,
    ];
    f.bytes[at..at + 22].copy_from_slice(&params);
    at += 22;
    if with_table {
        f.bytes[at..at + 6].copy_from_slice(b"TABLE\0");
        at += 6;
        BinaryWriter::u16_le(4096, &mut f.bytes[at..]);
        at += 2;
        for (i, byte) in f.bytes[at..at + 4096].iter_mut().enumerate() {
            *byte = (i * 11) as u8;
        }
    }
    f.bytes
}

fn host_with_internal_module(module: &[u8]) -> Vec<u8> {
    let packed = zlib_stored(module);
    let mut f = Fixture::new(0x400000);
    f.bytes.resize(0x5000 + packed.len(), 0);
    // Host EXE does not export V2Link or import TVPSetXP3ArchiveExtractionFilter directly.
    f.bytes[0xf8..0x100].fill(0);
    f.bytes[0x400..0x400 + API.len()].fill(0);
    BinaryWriter::u32_le((0x4e00 + packed.len()) as u32, &mut f.bytes[0x180..]);
    BinaryWriter::u32_le((0x4e00 + packed.len()) as u32, &mut f.bytes[0x188..]);

    let s_internal = 0x1500;
    f.bytes[s_internal..s_internal + 16].copy_from_slice(b"internal module\0");
    let s_v2link = 0x1510;
    f.bytes[s_v2link..s_v2link + 7].copy_from_slice(b"V2Link\0");
    let s_v2unlink = 0x1518;
    f.bytes[s_v2unlink..s_v2unlink + 9].copy_from_slice(b"V2Unlink\0");
    let v_packed = 0x1530;
    BinaryWriter::u32_le(packed.len() as u32, &mut f.bytes[v_packed..]);
    let v_unpacked = 0x1534;
    BinaryWriter::u32_le(module.len() as u32, &mut f.bytes[v_unpacked..]);
    let body = 0x2000;
    f.bytes[body..body + packed.len()].copy_from_slice(&packed);

    let start = f.at;
    let empty_target = start + 0x200;
    let ctor_at = start + 0x100;
    let helper_at = start + 0x220;
    let resolver_at = start + 0x230;
    let absent_target = ctor_at + 53;

    let mut rel_calls = Vec::new();
    let emit_rel = |f: &mut Fixture, calls: &mut Vec<(usize, usize)>, op: &[u8], target: usize| {
        f.emit(op);
        calls.push((f.at, target));
        f.word(0);
    };

    // loader()
    f.emit(&[0x8b, 0x3d]);
    f.word(f.va(v_packed));
    f.emit(&[0x8b, 0x1d]);
    f.word(f.va(v_unpacked));
    f.emit(&[0x85, 0xff]);
    emit_rel(&mut f, &mut rel_calls, &[0x0f, 0x84], empty_target);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], helper_at);
    f.emit(&[0x8b, 0xf0, 0x68]);
    f.word(f.va(s_internal));
    f.emit(&[0x8b, 0xce]);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], helper_at);
    f.emit(&[
        0x89, 0x75, 0xf0, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x6a, 20,
    ]);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], helper_at);
    f.emit(&[
        0x83, 0xc4, 4, 0x89, 0x45, 0xec, 0xc6, 0x45, 0xfc, 0x01, 0x85, 0xc0,
    ]);
    emit_rel(&mut f, &mut rel_calls, &[0x0f, 0x84], empty_target);
    f.emit(&[0x53, 0x57, 0x68]);
    f.word(f.va(body));
    f.emit(&[0x8d, 0x4d, 0xf0, 0x51, 0x8b, 0xc8]);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], ctor_at);
    assert!(f.at <= empty_target);
    f.at = empty_target;
    f.emit(&[0xc3]);

    // constructor -> links_module -> link_exports()
    f.at = ctor_at;
    f.emit(&[0xba]);
    f.word(f.va(s_v2link));
    f.emit(&[0x8b, 0x4f, 0x04]);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], resolver_at);
    f.emit(&[0x89, 0x47, 0x0c, 0xba]);
    f.word(f.va(s_v2unlink));
    f.emit(&[0x8b, 0x4f, 0x04]);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], resolver_at);
    f.emit(&[0x89, 0x47, 0x10, 0x83, 0x7f, 0x0c, 0x00]);
    emit_rel(&mut f, &mut rel_calls, &[0x0f, 0x84], absent_target);
    emit_rel(&mut f, &mut rel_calls, &[0xe8], helper_at);
    f.emit(&[0x50, 0x8b, 0x47, 0x0c, 0xff, 0xd0]);
    assert_eq!(f.at, absent_target);
    f.emit(&[0xc3]);

    f.at = helper_at;
    f.emit(&[0xc3]);
    f.at = resolver_at;
    f.emit(&[0xc3]);

    for (at, target) in rel_calls {
        BinaryWriter::u32_le(
            (target as u32).wrapping_sub(at as u32 + 4),
            &mut f.bytes[at..],
        );
    }
    f.bytes
}

#[test]
fn internal_cxdec_recovers_from_plugin_and_compressed_host_module() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let dll = cxdec_module(0x1000_0000, true, true);
    let dll_image = PeImage::parse(&dll)?.ok_or(Error::InvalidFormat)?;
    let direct = internal::resolve(&dll_image, &cancel)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(direct.numbers.get("xp3_cxdec"), Some(&1));
    assert_eq!(direct.keys["cxdec_params"].bytes().len(), 22);
    assert_eq!(direct.keys["cxdec_table"].bytes().len(), 4096);

    let host = host_with_internal_module(&dll);
    let host_image = PeImage::parse(&host)?.ok_or(Error::InvalidFormat)?;
    let from_host = internal::resolve(&host_image, &cancel)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(from_host, direct);

    let non_filter = host_with_internal_module(&cxdec_module(0x1000_0000, false, true));
    let non_filter_image = PeImage::parse(&non_filter)?.ok_or(Error::InvalidFormat)?;
    assert!(internal::resolve(&non_filter_image, &cancel)?.is_none());

    let missing_table = cxdec_module(0x1000_0000, true, false);
    let missing_table_image = PeImage::parse(&missing_table)?.ok_or(Error::InvalidFormat)?;
    assert!(matches!(
        internal::resolve(&missing_table_image, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    Ok(())
}
