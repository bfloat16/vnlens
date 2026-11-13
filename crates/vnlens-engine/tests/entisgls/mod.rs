#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_io::BinaryWriter;

fn image(text: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0x200 + text.len()];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut bytes[0x84..]);
    BinaryWriter::u16_le(1, &mut bytes[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut bytes[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut bytes[0x98..]);
    BinaryWriter::u32_le(0x400000, &mut bytes[0xb4..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0xd4..]);
    BinaryWriter::u32_le(0x1000, &mut bytes[0x184..]);
    BinaryWriter::u32_le(text.len() as u32, &mut bytes[0x188..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0x18c..]);
    bytes[0x200..].copy_from_slice(text);
    bytes
}

#[test]
fn classic_and_sakura_pe_evidence_require_both_markers() {
    for data in [
        b"EntisGLS_GameWindow\0ERISAArchive\0".as_slice(),
        b"EntisGLS_GameWindow\0ERISAArchive\0ERISA::SGLArchiveFile\0",
        b"EntisGLS4_SGLGenericWindow\0ERISA::SGLArchiveFile\0",
    ] {
        let bytes = image(data);
        assert!(pe(&PeImage::parse(&bytes).unwrap().unwrap()).unwrap());
    }
    for data in [
        b"ERISAArchive".as_slice(),
        b"EntisGLS_GameWindow",
        b"EntisGLS4_SGLGenericWindow",
        b"ERISA::SGLArchiveFile",
        b"EntisGLS_GameWindow\0ERISA::SGLArchiveFile\0",
        b"EntisGLS4_SGLGenericWindow\0ERISAArchive\0",
        b"Unknown engine",
    ] {
        let bytes = image(data);
        assert!(!pe(&PeImage::parse(&bytes).unwrap().unwrap()).unwrap());
    }
}
