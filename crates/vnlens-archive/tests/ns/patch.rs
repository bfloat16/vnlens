use super::*;
use crate::ns::fixtures;
use vnlens_io::BinaryWriter;

fn mapping(virtual_at: u64, physical: u64, storage: u32) -> Vec<u8> {
    let mut row = vec![0; 20];
    BinaryWriter::u64_le(virtual_at, &mut row);
    BinaryWriter::u64_le(physical, &mut row[8..]);
    BinaryWriter::u32_le(storage, &mut row[16..]);
    row
}

#[test]
fn indirect_reads_cross_base_patch_and_base_again_without_loading_bodies() -> Result<()> {
    let (header, table) =
        fixtures::table(&[mapping(0, 0, 0), mapping(3, 0, 1), mapping(6, 6, 0)], 9);
    let mut fs = fixtures::fs_header();
    BinaryWriter::u64_le(512, &mut fs[0x100..]);
    BinaryWriter::u64_le(table.len() as u64, &mut fs[0x108..]);
    fs[0x110..0x120].copy_from_slice(&header);
    let mut bytes = vec![0; 512];
    bytes[..3].copy_from_slice(b"XYZ");
    bytes.extend(table);
    let source = indirect(
        fixtures::source(bytes.clone()),
        Some(fixtures::source(b"abcdefghi".to_vec())),
        &fs,
        None,
        &std::sync::atomic::AtomicBool::new(false),
    )?;
    assert_eq!(source.read_at(0, 9)?.as_ref(), b"abcXYZghi");
    assert_eq!(source.read_at(2, 5)?.as_ref(), b"cXYZg");
    assert_eq!(source.read_at(7, 2)?.as_ref(), b"hi");
    assert!(matches!(
        indirect(
            fixtures::source(bytes),
            None,
            &fs,
            None,
            &std::sync::atomic::AtomicBool::new(false)
        ),
        Err(Error::Unsupported(_))
    ));
    assert!(source.read_at(9, 1).is_err());
    Ok(())
}

#[test]
fn bucket_counts_and_ranges_come_from_the_layout() -> Result<()> {
    let rows: Vec<_> = (0..4097).map(|i| mapping(i, i, 0)).collect();
    let (header, bytes) = fixtures::table(&rows, 4097);
    assert_eq!(
        table(
            fixtures::source(bytes.clone()).as_ref(),
            &header,
            20,
            &std::sync::atomic::AtomicBool::new(false)
        )?
        .entries
        .len(),
        4097
    );
    let mut invalid = bytes.clone();
    BinaryWriter::u64_le(u64::MAX, &mut invalid[8..]);
    assert!(
        table(
            fixtures::source(invalid).as_ref(),
            &header,
            20,
            &std::sync::atomic::AtomicBool::new(false)
        )
        .is_err()
    );
    let mut invalid = header;
    BinaryWriter::u32_le(u32::MAX, &mut invalid[8..]);
    assert!(
        table(
            fixtures::source(bytes.clone()).as_ref(),
            &invalid,
            20,
            &std::sync::atomic::AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(
        table(
            fixtures::source(bytes[..bytes.len() - 1].to_vec()).as_ref(),
            &header,
            20,
            &std::sync::atomic::AtomicBool::new(false)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn counter_generations_clear_regions_and_unaligned_reads_match_vectors() -> Result<()> {
    let key = [0x35; 16];
    let upper = 0x1122_3344_0000_0001u64;
    let absolute = 0xc00;
    let plain: Vec<_> = (0..64).collect();
    let mut raw = plain.clone();
    apply_ctr128(&key, 0x1122_3344_0000_0007, absolute, &mut raw[..16]);
    apply_ctr128(&key, 0x1122_3344_0000_0009, absolute + 32, &mut raw[32..]);
    let rows: Vec<_> = [(0, 0, 7), (16, 1, 0), (32, 0, 9)]
        .into_iter()
        .map(|(at, clear, generation)| {
            let mut row = vec![0; 16];
            BinaryWriter::u64_le(at, &mut row);
            row[8] = clear;
            BinaryWriter::u32_le(generation, &mut row[12..]);
            row
        })
        .collect();
    let (header, bytes) = fixtures::table(&rows, 64);
    let mut fs = fixtures::fs_header();
    fs[4] = 4;
    BinaryWriter::u64_le(64, &mut fs[0x120..]);
    BinaryWriter::u64_le(bytes.len() as u64, &mut fs[0x128..]);
    fs[0x130..0x140].copy_from_slice(&header);
    BinaryWriter::u64_le(upper, &mut fs[0x140..]);
    let mut metadata = vec![0; 64];
    metadata.extend(bytes);
    let source = counter(
        fixtures::source(raw),
        fixtures::source(metadata),
        &fs,
        key,
        absolute,
        0,
        &std::sync::atomic::AtomicBool::new(false),
    )?;
    assert_eq!(source.read_at(0, 64)?.as_ref(), plain);
    assert_eq!(source.read_at(7, 42)?.as_ref(), &plain[7..49]);
    Ok(())
}

#[test]
fn patch_metadata_is_authenticated_before_bucket_records_are_used() -> Result<()> {
    use vnlens_crypto::hash::sha256::Sha256;
    let mut fs = fixtures::fs_header();
    fs[5] = 1;
    BinaryWriter::u64_le(512, &mut fs[0x100..]);
    BinaryWriter::u64_le(1536, &mut fs[0x1a0..]);
    BinaryWriter::u64_le(0xe8, &mut fs[0x1a8..]);
    let mut body = vec![0; 1536 + 0xe8];
    body[512..528].copy_from_slice(b"authenticated!!!");
    let mut descriptor = [0; 0xe8];
    BinaryWriter::u64_le(1024, &mut descriptor);
    descriptor[8..12].copy_from_slice(b"IVFC");
    for (at, value) in [(12, 0x20000), (16, 32), (20, 2), (40, 4)] {
        BinaryWriter::u32_le(value, &mut descriptor[at..]);
    }
    BinaryWriter::u64_le(16, &mut descriptor[32..]);
    descriptor[0xc8..].copy_from_slice(&Sha256::digest(&body[512..528]));
    body[1536..].copy_from_slice(&descriptor);
    fs[0x1b0..0x1d0].copy_from_slice(&Sha256::digest(&descriptor));
    let verified = metadata(
        fixtures::source(body.clone()),
        &fs,
        &std::sync::atomic::AtomicBool::new(false),
    )?
    .ok_or(Error::InvalidFormat)?;
    assert_eq!(verified.read_at(512, 16)?.as_ref(), b"authenticated!!!");
    let mut corrupt_payload = body.clone();
    corrupt_payload[512] ^= 1;
    let verified = metadata(
        fixtures::source(corrupt_payload),
        &fs,
        &std::sync::atomic::AtomicBool::new(false),
    )?
    .ok_or(Error::InvalidFormat)?;
    assert!(verified.read_at(512, 1).is_err());
    body[1536] ^= 1;
    assert!(matches!(
        metadata(
            fixtures::source(body),
            &fs,
            &std::sync::atomic::AtomicBool::new(false)
        ),
        Err(Error::Corrupt { .. })
    ));
    Ok(())
}
