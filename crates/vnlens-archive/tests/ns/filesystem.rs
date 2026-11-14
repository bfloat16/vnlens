#![allow(clippy::unwrap_used)]
use super::*;
use std::{borrow::Cow, io, sync::Mutex};
use vnlens_core::ResourceKind;
use vnlens_crypto::hash::sha256::Sha256;
use vnlens_io::BinaryWriter;

fn source(bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    Arc::new(Arc::<[u8]>::from(bytes))
}

fn partition(hashed: bool) -> Vec<u8> {
    let stride = if hashed { 64 } else { 24 };
    let strings = "台詞.txt\0bad.bin\0".as_bytes();
    let base = 16 + stride * 2 + strings.len();
    let mut bytes = vec![0; base + 8];
    bytes[..4].copy_from_slice(if hashed { b"HFS0" } else { b"PFS0" });
    BinaryWriter::u32_le(2, &mut bytes[4..]);
    BinaryWriter::u32_le(strings.len() as u32, &mut bytes[8..]);
    for i in 0..2 {
        let at = 16 + stride * i;
        BinaryWriter::u64_le(i as u64 * 4, &mut bytes[at..]);
        BinaryWriter::u64_le(4, &mut bytes[at + 8..]);
        BinaryWriter::u32_le(if i == 0 { 0 } else { 11 }, &mut bytes[at + 16..]);
        if hashed {
            BinaryWriter::u32_le(4, &mut bytes[at + 20..]);
            bytes[at + 32..at + 64].copy_from_slice(&Sha256::digest(b"GOOD"));
        }
    }
    bytes[16 + stride * 2..base].copy_from_slice(strings);
    bytes[base..].copy_from_slice(b"GOODFAIL");
    bytes
}

struct Watched {
    bytes: Vec<u8>,
    payload: u64,
    reads: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for Watched {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.reads.lock().unwrap().push((offset, size));
        if offset + size as u64 > self.payload {
            return Err(io::Error::other("payload access forbidden during mount"));
        }
        Ok(Cow::Borrowed(
            &self.bytes[offset as usize..offset as usize + size],
        ))
    }
}

#[test]
fn partitions_are_lazy_and_hashed_payload_failures_are_local() -> Result<()> {
    for hashed in [false, true] {
        let bytes = partition(hashed);
        let watched = Arc::new(Watched {
            payload: bytes.len() as u64 - 8,
            bytes: bytes.clone(),
            reads: Mutex::default(),
        });
        let fs = open_partition(watched.clone(), hashed)?;
        assert_eq!(fs.entries.len(), 2);
        assert_eq!(fs.entries[0].name, "台詞.txt");
        assert!(
            watched
                .reads
                .lock()
                .unwrap()
                .iter()
                .all(|&(at, n)| at + n as u64 <= watched.payload)
        );
        let fs = open_partition(source(bytes), hashed)?;
        assert_eq!(fs.read(&fs.entries[0])?.as_ref(), b"GOOD");
        assert_eq!(fs.source(&fs.entries[0])?.read_at(1, 2)?.as_ref(), b"OO");
        if hashed {
            assert!(fs.read(&fs.entries[1]).is_err());
        }
    }
    Ok(())
}

#[test]
fn partition_invalid_offsets_counts_strings_and_truncation() {
    for end in [0, 4, 15, 32] {
        assert!(open_partition(source(partition(false)[..end].to_vec()), false).is_err());
    }
    let mut bytes = partition(false);
    BinaryWriter::u32_le(u32::MAX, &mut bytes[4..]);
    assert!(
        matches!(open_partition(source(bytes), false), Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    let mut bytes = partition(false);
    BinaryWriter::u64_le(u64::MAX, &mut bytes[16..]);
    assert!(open_partition(source(bytes), false).is_err());
    let mut bytes = partition(false);
    BinaryWriter::u32_le(u32::MAX, &mut bytes[32..]);
    assert!(open_partition(source(bytes), false).is_err());
}

#[test]
fn xci_initial_data_offsets_and_root_hash_are_verified_without_payload_reads() -> Result<()> {
    for base in [0, 0x1000] {
        let partition = partition(true);
        let root = base + 0x20000;
        let header_size = partition.len() - 8;
        let mut bytes = vec![0; root + partition.len()];
        bytes[base + 0x100..base + 0x104].copy_from_slice(b"HEAD");
        BinaryWriter::u64_le(0x20000, &mut bytes[base + 0x130..]);
        BinaryWriter::u64_le(header_size as u64, &mut bytes[base + 0x138..]);
        bytes[base + 0x140..base + 0x160]
            .copy_from_slice(&Sha256::digest(&partition[..header_size]));
        bytes[root..].copy_from_slice(&partition);
        let watched = Arc::new(Watched {
            payload: (root + header_size) as u64,
            bytes: bytes.clone(),
            reads: Mutex::default(),
        });
        let fs = open_xci(watched)?;
        assert_eq!(fs.entries[0].offset, (root + header_size) as u64);
        let fs = open_xci(source(bytes.clone()))?;
        assert!(matches!(fs.read(&fs.entries[0])?, Cow::Borrowed(b"GOOD")));
        assert!(fs.read(&fs.entries[1]).is_err());
        bytes[root + 16] ^= 1;
        assert!(matches!(
            open_xci(source(bytes)),
            Err(Error::Corrupt { .. })
        ));
    }
    Ok(())
}

fn romfs() -> Vec<u8> {
    let mut bytes = vec![0; 0x80 + 36 + 4];
    BinaryWriter::u64_le(0x50, &mut bytes);
    // Empty hash tables, a root directory, one file record and four data bytes.
    for (at, value) in [
        (8, 0x50),
        (16, 0),
        (24, 0x50),
        (32, 24),
        (40, 0x68),
        (48, 0),
        (56, 0x80),
        (64, 36),
        (72, 0xa4),
    ] {
        BinaryWriter::u64_le(value, &mut bytes[at..]);
    }
    for at in [0x54, 0x58, 0x60, 0x84, 0x98] {
        BinaryWriter::u32_le(u32::MAX, &mut bytes[at..]);
    }
    BinaryWriter::u64_le(4, &mut bytes[0x90..]);
    BinaryWriter::u32_le(4, &mut bytes[0x9c..]);
    bytes[0xa0..0xa4].copy_from_slice(b"file");
    bytes[0xa4..].copy_from_slice(b"DATA");
    bytes
}

#[test]
fn romfs_walks_links_and_never_reads_files_during_mount() -> Result<()> {
    let bytes = romfs();
    let watched = Arc::new(Watched {
        payload: 0xa4,
        bytes: bytes.clone(),
        reads: Mutex::default(),
    });
    let fs = open_romfs(watched)?;
    assert_eq!(fs.entries.len(), 1);
    assert_eq!(fs.entries[0].name, "file");
    let fs = open_romfs(source(bytes))?;
    assert_eq!(fs.read(&fs.entries[0])?.as_ref(), b"DATA");
    let mut cyclic = romfs();
    BinaryWriter::u32_le(0, &mut cyclic[0x58..]);
    assert!(matches!(
        open_romfs(source(cyclic)),
        Err(Error::Corrupt { .. })
    ));
    let mut truncated = romfs();
    truncated.pop();
    assert!(
        matches!(open_romfs(source(truncated)), Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}

#[test]
fn hash_tree_authenticates_only_requested_blocks() -> Result<()> {
    let bytes = b"GOODFAIL".to_vec();
    let mut hashes = Sha256::digest(b"GOOD").to_vec();
    hashes.extend_from_slice(&Sha256::digest(b"XXXX"));
    let tree = integrity::HashLevel {
        source: source(bytes),
        hashes: source(hashes),
        block_size: 4,
        padded: false,
        verified: Default::default(),
    };
    assert_eq!(tree.read_at(1, 2)?.as_ref(), b"OO");
    assert!(tree.read_at(3, 2).is_err());
    assert!(tree.read_at(8, 1).is_err());
    let mut padded = Sha256::default();
    padded.update(b"abc\0");
    let tree = integrity::HashLevel {
        source: source(b"abc".to_vec()),
        hashes: source(padded.finish().to_vec()),
        block_size: 4,
        padded: true,
        verified: Default::default(),
    };
    assert_eq!(tree.read_at(0, 3)?.as_ref(), b"abc");
    Ok(())
}

#[test]
fn hash_tree_reuses_successful_checks_without_reading_unrequested_blocks() -> Result<()> {
    let watched = Arc::new(Watched {
        bytes: b"GOODFAIL".to_vec(),
        payload: 4,
        reads: Mutex::default(),
    });
    let mut hashes = Sha256::digest(b"GOOD").to_vec();
    hashes.extend_from_slice(&Sha256::digest(b"FAIL"));
    let tree = integrity::HashLevel {
        source: watched.clone(),
        hashes: source(hashes),
        block_size: 4,
        padded: false,
        verified: Default::default(),
    };
    assert_eq!(tree.read_at(1, 2)?.as_ref(), b"OO");
    assert_eq!(tree.read_at(0, 1)?.as_ref(), b"G");
    assert_eq!(*watched.reads.lock().unwrap(), [(0, 4), (1, 2), (0, 1)]);
    assert!(tree.read_at(4, 1).is_err());
    assert_eq!(
        tree.verified
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        [0]
    );
    Ok(())
}

#[test]
fn plaintext_nca_mounts_only_header_and_preserves_raw_sections() -> Result<()> {
    let mut bytes = vec![0; 0xe00];
    bytes[0x200..0x204].copy_from_slice(b"NCA3");
    BinaryWriter::u64_le(0xe00, &mut bytes[0x208..]);
    BinaryWriter::u32_le(6, &mut bytes[0x240..]);
    BinaryWriter::u32_le(7, &mut bytes[0x244..]);
    bytes[0x402] = 1;
    bytes[0x403] = 1;
    bytes[0x404] = 1;
    let hash = Sha256::digest(&bytes[0x400..0x600]);
    bytes[0x280..0x2a0].copy_from_slice(&hash);
    let pfs = partition(false);
    bytes[0xc00..0xc00 + pfs.len()].copy_from_slice(&pfs);
    let watched = Arc::new(Watched {
        bytes: bytes.clone(),
        payload: 0xc00,
        reads: Mutex::default(),
    });
    let nca = Nca::open(watched)?;
    assert_eq!(nca.entries[0].name, "section0.pfs0");
    assert_eq!(nca.entries[0].kind, ResourceKind::Archive);
    let nca = Nca::open(source(bytes.clone()))?;
    let entry = &nca.entries[0];
    assert_eq!(nca.raw_source(entry)?.read_at(0, 4)?.as_ref(), b"PFS0");
    let fs = open_partition(
        nca.source(entry, &std::sync::atomic::AtomicBool::new(false))?,
        false,
    )?;
    assert_eq!(fs.read(&fs.entries[0])?.as_ref(), b"GOOD");
    bytes[0x405] ^= 1;
    assert!(matches!(
        Nca::open(source(bytes)),
        Err(Error::Corrupt { .. })
    ));
    Ok(())
}

#[test]
fn absent_user_keys_report_destination_and_never_use_bundled_keys() {
    let directory = std::env::temp_dir().join(format!("vnlens-ns-absent-{}", std::process::id()));
    let error = Keys::load(&directory).unwrap_err();
    assert!(matches!(error, Error::UnknownScheme(_)));
    let message = error.to_string();
    assert!(
        message.contains("prod.keys")
            && message.contains("obtain your own")
            && message.contains(&directory.display().to_string())
    );
    assert!(!format!("{:?}", Keys::default()).contains("values"));
}
