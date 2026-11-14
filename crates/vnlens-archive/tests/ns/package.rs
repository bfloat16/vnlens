use super::*;
use crate::ns::fixtures;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use vnlens_io::BinaryWriter;

#[test]
#[ignore = "Requires user-owned NS packages and keys; set VNLENS_NS_DIRECTORY"]
fn local_associated_packages() -> Result<()> {
    let directory = std::env::var_os("VNLENS_NS_DIRECTORY").ok_or(Error::InvalidFormat)?;
    let cancel = AtomicBool::new(false);
    let catalog = Catalog::load(Path::new(&directory), &cancel)?;
    for meta in &catalog.metadata {
        println!(
            "application={:016x} version={} patch={}",
            meta.application, meta.version, meta.patch
        );
        for content in &meta.contents {
            let nca = catalog.content(content)?;
            println!(
                "  {} kind={} index={}",
                content.id, content.kind, content.index
            );
            for entry in &nca.entries {
                let section = entry.name.as_bytes()[7] as usize - usize::from(b'0');
                let fs = &nca.identity()[0x400 + section * 512..0x600 + section * 512];
                println!(
                    "    {} encryption={} compression_at={} compression_size={}",
                    entry.name,
                    fs[4],
                    BinaryReader::u64_le(&fs[0x178..]),
                    BinaryReader::u64_le(&fs[0x180..])
                );
                let source = catalog
                    .resolve(&content.id, nca.identity(), section, &cancel)?
                    .map(Ok)
                    .unwrap_or_else(|| nca.source_with_base(section, None, &cancel))?;
                source.read_at(0, 16)?;
                println!("      ok size={}", source.len());
            }
        }
    }
    Ok(())
}

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn temp() -> std::io::Result<Temp> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "vnlens-ns-update-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path)?;
    Ok(Temp(path))
}
fn id(value: u8) -> String {
    format!("{value:02x}").repeat(16) + ".nca"
}
fn cnmt(application: u64, version: u32, patch: bool, content: u8, size: usize) -> Vec<u8> {
    let mut data = vec![0; 0x20 + if patch { 0x18 } else { 0x10 }];
    BinaryWriter::u64_le(
        if patch {
            application + 0x800
        } else {
            application
        },
        &mut data,
    );
    BinaryWriter::u32_le(version, &mut data[8..]);
    data[12] = if patch { 0x81 } else { 0x80 };
    BinaryWriter::u16_le(if patch { 0x18 } else { 0x10 }, &mut data[14..]);
    BinaryWriter::u16_le(1, &mut data[16..]);
    if patch {
        BinaryWriter::u64_le(application, &mut data[32..]);
    }
    let mut record = [0; 0x38];
    record[32..48].fill(content);
    BinaryWriter::u64_le(size as u64, &mut record[48..]);
    record[54] = 1;
    data.extend_from_slice(&record);
    data
}
fn package(
    directory: &Path,
    name: &str,
    application: u64,
    version: u32,
    patch: bool,
    content: u8,
    nca: &[u8],
) -> Result<()> {
    let meta = cnmt(application, version, patch, content, nca.len());
    let meta = fixtures::nca(
        &fixtures::pfs(&[("Application.cnmt", &meta)]),
        &fixtures::fs_header(),
        1,
    );
    let content_name = id(content);
    let meta_name = format!("{}.cnmt.nca", &id(content.wrapping_add(0x80))[..32]);
    std::fs::write(
        directory.join(name),
        fixtures::pfs(&[(&content_name, nca), (&meta_name, &meta)]),
    )?;
    Ok(())
}
fn selected(directory: &Path, nca: &[u8], content: u8) -> Result<Nca> {
    let mut options = vnlens_core::ArchiveOptions::default();
    options.paths.insert("ns_directory", directory.into());
    Ok(Nca::open(fixtures::source(nca.to_vec()))?.with_context(&id(content), &options))
}

#[test]
fn latest_related_cnmt_replaces_files_and_identification_reads_the_updated_directory() -> Result<()>
{
    let dir = temp()?;
    let application = 0x0100_1111_2222_0000;
    let base = fixtures::nca(
        &fixtures::pfs(&[("old.txt", b"old")]),
        &fixtures::fs_header(),
        0,
    );
    package(&dir.0, "base.nsp", application, 0, false, 1, &base)?;
    let old = fixtures::nca(
        &fixtures::pfs(&[("stale.txt", b"stale")]),
        &fixtures::fs_header(),
        0,
    );
    package(
        &dir.0,
        "zzz-old-update.nsp",
        application,
        65536,
        true,
        2,
        &old,
    )?;
    let data = fixtures::pfs(&[
        ("CONTENTS/SYSTEM.cpk", b"new"),
        ("CONTENTS/STORY.cpk", b"new"),
        ("CONTENTS/GAME.cpk", b"new"),
        ("CONTENTS/MOVIE.cpk", b"new"),
        ("CONTENTS/SOUND.cpk", b"new"),
    ]);
    let update = fixtures::nca(&data, &fixtures::fs_header(), 0);
    package(
        &dir.0,
        "aaa-new-update.nsp",
        application,
        131072,
        true,
        3,
        &update,
    )?;
    let unrelated = fixtures::nca(
        &fixtures::pfs(&[("foreign.txt", b"foreign")]),
        &fixtures::fs_header(),
        0,
    );
    package(
        &dir.0,
        "unrelated.nsp",
        application + 0x10000,
        u32::MAX,
        true,
        4,
        &unrelated,
    )?;
    let paths = Catalog::load(&dir.0, &AtomicBool::new(false))?
        .application_paths(&AtomicBool::new(false))?;
    for name in ["base.nsp", "zzz-old-update.nsp", "aaa-new-update.nsp"] {
        assert_eq!(paths.get(&dir.0.join(name)), Some(&dir.0.join("base.nsp")));
    }
    assert!(!paths.contains_key(&dir.0.join("unrelated.nsp")));
    for (bytes, content) in [(&base, 1), (&old, 2), (&update, 3)] {
        let nca = selected(&dir.0, bytes, content)?;
        let entry = &nca.entries[0];
        let fs = open_partition(
            nca.source(entry, &std::sync::atomic::AtomicBool::new(false))?,
            false,
        )?;
        assert_eq!(fs.entries.len(), 5);
        assert!(
            fs.entries
                .iter()
                .all(|entry| entry.name.starts_with("CONTENTS/"))
        );
        let root = PathBuf::from("updated.romfs");
        let mut files = vnlens_io::FileSystem::isolated(root.clone());
        for entry in &fs.entries {
            files.insert(root.join(&entry.name), fs.source(entry)?)?;
        }
        let host = vnlens_engine::identify(&dir.0.join("base.nsp"), &AtomicBool::new(false))?
            .ok_or(Error::InvalidFormat)?;
        let game = host.for_filesystem(root, Arc::new(files), &AtomicBool::new(false))?;
        assert_eq!(game.engine, vnlens_engine::Engine::Otomate);
        assert!(game.warning().is_none());
    }
    Ok(())
}

#[test]
fn sections_absent_from_patch_keep_their_base_filesystem() -> Result<()> {
    let dir = temp()?;
    let fs = fixtures::fs_header();
    let mut base = fixtures::nca(&fixtures::pfs(&[("main", b"old")]), &fs, 0);
    let start = base.len();
    base.resize(start + 512, 0);
    BinaryWriter::u64_le(base.len() as u64, &mut base[0x208..]);
    BinaryWriter::u32_le((start / 512) as u32, &mut base[0x250..]);
    BinaryWriter::u32_le((start / 512 + 1) as u32, &mut base[0x254..]);
    base[0x600..0x800].copy_from_slice(&fs);
    base[0x2a0..0x2c0].copy_from_slice(&vnlens_crypto::hash::sha256::Sha256::digest(&fs));
    let preserved = fixtures::pfs(&[("logo", b"base-only")]);
    base[start..start + preserved.len()].copy_from_slice(&preserved);
    let patch = fixtures::nca(&fixtures::pfs(&[("main", b"new")]), &fs, 0);
    package(&dir.0, "base.nsp", 1, 0, false, 1, &base)?;
    package(&dir.0, "patch.nsp", 1, 65536, true, 2, &patch)?;
    let selected = selected(&dir.0, &base, 1)?;
    for (entry, expected) in selected
        .entries
        .iter()
        .zip([&b"new"[..], &b"base-only"[..]])
    {
        let directory = open_partition(selected.source(entry, &AtomicBool::new(false))?, false)?;
        assert_eq!(directory.read(&directory.entries[0])?.as_ref(), expected);
    }
    Ok(())
}

#[test]
fn bktr_update_reads_original_and_patch_spans_and_raw_storage_stays_original() -> Result<()> {
    let dir = temp()?;
    let application = 0x0100_2222_3333_0000;
    let data = fixtures::pfs(&[("file.txt", b"old")]);
    let base = fixtures::nca(&data, &fixtures::fs_header(), 0);
    package(&dir.0, "base.nsp", application, 0, false, 1, &base)?;
    let changed = data.len() - 3;
    let mut first = vec![0; 20];
    let mut second = vec![0; 20];
    BinaryWriter::u64_le(changed as u64, &mut second);
    BinaryWriter::u32_le(1, &mut second[16..]);
    let (header, table) = fixtures::table(&[std::mem::take(&mut first), second], data.len() as u64);
    let mut fs = fixtures::fs_header();
    BinaryWriter::u64_le(512, &mut fs[0x100..]);
    BinaryWriter::u64_le(table.len() as u64, &mut fs[0x108..]);
    fs[0x110..0x120].copy_from_slice(&header);
    let mut body = vec![0; 512];
    body[..3].copy_from_slice(b"new");
    body.extend(table);
    let update = fixtures::nca(&body, &fs, 0);
    package(&dir.0, "patch.nsp", application, 65536, true, 2, &update)?;
    let nca = selected(&dir.0, &base, 1)?;
    let fs = open_partition(
        nca.source(&nca.entries[0], &std::sync::atomic::AtomicBool::new(false))?,
        false,
    )?;
    assert_eq!(fs.read(&fs.entries[0])?.as_ref(), b"new");
    let raw = open_partition(nca.raw_source(&nca.entries[0])?, false)?;
    assert_eq!(raw.read(&raw.entries[0])?.as_ref(), b"old");
    std::fs::remove_file(dir.0.join("base.nsp"))?;
    let nca = selected(&dir.0, &update, 2)?;
    assert!(matches!(
        nca.source(&nca.entries[0], &std::sync::atomic::AtomicBool::new(false)),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}

#[test]
fn cnmt_truncation_conflicting_versions_and_absent_newer_content_are_errors() -> Result<()> {
    let data = cnmt(1, 1, true, 1, 0xc00);
    for end in 0..data.len() {
        assert!(parse(&data[..end]).is_err());
    }
    let dir = temp()?;
    let nca = fixtures::nca(
        &fixtures::pfs(&[("file", b"new")]),
        &fixtures::fs_header(),
        0,
    );
    package(&dir.0, "base.nsp", 1, 0, false, 1, &nca)?;
    package(&dir.0, "first.nsp", 1, 1, true, 2, &nca)?;
    package(&dir.0, "conflict.nsp", 1, 1, true, 3, &nca)?;
    let current = selected(&dir.0, &nca, 1)?;
    assert!(matches!(
        current.source(&current.entries[0], &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        current.source(
            &current.entries[0],
            &std::sync::atomic::AtomicBool::new(false)
        ),
        Err(Error::Corrupt { .. })
    ));
    drop(current);
    std::fs::remove_file(dir.0.join("conflict.nsp"))?;
    let meta = cnmt(1, 2, true, 7, nca.len());
    let meta = fixtures::nca(
        &fixtures::pfs(&[("Patch.cnmt", &meta)]),
        &fixtures::fs_header(),
        1,
    );
    std::fs::write(
        dir.0.join("first.nsp"),
        fixtures::pfs(&[("missing.cnmt.nca", &meta)]),
    )?;
    let current = selected(&dir.0, &nca, 1)?;
    assert!(matches!(
        current.source(
            &current.entries[0],
            &std::sync::atomic::AtomicBool::new(false)
        ),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}
