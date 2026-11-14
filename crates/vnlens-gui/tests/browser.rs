#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::sync::atomic::AtomicU64;
use vnlens_io::BinaryWriter;

#[test]
#[ignore = "Requires user-owned base/update packages and keys; set VNLENS_NS_BASE and VNLENS_NS_PATCH"]
fn ns_local_associated_application() -> Result<()> {
    vnlens_archive::init();
    let base = PathBuf::from(
        std::env::var_os("VNLENS_NS_BASE").ok_or_else(|| anyhow!("Set VNLENS_NS_BASE"))?,
    );
    let patch = PathBuf::from(
        std::env::var_os("VNLENS_NS_PATCH").ok_or_else(|| anyhow!("Set VNLENS_NS_PATCH"))?,
    );
    let cancel = AtomicBool::new(false);
    let base_item = Item::from_path(base.clone())?;
    let patch_item = Item::from_path(patch)?;
    assert!(base_item.target.same(&patch_item.target));
    assert_eq!(base_item.name, base.file_name().unwrap().to_string_lossy());
    let mut selected = Folder::empty(Target::Opened);
    selected.insert(base_item);
    selected.insert(patch_item);
    assert_eq!(selected.items.len(), 1);
    let mut pending = vec![selected.items[0].target.clone()];
    let mut banks = 0;
    let mut files = 0;
    while let Some(target) = pending.pop() {
        let folder = open(&target, &cancel, false)?
            .ok_or_else(|| anyhow!("Expected folder {}", target.name()))?;
        for item in folder.items {
            if item.name.ends_with(".cpk") {
                assert_eq!(
                    item.target.game().map(|game| game.engine),
                    Some(vnlens_engine::Engine::Otomate)
                );
                assert!(item.target.warning().is_none());
                let bank =
                    open(&item.target, &cancel, false)?.ok_or_else(|| anyhow!("Missing CPK"))?;
                println!("{}: {} indexed items", item.name, bank.items.len());
                banks += 1;
            } else if item.target.is_directory()
                && !matches!(item.name.as_str(), "update" | "normal" | "logo")
            {
                pending.push(item.target);
            } else if let Target::File(path, game) = item.target {
                let source = game.files.source(&path)?;
                source.read_at(0, source.len().min(16) as usize)?;
                files += 1;
            }
        }
    }
    assert!(files > 0 || banks > 0);
    println!("one base entry, {files} file prefixes verified, {banks} CPK banks");
    Ok(())
}

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "vnlens-browser-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    fs::write(path.join("AdvHD.exe"), []).unwrap();
    fs::write(path.join("Script2.arc"), []).unwrap();
    fs::write(path.join("Graphic.arc"), []).unwrap();
    Temp(path)
}
fn fixture(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut index = vec![0; 8];
    BinaryWriter::u32_le(payload.len() as u32, &mut index);
    for unit in name.encode_utf16().chain([0]) {
        let mut word = [0; 2];
        BinaryWriter::u16_le(unit, &mut word);
        index.extend(word);
    }
    let mut bytes = vec![0; 8];
    BinaryWriter::u32_le(1, &mut bytes);
    BinaryWriter::u32_le(index.len() as u32, &mut bytes[4..]);
    bytes.extend(index);
    bytes.extend_from_slice(payload);
    bytes
}

fn pfs_fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut names = Vec::new();
    let mut records = Vec::new();
    let mut payloads = Vec::new();
    for (name, payload) in entries {
        let mut record = [0; 24];
        BinaryWriter::u64_le(payloads.len() as u64, &mut record);
        BinaryWriter::u64_le(payload.len() as u64, &mut record[8..]);
        BinaryWriter::u32_le(names.len() as u32, &mut record[16..]);
        records.extend(record);
        names.extend(name.as_bytes());
        names.push(0);
        payloads.extend_from_slice(payload);
    }
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(b"PFS0");
    BinaryWriter::u32_le(entries.len() as u32, &mut bytes[4..]);
    BinaryWriter::u32_le(names.len() as u32, &mut bytes[8..]);
    bytes.extend(records);
    bytes.extend(names);
    bytes.extend(payloads);
    bytes
}

#[test]
fn ns_transport_folders_identify_each_inner_game_without_reading_resource_bodies() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let game = pfs_fixture(&[
        ("CONTENTS/SYSTEM.cpk", b"unrequested"),
        ("CONTENTS/STORY.cpk", b"unrequested"),
        ("CONTENTS/GAME.cpk", b"unrequested"),
        ("CONTENTS/MOVIE.cpk", b"unrequested"),
        ("CONTENTS/SOUND.cpk", b"unrequested"),
        ("scene.dat", b"unrequested"),
    ]);
    let unknown = pfs_fixture(&[("scene.dat", b"unknown"), ("info.txt", b"info")]);
    let path = dir.0.join("package.nsp");
    fs::write(
        &path,
        pfs_fixture(&[
            ("title.pfs0", &game),
            ("other.pfs0", &unknown),
            ("broken.nca", b"unrequested"),
        ]),
    )?;
    let item = Item::from_path(path)?;
    assert!(item.target.is_directory());
    assert!(item.target.warning().is_none());
    assert!(!item.can_preview());
    let package =
        open(&item.target, &cancel, false)?.ok_or_else(|| anyhow!("Missing NSP folder"))?;
    assert!(package.target.is_directory());
    assert!(package.target.warning().is_none());
    assert!(package.items.iter().all(|item| item.target.is_directory()));
    let title = package
        .items
        .iter()
        .find(|item| item.name == "title.pfs0")
        .unwrap();
    let title =
        open(&title.target, &cancel, false)?.ok_or_else(|| anyhow!("Missing title folder"))?;
    let Target::Directory(_, game) = &title.target else {
        return Err(anyhow!(
            "Game files were not mounted as a virtual directory"
        ));
    };
    assert_eq!(game.engine, vnlens_engine::Engine::Otomate);
    assert!(title.target.warning().is_none());
    let script = title
        .items
        .iter()
        .find(|item| item.name == "scene.dat")
        .unwrap();
    assert_eq!(
        script.target.resource_route(&[])?,
        ResourceRoute::Script("stcm2/otomate")
    );
    let contents = title
        .items
        .iter()
        .find(|item| item.name == "CONTENTS")
        .unwrap();
    let contents = open(&contents.target, &cancel, false)?.unwrap();
    assert!(contents.target.warning().is_none());
    assert_eq!(contents.items.len(), 5);
    let other = package
        .items
        .iter()
        .find(|item| item.name == "other.pfs0")
        .unwrap();
    let other = open(&other.target, &cancel, false)?.unwrap();
    assert!(other.target.warning().is_some());
    let script = other
        .items
        .iter()
        .find(|item| item.name == "scene.dat")
        .unwrap();
    assert_eq!(
        script.target.resource_route(&[])?,
        ResourceRoute::Other(ResourceKind::Unknown)
    );
    assert!(package.target.warning().is_none());
    assert!(
        open(
            &package
                .items
                .iter()
                .find(|item| item.name == "broken.nca")
                .unwrap()
                .target,
            &cancel,
            false
        )
        .is_err()
    );
    assert!(matches!(
        open(&item.target, &AtomicBool::new(true), false)
            .unwrap_err()
            .downcast_ref(),
        Some(vnlens_core::Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn ns_folders_export_their_virtual_files_instead_of_transport_bytes() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let inner = pfs_fixture(&[("folder/leaf.txt", b"leaf")]);
    let path = dir.0.join("package.nsp");
    fs::write(&path, pfs_fixture(&[("child.pfs0", &inner)]))?;
    let item = Item::from_path(path)?;
    let output = dir.0.join("output");
    let result = export(
        std::slice::from_ref(&item),
        &output,
        false,
        &cancel,
        |_, _| {},
    )?;
    assert_eq!(result.progress.succeeded, 1);
    assert_eq!(
        fs::read(output.join("package.nsp/child.pfs0/folder/leaf.txt"))?,
        b"leaf"
    );
    let folder = open(&item.target, &cancel, false)?.unwrap();
    let output = dir.0.join("entry-output");
    // The common-archive export shortcut must also expand an NS directory.
    let result = export(&folder.items, &output, true, &cancel, |_, _| {})?;
    assert_eq!(result.progress.succeeded, 1);
    assert_eq!(
        fs::read(output.join("child.pfs0/folder/leaf.txt"))?,
        b"leaf"
    );
    Ok(())
}

#[test]
fn ns_filesystems_browse_as_isolated_folders_with_safe_unknown_previews() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let inner = pfs_fixture(&[("leaf.txt", b"leaf")]);
    let path = dir.0.join("game.nsp");
    fs::write(
        &path,
        pfs_fixture(&[
            ("GAME.cpk", b"broken CPK"),
            ("unknown.g00", b"plain text with unknown suffix"),
            ("child.nsp", &inner),
            ("folder/info.txt", b"info"),
        ]),
    )?;
    let item = Item::from_path(path)?;
    let folder = open(&item.target, &cancel, false)?.unwrap();
    assert!(matches!(folder.target, Target::Directory(..)));
    assert!(folder.target.warning().is_some());
    assert_eq!(folder.items.len(), 4);
    let cpk = folder
        .items
        .iter()
        .find(|item| item.name == "GAME.cpk")
        .unwrap();
    assert!(cpk.container);
    assert!(open(&cpk.target, &cancel, false).is_err());
    let unknown = folder
        .items
        .iter()
        .find(|item| item.name == "unknown.g00")
        .unwrap();
    let resource = crate::resource::read(&unknown.target, false, &cancel)?;
    assert_eq!(resource.route, ResourceRoute::Other(ResourceKind::Unknown));
    assert!(
        resource.image.is_none()
            && resource.script.is_none()
            && !resource.audio
            && resource.video.is_none()
    );
    assert_eq!(&*resource.bytes, b"plain text with unknown suffix");
    let child = folder
        .items
        .iter()
        .find(|item| item.name == "child.nsp")
        .unwrap();
    let child = open(&child.target, &cancel, false)?.unwrap();
    assert!(matches!(child.target, Target::Directory(..)));
    assert_eq!(child.items[0].target.read(false, &cancel)?, b"leaf");
    // A sibling from the real installation cannot become an engine or key
    // source for this independent virtual filesystem.
    let Target::Directory(root, game) = &folder.target else {
        return Err(anyhow!("Missing NS folder"));
    };
    assert!(!game.files.is_file(&root.join("AdvHD.exe")));
    assert_eq!(game.engine, vnlens_engine::Engine::NintendoSwitch);
    Ok(())
}

#[test]
fn standalone_archives_cannot_bypass_engine_identification() {
    let dir = temp();
    for name in ["AdvHD.exe", "Script2.arc", "Graphic.arc"] {
        fs::remove_file(dir.0.join(name)).unwrap();
    }
    let archive = dir.0.join("valid.arc");
    fs::write(&archive, fixture("data.txt", b"contents")).unwrap();
    assert!(Item::from_path(archive).is_err());
    assert!(Item::from_path(dir.0.clone()).is_err());
}

#[test]
fn lists_disk_without_mounting_archives_or_reading_files() {
    vnlens_archive::init();
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut invalid = vec![0; 32];
    invalid[..4].copy_from_slice(b"YPF\0");
    fs::write(dir.0.join("broken.arc"), invalid).unwrap();
    fs::write(dir.0.join("note.txt"), b"old").unwrap();
    fs::create_dir(dir.0.join("folder")).unwrap();
    let folder = open(
        &Item::from_path(dir.0.clone()).unwrap().target,
        &cancel,
        false,
    )
    .unwrap()
    .unwrap();
    assert_eq!(folder.items.len(), 6);
    let archive = folder
        .items
        .iter()
        .find(|item| item.name == "broken.arc")
        .unwrap();
    assert!(archive.container);
    assert!(open(&archive.target, &cancel, false).is_err());
    let file = folder
        .items
        .iter()
        .find(|item| item.name == "note.txt")
        .unwrap();
    fs::write(dir.0.join("note.txt"), b"changed after listing").unwrap();
    let resource = crate::resource::read(&file.target, false, &cancel).unwrap();
    assert_eq!(&*resource.bytes, b"changed after listing");
}

#[test]
fn archive_sets_open_one_logical_archive_and_export_physical_names() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let mut game =
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = vnlens_engine::Engine::SystemNnn;
    let game = Arc::new(game);
    let data = dir.0.join("voice.vpk");
    let index = dir.0.join("voice.vtb");
    fs::write(&data, b"audio")?;
    fs::write(&index, b"broken")?;
    let target = Target::Directory(dir.0.clone(), game.clone());
    // A broken index cannot prevent grouping: directory listing reads no
    // archive index or payload. Only opening the group parses its index.
    let folder = open(&target, &cancel, false)?.ok_or_else(|| anyhow!("Missing folder"))?;
    let item = folder
        .items
        .iter()
        .find(|item| item.name == "voice.vpk")
        .ok_or_else(|| anyhow!("Missing archive group"))?;
    assert!(matches!(item.target, Target::ArchiveSet(..)));
    assert_eq!(item.count, Some(2));
    assert!(item.container);
    assert!(!folder.items.iter().any(|item| item.name == "voice.vtb"));
    assert!(open(&item.target, &cancel, false).is_err());
    let mut table = [0; 24];
    table[..5].copy_from_slice(b"line1");
    BinaryWriter::u32_le(5, &mut table[20..]);
    fs::write(&index, table)?;
    let resources =
        open(&item.target, &cancel, false)?.ok_or_else(|| anyhow!("Missing archive contents"))?;
    assert_eq!(resources.items.len(), 1);
    assert_eq!(resources.items[0].name, "line1.vaw");
    assert_eq!(resources.items[0].target.read(true, &cancel)?, b"audio");
    let out = dir.0.join("export");
    let result = export(std::slice::from_ref(item), &out, true, &cancel, |_, _| {})?;
    assert_eq!((result.progress.succeeded, result.progress.failed), (2, 0));
    assert_eq!(fs::read(out.join("voice.vpk"))?, b"audio");
    assert_eq!(fs::read(out.join("voice.vtb"))?, table);
    let again = Item::from_set(
        ArchiveSet {
            primary: data.clone(),
            members: vec![data, index],
        },
        game,
    );
    assert!(again.target.same(&item.target));
    Ok(())
}

#[test]
fn registered_archive_suffix_does_not_switch_to_video_on_access() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut game =
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = vnlens_engine::Engine::Propeller;
    let path = dir.0.join("ma.mpk");
    let mut header = [0; 12];
    BinaryWriter::u32_le(0xba01_0000, &mut header);
    fs::write(&path, header)?;
    let item = Item::from_target(Target::File(path, Arc::new(game)), Some(12));
    assert_eq!(item.kind, ResourceKind::Archive);
    assert!(item.container);
    assert!(open(&item.target, &cancel, false).is_err());
    let resource = crate::resource::read(&item.target, false, &cancel)?;
    assert!(resource.bytes.is_empty());
    assert!(
        matches!(resource.route, ResourceRoute::Archive(route) if route.tag == "mpk/propeller")
    );
    assert!(resource.video.is_none());
    assert_eq!(item.target.read(true, &cancel)?, header);
    assert!(resource.image.is_none() && resource.script.is_none() && !resource.audio);
    Ok(())
}

#[test]
fn preview_and_export_share_the_selected_image_and_audio_routes() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let game = Arc::new(
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let image = vnlens_image::Image {
        meta: vnlens_image::ImageMeta {
            width: 1,
            height: 1,
            bpp: 32,
            offset_x: 0,
            offset_y: 0,
            offset_unit: vnlens_image::OffsetUnit::Pixels,
        },
        pixels: vnlens_image::PixelBuffer::Rgba8(vec![12, 34, 56, 255]),
    };
    let png = image.to_png()?;
    // ARC entries have no type field. Both disk and archive access must use
    // the identified host's resource route, even with an unknown entry name.
    fs::write(dir.0.join("cg.png"), &png)?;
    fs::write(dir.0.join("cg.arc"), fixture("00001", &png))?;
    let archive = Arc::new(
        MountedArchive::open(dir.0.join("cg.arc"), false, game.clone())?
            .ok_or_else(|| anyhow!("Missing fixture archive"))?,
    );
    for target in [
        Target::File(dir.0.join("cg.png"), game.clone()),
        Target::Entry { archive, index: 0 },
    ] {
        let resource = crate::resource::read(&target, false, &cancel)?;
        assert_eq!(resource.route, ResourceRoute::Image("image/standard"));
        assert!(resource.image.is_some());
        assert!(resource.script.is_none());
        let exported = crate::resource::convert(
            &target,
            &resource.bytes,
            &resource.route,
            crate::resource::ExportKind::Png,
            None,
            0,
        )?;
        assert_eq!(exported, png);
        assert!(
            crate::resource::convert(
                &target,
                &resource.bytes,
                &resource.route,
                crate::resource::ExportKind::Wav,
                None,
                0
            )
            .is_err()
        );
    }
    let pcm = vnlens_audio::Pcm {
        meta: vnlens_audio::AudioMeta {
            codec: "fixture",
            channels: 2,
            sample_rate: 48000,
            frames: Some(2),
        },
        samples: Arc::from([0.25, -0.5, 0.75, -1.]),
    };
    let wav = pcm.to_wav()?;
    let path = dir.0.join("voice.wav");
    fs::write(&path, &wav)?;
    let target = Target::File(path, game);
    let resource = crate::resource::read(&target, false, &cancel)?;
    assert_eq!(resource.route, ResourceRoute::Audio("audio/standard"));
    assert!(resource.audio);
    let exported = crate::resource::convert(
        &target,
        &resource.bytes,
        &resource.route,
        crate::resource::ExportKind::Wav,
        None,
        0,
    )?;
    assert_eq!(
        vnlens_audio::decode_as("audio/standard", &exported)?.samples,
        pcm.samples
    );
    Ok(())
}

#[test]
fn psb_navigation_and_pimg_preview_follow_the_host_route() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let host = Arc::new(
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let mut game = (*host).clone();
    game.engine = vnlens_engine::Engine::Krkr;
    let game = Arc::new(game);
    for name in ["map.pimg", "00001"] {
        let path = dir.0.join("ui.arc");
        // A prefix is sufficient to route access; preview must not parse the
        // PSB index or synthesize a root-object view before navigation.
        fs::write(&path, fixture(name, b"PSB\0"))?;
        let mut archive = MountedArchive::open(path, false, host.clone())?
            .ok_or_else(|| anyhow!("Missing fixture archive"))?;
        archive.game = game.clone();
        let mut item = Folder::archive(Arc::new(archive), 0).items.remove(0);
        if name == "map.pimg" {
            assert!(item.container);
            assert!(!item.can_preview());
            item.set_compose_pimg(true);
            assert!(!item.container);
            assert!(item.can_preview());
            assert_eq!(
                item.target.resource_route(b"PSB\0")?,
                ResourceRoute::Image("pimg/krkr")
            );
            assert!(open(&item.target, &cancel, false)?.is_none());
            item.set_compose_pimg(false);
            assert!(!item.can_preview());
        } else {
            assert!(!item.container);
            let resource = crate::resource::read(&item.target, false, &cancel)?;
            assert!(matches!(resource.route, ResourceRoute::Archive(_)));
            assert!(resource.psb.is_none());
            assert!(resource.bytes.is_empty());
            // Header-based navigation marks this row as a container. The
            // preview action must remain unavailable on subsequent clicks.
            item.container = true;
            assert!(!item.can_preview());
        }
    }
    Ok(())
}

fn psb_fixture(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 44];
    bytes[..4].copy_from_slice(b"PSB\0");
    BinaryWriter::u16_le(3, &mut bytes[4..]);
    BinaryWriter::u32_le(44, &mut bytes[8..]);
    let names = bytes.len();
    bytes.extend([0x0d, 0, 0x0d].repeat(3));
    let strings = bytes.len();
    bytes.extend([0x0d, 0, 0x0d]);
    let root = bytes.len();
    bytes.push(2);
    let offsets = bytes.len();
    bytes.extend([0x0d, 1, 0x0d, 0]);
    let lengths = bytes.len();
    bytes.extend([0x0d, 1, 0x10]);
    let mut length = [0; 4];
    BinaryWriter::u32_le(u32::try_from(payload.len()).unwrap(), &mut length);
    bytes.extend(length);
    let data = bytes.len();
    bytes.extend(payload);
    for (at, offset) in [
        (12, names),
        (16, strings),
        (20, data),
        (24, offsets),
        (28, lengths),
        (32, data),
        (36, root),
    ] {
        BinaryWriter::u32_le(u32::try_from(offset).unwrap(), &mut bytes[at..]);
    }
    bytes
}

#[test]
fn psb_scenario_members_are_containers_before_access() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let host = Arc::new(
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let mut game = (*host).clone();
    game.engine = vnlens_engine::Engine::Krkr;
    let game = Arc::new(game);
    let payload = psb_fixture(b"res");
    let path = dir.0.join("ks.scn");
    fs::write(&path, &payload)?;
    let item = Item::from_target(Target::File(path, game.clone()), None);
    assert!(item.container);
    assert_eq!(item.kind, ResourceKind::Archive);
    assert!(!item.can_preview());
    assert_eq!(open(&item.target, &cancel, false)?.unwrap().items.len(), 2);
    // Both stored and recovered SCN names classify the container without
    // reading its contents or first opening a script preview.
    for (stored, recovered) in [
        ("ks.scn", "ks.scn"),
        ("00001", "scenario/ks.scn"),
        ("ks.scn", "00001"),
    ] {
        let path = dir.0.join("scenario.arc");
        fs::write(&path, fixture(stored, &payload))?;
        let mut archive = MountedArchive::open(path, false, host.clone())?.unwrap();
        archive.game = game.clone();
        let archive = Arc::new(archive.with_paths(vec![recovered.into()])?);
        let target = Target::Entry { archive, index: 0 };
        let item = Item::from_target(target.clone(), None);
        assert!(item.container);
        assert_eq!(item.kind, ResourceKind::Archive);
        assert!(!item.can_preview());
        let preview = crate::resource::read(&target, false, &cancel)?;
        assert!(matches!(preview.route, ResourceRoute::Archive(ref route) if route.tag == "psb"));
        assert!(preview.psb.is_none() && preview.bytes.is_empty());

        let folder = open(&target, &cancel, false)?.unwrap();
        assert_eq!(folder.items.len(), 2);
        let value = folder
            .items
            .iter()
            .find(|item| item.name == "root")
            .unwrap();
        assert!(!value.container);
        assert!(open(&value.target, &cancel, false)?.is_none());
        let preview = crate::resource::read(&value.target, false, &cancel)?;
        assert_eq!(preview.route, ResourceRoute::Other(ResourceKind::Data));
        assert_eq!(
            preview.psb.as_ref().and_then(|value| value.value()),
            Some(&vnlens_middleware::psb::PsbValue::Bool(true))
        );
        assert!(preview.bytes.is_empty());
        let resource = folder
            .items
            .iter()
            .find(|item| item.name == "resources")
            .unwrap();
        let resources = open(&resource.target, &cancel, false)?.unwrap();
        assert_eq!(resources.items[0].target.read(false, &cancel)?, b"res");
    }
    Ok(())
}

#[test]
fn malformed_psb_scenario_members_return_the_directed_archive_error() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let host = Arc::new(
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let path = dir.0.join("scenario.arc");
    fs::write(&path, fixture("ks.scn", b"PSB\0"))?;
    let mut archive = MountedArchive::open(path, false, host.clone())?.unwrap();
    let mut game = (*host).clone();
    game.engine = vnlens_engine::Engine::Krkr;
    archive.game = Arc::new(game);
    let target = Target::Entry {
        archive: Arc::new(archive),
        index: 0,
    };
    assert!(target.archive_hint());
    let error = open(&target, &cancel, false).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<vnlens_core::Error>(),
        Some(vnlens_core::Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
    Ok(())
}

#[test]
fn nested_psb_navigation_preserves_context_and_defers_child_errors() -> Result<()> {
    vnlens_archive::init();
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let host = Arc::new(
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let mut game = (*host).clone();
    game.engine = vnlens_engine::Engine::Krkr;
    let game = Arc::new(game);
    for leaf in [b"leaf".as_slice(), b"PSB\0"] {
        let mut payload = leaf.to_vec();
        for _ in 0..4 {
            payload = psb_fixture(&payload);
        }
        let path = dir.0.join("nested.arc");
        fs::write(&path, fixture("chapter.ks.scn", &payload))?;
        let mut archive = MountedArchive::open(path, false, host.clone())?.unwrap();
        archive.game = game.clone();
        let mut target = Target::Entry {
            archive: Arc::new(archive),
            index: 0,
        };
        for _ in 0..4 {
            let folder = open(&target, &cancel, false)?.unwrap();
            let Target::ArchiveDirectory { archive, .. } = &folder.target else {
                return Err(anyhow!("Missing nested PSB mount"));
            };
            assert!(Arc::ptr_eq(&archive.game, &game));
            let directory = folder
                .items
                .iter()
                .find(|item| item.name == "resources")
                .unwrap();
            let resources = open(&directory.target, &cancel, false)?.unwrap();
            assert_eq!(resources.items.len(), 1);
            target = resources.items[0].target.clone();
        }
        assert_eq!(target.read(false, &cancel)?, leaf);
        if leaf == b"PSB\0" {
            assert!(open(&target, &cancel, false).is_err());
        } else {
            assert!(open(&target, &cancel, false)?.is_none());
        }
    }
    Ok(())
}

#[test]
fn foreign_headerless_prefix_is_not_sent_to_global_decoders() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut game =
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = vnlens_engine::Engine::Bgi;
    let path = dir.0.join("unknown");
    let mut bytes = vec![0; 44];
    BinaryWriter::u16_le(2, &mut bytes);
    BinaryWriter::u16_le(16, &mut bytes[2..]);
    fs::write(&path, &bytes)?;
    let resource = crate::resource::read(&Target::File(path, Arc::new(game)), false, &cancel)?;
    assert_eq!(resource.route, ResourceRoute::Other(ResourceKind::Unknown));
    assert_eq!(&*resource.bytes, &bytes);
    assert!(resource.image.is_none() && resource.script.is_none() && !resource.audio);
    Ok(())
}

#[test]
fn a_selected_native_decoder_error_does_not_fall_through() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut game =
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = vnlens_engine::Engine::Siglus;
    let path = dir.0.join("broken.g00");
    fs::write(&path, b"not a G00")?;
    let target = Target::File(path, Arc::new(game));
    assert!(crate::resource::read(&target, false, &cancel).is_err());
    assert_eq!(
        &*crate::resource::read(&target, true, &cancel)?.bytes,
        b"not a G00"
    );
    Ok(())
}

#[test]
fn traverses_disk_archive_directories_and_nested_archives() {
    vnlens_archive::init();
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let inner = fixture("leaf.txt", b"leaf");
    fs::write(dir.0.join("outer.arc"), fixture("nested/inner.arc", &inner)).unwrap();
    let disk = open(
        &Item::from_path(dir.0.clone()).unwrap().target,
        &cancel,
        false,
    )
    .unwrap()
    .unwrap();
    let outer = open(
        &disk
            .items
            .iter()
            .find(|item| item.name == "outer.arc")
            .unwrap()
            .target,
        &cancel,
        false,
    )
    .unwrap()
    .unwrap();
    let nested = open(&outer.items[0].target, &cancel, false)
        .unwrap()
        .unwrap();
    assert!(nested.items[0].container);
    let inner = open(&nested.items[0].target, &cancel, false)
        .unwrap()
        .unwrap();
    assert_eq!(inner.items[0].target.read(false, &cancel).unwrap(), b"leaf");
    assert!(!inner.items[0].container);
}

#[test]
fn disk_export_continues_after_failure_and_honors_cancellation() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let missing = dir.0.join("missing.txt");
    let good = dir.0.join("good.txt");
    fs::write(&missing, b"gone").unwrap();
    fs::write(&good, b"ok").unwrap();
    let items = vec![
        Item::from_path(missing.clone()).unwrap(),
        Item::from_path(good).unwrap(),
    ];
    fs::remove_file(missing).unwrap();
    let out = dir.0.join("out");
    let result = export(&items, &out, false, &cancel, |_, _| {}).unwrap();
    assert_eq!((result.progress.succeeded, result.progress.failed), (1, 1));
    assert_eq!(fs::read(out.join("good.txt")).unwrap(), b"ok");
    cancel.store(true, Ordering::Relaxed);
    let result = export(&items, &dir.0.join("cancelled"), false, &cancel, |_, _| {}).unwrap();
    assert!(result.cancelled);
    assert_eq!(result.progress.completed, 0);
    assert!(!dir.0.join("cancelled").exists());
}

#[test]
fn root_folder_insert_sorts_alphabetically_and_deduplicates() -> Result<()> {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let game = Arc::new(
        vnlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let mut root = Folder::empty(Target::Opened);
    let file_b = Item::from_target(Target::File(dir.0.join("b.txt"), game.clone()), Some(1));
    let dir_c = Item::from_target(Target::Directory(dir.0.join("Charlie"), game.clone()), None);
    let dir_a = Item::from_target(Target::Directory(dir.0.join("alpha"), game.clone()), None);
    let dir_b = Item::from_target(Target::Directory(dir.0.join("Bravo"), game.clone()), None);
    let file_a = Item::from_target(Target::File(dir.0.join("a.txt"), game), Some(1));

    assert_eq!(root.insert(file_b), 0);
    assert_eq!(root.insert(dir_c.clone()), 0);
    assert_eq!(root.insert(dir_a), 0);
    assert_eq!(root.insert(dir_b), 1);
    assert_eq!(root.insert(file_a), 3);
    assert_eq!(root.insert(dir_c), 2);
    assert_eq!(
        root.items
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "Bravo", "Charlie", "a.txt", "b.txt"]
    );
    Ok(())
}
