#![allow(clippy::unwrap_used)]

use super::*;
use nvlens_io::BinaryWriter;
use std::fs;
use std::sync::atomic::AtomicU64;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "nvlens-browser-{}-{}-{}",
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
    nvlens_archive::init();
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
    nvlens_archive::init();
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let mut game =
        nvlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = nvlens_engine::Engine::SystemNnn;
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
fn propeller_mpeg_mpk_resolves_its_video_route_only_on_access() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut game =
        nvlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = nvlens_engine::Engine::Propeller;
    let path = dir.0.join("ma.mpk");
    let mut header = [0; 12];
    BinaryWriter::u32_le(0xba01_0000, &mut header);
    fs::write(&path, header)?;
    let item = Item::from_target(Target::File(path, Arc::new(game)), Some(12));
    assert_eq!(item.kind, ResourceKind::Archive);
    assert!(item.container);
    assert!(open(&item.target, &cancel, false)?.is_none());
    let resource = crate::resource::read(&item.target, false, &cancel)?;
    assert!(resource.bytes.is_empty());
    let input = resource
        .video
        .as_ref()
        .ok_or_else(|| anyhow!("Missing video input"))?;
    assert_eq!(&*input.source.read_at(0, header.len())?, &header);
    assert!(resource.image.is_none() && resource.script.is_none() && !resource.audio);
    Ok(())
}

#[test]
fn preview_and_export_share_the_selected_image_and_audio_routes() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let game = Arc::new(
        nvlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?,
    );
    let image = nvlens_image::Image {
        meta: nvlens_image::ImageMeta {
            width: 1,
            height: 1,
            bpp: 32,
            offset_x: 0,
            offset_y: 0,
            offset_unit: nvlens_image::OffsetUnit::Pixels,
        },
        pixels: nvlens_image::PixelBuffer::Rgba8(vec![12, 34, 56, 255]),
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
            &resource.bytes,
            &resource.route,
            crate::resource::ExportKind::Png,
            None,
            0,
        )?;
        assert_eq!(exported, png);
        assert!(
            crate::resource::convert(
                &resource.bytes,
                &resource.route,
                crate::resource::ExportKind::Wav,
                None,
                0
            )
            .is_err()
        );
    }
    let pcm = nvlens_audio::Pcm {
        meta: nvlens_audio::AudioMeta {
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
    let resource = crate::resource::read(&Target::File(path, game), false, &cancel)?;
    assert_eq!(resource.route, ResourceRoute::Audio("audio/standard"));
    assert!(resource.audio);
    let exported = crate::resource::convert(
        &resource.bytes,
        &resource.route,
        crate::resource::ExportKind::Wav,
        None,
        0,
    )?;
    assert_eq!(
        nvlens_audio::decode_as("audio/standard", &exported)?.samples,
        pcm.samples
    );
    Ok(())
}

#[test]
fn foreign_headerless_prefix_is_not_sent_to_global_decoders() -> Result<()> {
    let dir = temp();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut game =
        nvlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = nvlens_engine::Engine::Bgi;
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
        nvlens_engine::identify(&dir.0, &cancel)?.ok_or_else(|| anyhow!("Missing fixture host"))?;
    game.engine = nvlens_engine::Engine::Siglus;
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
    nvlens_archive::init();
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
