//! Local, licensed Escu:de sample; no images are displayed and no game is run.
//! NVLENS_ESCUDE_GAME=<game root> cargo test -p nvlens-archive --test escude_game -- --ignored --nocapture
use nvlens_core::{Archive, Catalog, Error, ResourceKind, ResourceResolver, Result};
use std::{collections::BTreeMap, path::PathBuf, sync::atomic::AtomicBool};

struct Resources<'a>(&'a dyn Archive, &'a str);
impl ResourceResolver for Resources<'_> {
    fn resource_name(&self) -> Option<&str> {
        Some(self.1)
    }
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if let Some(entry) = self
            .0
            .entries()
            .iter()
            .find(|e| e.name.replace('\\', "/").eq_ignore_ascii_case(name))
        {
            Ok(Some(self.0.open_entry(entry)?.into_owned()))
        } else {
            self.0.read_companion(name)
        }
    }
}

#[test]
#[ignore = "Requires NVLENS_ESCUDE_GAME pointing to the licensed Haison2_FD installation"]
fn validates_escude_archives_sources_and_structured_resources() -> Result<()> {
    nvlens_archive::init();
    nvlens_script::init();
    nvlens_image::init();
    nvlens_audio::init();
    let root = PathBuf::from(
        std::env::var_os("NVLENS_ESCUDE_GAME")
            .ok_or_else(|| Error::Unsupported("Set NVLENS_ESCUDE_GAME".into()))?,
    );
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::Escude);
    assert!(game.evidence.starts_with("PE features"));
    let catalog = Catalog::load();
    let mut types = BTreeMap::<String, usize>::new();
    let mut instructions = 0;
    let mut procedures = 0;
    let mut resolved_messages = 0;
    let mut mapped = BTreeMap::<String, usize>::new();
    for (file, count) in [
        ("bg.bin", 281),
        ("data.bin", 5),
        ("etc.bin", 35),
        ("ev.bin", 2314),
        ("gfx.bin", 2499),
        ("haison2_fd.bin", 118),
        ("script.bin", 116),
        ("snd.bin", 5488),
        ("st.bin", 1100),
        ("voc.bin", 4691),
    ] {
        let route = game.route(file).ok_or(Error::InvalidFormat)?;
        let archive = catalog.open(root.join(file), &route)?.archive;
        assert_eq!(archive.entries().len(), count, "{file}");
        let mut media = std::collections::BTreeSet::new();
        for entry in archive.entries() {
            let bytes = archive
                .open_entry(entry)
                .map_err(|error| Error::Unsupported(format!("{file}/{}: {error}", entry.name)))?;
            let raw = archive.open_entry_raw(entry)?;
            if raw.starts_with(b"acp\0") {
                assert_eq!(
                    bytes.len() as u64,
                    u64::from(nvlens_io::BinaryReader::u32_be(&raw[4..]))
                );
            } else {
                assert_eq!(&*raw, &*bytes);
            }
            let ext = entry
                .name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            *types.entry(ext.clone()).or_default() += 1;
            if let Some(tag) = game.script_format_for(&entry.name) {
                if let Some(script) = nvlens_script::disassemble_as(
                    tag,
                    &bytes,
                    Some(&Resources(&*archive, &entry.name)),
                )
                .map_err(|error| Error::Unsupported(format!("{file}/{}: {error}", entry.name)))?
                {
                    assert_eq!(
                        script
                            .sections
                            .iter()
                            .flat_map(|s| s.raw.iter())
                            .copied()
                            .collect::<Vec<_>>(),
                        &*bytes
                    );
                    assert!(!script.instructions.is_empty());
                    for i in &script.instructions {
                        if i.opcode.namespace == "escude.scenario" && i.opcode.code == 44 {
                            assert!(
                                i.opcode
                                    .native_mnemonic
                                    .as_deref()
                                    .is_some_and(|n| n.starts_with("proc_")),
                                "{} at {}",
                                entry.name,
                                i.span.offset
                            );
                            assert!(
                                i.args
                                    .iter()
                                    .any(|a| a.name == nvlens_script::ir::ArgName::Arguments)
                            );
                            *mapped.entry(i.opcode.operation.name().into()).or_default() += 1;
                            procedures += 1;
                        }
                        resolved_messages += usize::from(
                            i.args
                                .iter()
                                .any(|a| a.name == nvlens_script::ir::ArgName::Message),
                        );
                    }
                    instructions += script.instructions.len();
                } else if let Some(text) =
                    nvlens_script::decode_text_as(tag, &bytes).map_err(|error| {
                        Error::Unsupported(format!("{file}/{}: {error}", entry.name))
                    })?
                {
                    if let Ok(expected) = std::str::from_utf8(&bytes) {
                        assert_eq!(text, expected);
                    } else {
                        let (expected, _, errors) = encoding_rs::SHIFT_JIS.decode(&bytes);
                        assert!(!errors);
                        assert_eq!(text, expected);
                    }
                    assert!(!text.is_empty());
                } else {
                    return Err(Error::Unsupported(format!(
                        "No script reader for {file}/{}",
                        entry.name
                    )));
                }
            } else if media.insert(ext.clone()) {
                if entry.kind == ResourceKind::Image {
                    assert!(nvlens_image::metadata(&bytes)?.is_some());
                }
                if entry.kind == ResourceKind::Audio {
                    assert!(nvlens_audio::metadata(&bytes)?.is_some());
                }
            }
        }
        println!("{file}: {count} entries validated");
    }
    println!("Validated resource types {types:?}; {instructions} structured records/instructions");
    assert_eq!(procedures, 11483);
    assert!(resolved_messages >= 10980);
    println!(
        "Resolved {procedures} procedure calls and {resolved_messages} message references: {mapped:?}"
    );
    assert_eq!(types.get("c"), Some(&45));
    assert_eq!(types.get("h"), Some(&30));
    assert_eq!(types.get("inc"), Some(&43));
    assert_eq!(types.get("001"), Some(&56));
    assert_eq!(types.get("mot"), Some(&64));
    assert_eq!(types.get("lsf"), Some(&181));
    Ok(())
}
