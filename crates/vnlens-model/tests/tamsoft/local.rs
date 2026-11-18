use super::*;
use std::path::PathBuf;
use vnlens_core::{Catalog, ResourceOrigin, ResourceRoute};

#[test]
#[ignore = "Requires installed ToHeart PC; set VNLENS_TAMSOFT_DIR"]
fn toheart_character_field_and_ui_geometry() -> Result<()> {
    vnlens_archive::init();
    let root = PathBuf::from(std::env::var_os("VNLENS_TAMSOFT_DIR").ok_or(Error::InvalidFormat)?);
    let game =
        vnlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    let catalog = Catalog::load();
    for (name, expected) in [
        ("Model/Chara/Body/pl000_cos00.cat", Some((46561, 22))),
        ("Model/Field/bg000_00_far.cat", Some((1643, 2))),
        ("UI/AdvUI.cat", None),
    ] {
        let path = root.join(name);
        let ResourceRoute::Archive(route) = game.route_path(&path)? else {
            return Err(Error::InvalidFormat);
        };
        let mut pending = vec![catalog.open(&path, &route)?.archive];
        let mut found = false;
        while let Some(archive) = pending.pop() {
            for entry in archive.entries() {
                let source = archive
                    .open_entry_source(entry)?
                    .ok_or(Error::InvalidFormat)?;
                let header = source.read_at(0, source.len().min(64) as usize)?;
                match game.resource_route(&entry.name, ResourceOrigin::Entry(entry.kind), &header) {
                    ResourceRoute::Archive(route) if route.tag == "cat/tamsoft" => {
                        pending.push(
                            catalog
                                .open_source(source.clone(), &entry.name, &route)?
                                .ok_or(Error::InvalidFormat)?
                                .archive,
                        );
                    }
                    ResourceRoute::Model(tag) => {
                        let model = crate::decode_as(
                            tag,
                            archive.open_entry(entry)?.into_owned().into(),
                            game.resource_options(),
                            &AtomicBool::new(false),
                        )
                        .inspect_err(|e| eprintln!("{name} > {}: {e}", entry.name))?;
                        assert!(!model.vertices.is_empty() && !model.meshes.is_empty());
                        if let Some((vertices, meshes)) = expected {
                            assert_eq!(model.vertices.len(), vertices);
                            assert_eq!(model.meshes.len(), meshes);
                        }
                        eprintln!(
                            "{name}: {} vertices, {} primitives, {} materials",
                            model.vertices.len(),
                            model.meshes.len(),
                            model.materials.len()
                        );
                        found = true;
                        break;
                    }
                    _ => {}
                }
            }
            if found {
                break;
            }
        }
        assert!(found);
    }
    Ok(())
}
