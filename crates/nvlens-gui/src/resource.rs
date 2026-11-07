//! Resource decoding and exports through domain crates, independent of widgets.
use crate::browser::Target;
use anyhow::{Result, anyhow};
use nvlens_core::{Archive, ResourceResolver};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct Resource {
    pub bytes: Arc<[u8]>,
    pub script: Option<nvlens_script::ir::Script>,
    pub image: Option<Vec<u8>>,
    pub audio: bool,
}

struct Resources<'a>(&'a dyn Archive);
impl ResourceResolver for Resources<'_> {
    fn read_resource(&self, name: &str) -> nvlens_core::Result<Option<Vec<u8>>> {
        self.0
            .entries()
            .iter()
            .find(|entry| entry.name.replace('\\', "/").eq_ignore_ascii_case(name))
            .map(|entry| self.0.open_entry(entry).map(|data| data.into_owned()))
            .transpose()
    }
}

struct FileResources<'a>(&'a std::path::Path);
impl ResourceResolver for FileResources<'_> {
    fn read_resource(&self, name: &str) -> nvlens_core::Result<Option<Vec<u8>>> {
        let relative = std::path::PathBuf::from(name.replace('\\', "/"));
        if !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(nvlens_core::Error::Unsupported(
                "Companion resource must use a relative path".into(),
            ));
        }
        let Some(parent) = self.0.parent() else {
            return Ok(None);
        };
        let mut path = parent.join(&relative);
        if relative
            .components()
            .next()
            .is_some_and(|component| Some(component.as_os_str()) == parent.file_name())
            && let Some(root) = parent.parent()
        {
            path = root.join(relative);
        }
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

pub fn read(target: &Target, raw: bool, cancel: &AtomicBool) -> Result<Resource> {
    let bytes = target.read(raw, cancel)?;
    let mut resource = Resource {
        bytes: bytes.into(),
        script: None,
        image: None,
        audio: false,
    };
    if raw || cancel.load(Ordering::Relaxed) {
        return Ok(resource);
    }
    if let Target::Entry { archive, .. } = target
        && let Some(tag) = archive.game.script_format()
    {
        let opened = archive
            .source
            .lock()
            .map_err(|_| anyhow!("Archive reader is unavailable"))?;
        resource.script = nvlens_script::disassemble_as(
            tag,
            &resource.bytes,
            Some(&Resources(&*opened.archive)),
        )?;
    } else if let Target::File(path, game) = target
        && let Some(tag) = game.script_format()
    {
        resource.script =
            nvlens_script::disassemble_as(tag, &resource.bytes, Some(&FileResources(path)))?;
    }
    if resource.script.is_none() {
        if let Some(image) = nvlens_image::decode(&resource.bytes)? {
            resource.image = Some(image.to_png()?);
        } else {
            resource.audio = nvlens_audio::metadata(&resource.bytes)?.is_some();
        }
    }
    Ok(resource)
}

#[derive(Clone, Copy)]
pub enum ExportKind {
    Png,
    Wav,
    Ir,
}
impl ExportKind {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Wav => "wav",
            Self::Ir => "ir.json",
        }
    }
}

pub fn convert(
    bytes: &[u8],
    kind: ExportKind,
    script: Option<&nvlens_script::ir::Script>,
) -> Result<Vec<u8>> {
    match kind {
        ExportKind::Png => Ok(nvlens_image::decode(bytes)?
            .ok_or_else(|| anyhow!("No image decoder matched"))?
            .to_png()?),
        ExportKind::Wav => Ok(nvlens_audio::decode(bytes)?
            .ok_or_else(|| anyhow!("No audio decoder matched"))?
            .to_wav()?),
        ExportKind::Ir => Ok(script
            .ok_or_else(|| anyhow!("No disassembly is available"))?
            .to_json()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Requires NVLENS_YURIS_GAME; validates script preview data without opening a window"]
    fn validates_game_script_resources() -> Result<()> {
        nvlens_archive::init();
        nvlens_script::init();
        let root = std::path::PathBuf::from(
            std::env::var_os("NVLENS_YURIS_GAME")
                .ok_or_else(|| anyhow!("Set NVLENS_YURIS_GAME"))?,
        );
        let archive = Arc::new(
            crate::archive::MountedArchive::open(
                root.join("pac/Scripts.ypf"),
                false,
                Arc::new(
                    nvlens_engine::identify(&root, &AtomicBool::new(false))?
                        .ok_or_else(|| anyhow::anyhow!("Engine not identified"))?,
                ),
            )?
            .ok_or_else(|| anyhow!("Archive not recognized"))?,
        );
        let cancelled = AtomicBool::new(false);
        let mut checked = 0;
        for (index, entry) in archive.entries.iter().enumerate() {
            let name = entry.name.rsplit(['/', '\\']).next().unwrap_or("");
            if name.starts_with("yst0") && name != "yst00000.ybn" {
                continue;
            }
            let resource = read(
                &Target::Entry {
                    archive: archive.clone(),
                    index,
                },
                false,
                &cancelled,
            )?;
            let script = resource
                .script
                .as_ref()
                .ok_or_else(|| anyhow!("Script not recognized"))?;
            let exported = convert(&resource.bytes, ExportKind::Ir, Some(script))?;
            assert!(std::str::from_utf8(&exported)?.contains("\"ir_version\": 2"));
            assert_eq!(
                script
                    .sections
                    .iter()
                    .flat_map(|section| section.raw.iter().copied())
                    .collect::<Vec<_>>(),
                &*resource.bytes
            );
            checked += 1;
        }
        println!("Validated {checked} script preview resources and IR exports without a window");
        Ok(())
    }

    /// Requires locally owned files; no samples are copied into the repository.
    /// NVLENS_YURIS_GAME=<game> cargo test -p nvlens-gui validates_game_media -- --ignored --nocapture
    #[test]
    #[ignore = "Requires NVLENS_YURIS_GAME and the original game archives"]
    fn validates_game_media() -> Result<()> {
        nvlens_archive::init();
        nvlens_image::init();
        nvlens_audio::init();
        let root = std::path::PathBuf::from(
            std::env::var_os("NVLENS_YURIS_GAME")
                .ok_or_else(|| anyhow!("Set NVLENS_YURIS_GAME"))?,
        );
        let catalog = nvlens_core::Catalog::load();
        let game = nvlens_engine::identify(&root, &AtomicBool::new(false))?
            .ok_or_else(|| anyhow!("Engine not identified"))?;
        for (name, is_image) in [("Graphics.ypf", true), ("Sounds.ypf", false)] {
            let opened = catalog.open(
                root.join("pac").join(name),
                &game
                    .route(name)
                    .ok_or_else(|| anyhow!("No archive route"))?,
            )?;
            for (index, entry) in opened.archive.entries().iter().enumerate() {
                let bytes = opened.archive.open_entry(entry)?;
                if is_image {
                    let meta = nvlens_image::metadata(&bytes)?
                        .ok_or_else(|| anyhow!("Image not recognized"))?;
                    if index % 512 == 0 {
                        let image = nvlens_image::decode(&bytes)?
                            .ok_or_else(|| anyhow!("No image decoded"))?;
                        assert_eq!(meta, image.meta);
                        let png = image.to_png()?;
                        assert_eq!(nvlens_image::metadata(&png)?.as_ref(), Some(&meta));
                    }
                } else {
                    let meta = nvlens_audio::metadata(&bytes)?
                        .ok_or_else(|| anyhow!("Audio not recognized"))?;
                    if index % 1024 == 0 {
                        let pcm = nvlens_audio::decode(&bytes)?
                            .ok_or_else(|| anyhow!("No audio decoded"))?;
                        assert_eq!(meta.channels, pcm.meta.channels);
                        assert_eq!(meta.sample_rate, pcm.meta.sample_rate);
                        let wav = pcm.to_wav()?;
                        let wav = nvlens_audio::decode(&wav)?
                            .ok_or_else(|| anyhow!("WAV not recognized"))?;
                        assert_eq!(&*wav.samples, &*pcm.samples);
                    }
                }
            }
            println!(
                "{name}: validated hashes and metadata for {} entries; sampled full decoding and export",
                opened.archive.entries().len()
            );
        }
        Ok(())
    }
}
