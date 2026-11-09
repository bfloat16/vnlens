//! Resource decoding and exports through domain crates, independent of widgets.
use crate::browser::Target;
use anyhow::{Result, anyhow};
use nvlens_core::{Archive, ResourceResolver};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub struct Resource {
    pub bytes: Arc<[u8]>,
    pub script: Option<nvlens_script::ir::Script>,
    pub psb: Option<nvlens_script::psb::Psb>,
    pub image: Option<nvlens_image::Image>,
    pub audio: bool,
}

struct Resources<'a>(&'a dyn Archive, &'a [String], &'a str);
impl ResourceResolver for Resources<'_> {
    fn read_resource(&self, name: &str) -> nvlens_core::Result<Option<Vec<u8>>> {
        let local = self
            .0
            .entries()
            .iter()
            .enumerate()
            .find(|(i, entry)| {
                entry.name.replace('\\', "/").eq_ignore_ascii_case(name)
                    || self
                        .1
                        .get(*i)
                        .is_some_and(|path| path.replace('\\', "/").eq_ignore_ascii_case(name))
            })
            .map(|(_, entry)| self.0.open_entry(entry).map(|data| data.into_owned()))
            .transpose()?;
        if local.is_some() {
            Ok(local)
        } else {
            self.0.read_companion(name)
        }
    }
    fn resource_name(&self) -> Option<&str> {
        Some(self.2)
    }
}

struct FileResources<'a>(&'a std::path::Path);
impl ResourceResolver for FileResources<'_> {
    fn resource_name(&self) -> Option<&str> {
        self.0.file_name()?.to_str()
    }
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
        psb: None,
        image: None,
        audio: false,
    };
    if raw || cancel.load(Ordering::Relaxed) {
        return Ok(resource);
    }
    // Video containers have no pixel/audio preview decoder yet. Preserve their
    // encoded stream without passing Ogg Theora to the Vorbis audio reader.
    let kind = match target {
        Target::Entry { archive, index }
            if archive.entries[*index].kind != nvlens_core::ResourceKind::Unknown =>
        {
            archive.entries[*index].kind
        }
        Target::File(path, game) => game.resource_kind_for_path(path),
        _ => nvlens_core::ResourceKind::guess_from_name(&target.name()),
    };
    if kind == nvlens_core::ResourceKind::Video {
        return Ok(resource);
    }
    let script_tag = match target {
        Target::Entry { archive, .. } => archive.game.script_format_for(&target.name()),
        Target::File(_, game) => game.script_format_for(&target.name()),
        _ => None,
    };
    if let Target::Entry { archive, index } = target
        && let Some(tag) = script_tag
    {
        let opened = archive
            .source
            .lock()
            .map_err(|_| anyhow!("Archive reader is unavailable"))?;
        resource.script = nvlens_script::disassemble_with_options_as(
            tag,
            &resource.bytes,
            Some(&Resources(
                &*opened.archive,
                &archive.paths,
                &archive.paths[*index],
            )),
            archive.game.resource_options(),
        )?;
    } else if let Target::File(path, game) = target
        && let Some(tag) = script_tag
    {
        resource.script = nvlens_script::disassemble_with_options_as(
            tag,
            &resource.bytes,
            Some(&FileResources(path)),
            game.resource_options(),
        )?;
    }
    if resource.script.is_none() {
        if let Some(tag) = script_tag
            && let Some(content) = nvlens_script::decode_content_as(tag, &resource.bytes)?
        {
            match content {
                nvlens_script::ScriptContent::Text(text) => {
                    resource.bytes = text.into_bytes().into();
                }
                nvlens_script::ScriptContent::Psb(psb) => resource.psb = Some(psb),
            }
            return Ok(resource);
        }
        if let Some(image) = nvlens_image::decode(&resource.bytes)? {
            resource.image = Some(image);
        } else {
            resource.audio = nvlens_audio::metadata(&resource.bytes)?.is_some();
        }
    }
    Ok(resource)
}

#[derive(Clone, Copy, Debug)]
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
    frame: usize,
) -> Result<Vec<u8>> {
    match kind {
        ExportKind::Png => Ok(nvlens_image::decode_frame(bytes, frame)?
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
