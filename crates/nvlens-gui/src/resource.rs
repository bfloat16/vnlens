//! Resource decoding and exports through domain crates, independent of widgets.
use crate::browser::Target;
use anyhow::{Result, anyhow};
use nvlens_core::{Archive, ResourceKind, ResourceResolver, ResourceRoute};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Retains nested archive backing storage while independent decoders read it.
#[derive(Clone)]
pub struct VideoInput {
    pub tag: &'static str,
    pub source: Arc<dyn nvlens_io::ReadAt>,
    pub name: String,
    pub archive: Option<Arc<crate::archive::MountedArchive>>,
}
impl fmt::Debug for VideoInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoInput")
            .field("name", &self.name)
            .field("size", &self.source.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Resource {
    pub route: ResourceRoute,
    pub bytes: Arc<[u8]>,
    pub script: Option<nvlens_script::ir::Script>,
    pub psb: Option<nvlens_script::psb::Psb>,
    pub image: Option<nvlens_image::Image>,
    pub audio: bool,
    /// Name hint for FFmpeg's container probe when the resource is a video.
    pub video: Option<VideoInput>,
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

pub fn read(target: &Target, raw: bool, cancel: &Arc<AtomicBool>) -> Result<Resource> {
    let mut resource = Resource {
        route: ResourceRoute::Other(ResourceKind::Unknown),
        bytes: Arc::from([]),
        script: None,
        psb: None,
        image: None,
        audio: false,
        video: None,
    };
    if raw {
        resource.bytes = target.read(true, cancel)?.into();
        return Ok(resource);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(nvlens_core::Error::Cancelled.into());
    }
    // Only the requested resource is opened. Streaming sources expose logical
    // bytes after archive transforms, and retain the archive's backing storage.
    let source: Option<Arc<dyn nvlens_io::ReadAt>> = match target {
        Target::File(path, _) => Some(Arc::new(nvlens_io::ArcView::open(path)?)),
        Target::Entry { archive, index } => {
            let opened = archive
                .source
                .lock()
                .map_err(|_| anyhow!("Archive reader is unavailable"))?;
            let entry = opened
                .archive
                .entries()
                .get(*index)
                .ok_or_else(|| anyhow!("Selected entry no longer exists"))?;
            opened.archive.open_entry_source(entry)?
        }
        _ => return Err(anyhow!("Select a file with an identified game context")),
    };
    let source = if let Some(source) = source {
        source
    } else {
        resource.bytes = target.read(false, cancel)?.into();
        Arc::new(resource.bytes.clone()) as Arc<dyn nvlens_io::ReadAt>
    };
    let mut header = [0; 64];
    let size = usize::try_from(source.len().min(header.len() as u64))?;
    let mut reader = source.clone().reader(cancel.clone())?;
    std::io::Read::read_exact(&mut reader, &mut header[..size])?;
    resource.route = target.resource_route(&header[..size])?;
    if let ResourceRoute::Media { audio, video } = resource.route {
        resource.route = if nvlens_video::contains_video(source.clone(), cancel.clone())? {
            ResourceRoute::Video(video)
        } else {
            ResourceRoute::Audio(audio)
        };
    }
    if let ResourceRoute::Video(tag) = resource.route {
        resource.video = Some(VideoInput {
            tag,
            source,
            name: target.name(),
            archive: match target {
                Target::Entry { archive, .. } => Some(archive.clone()),
                _ => None,
            },
        });
        return Ok(resource);
    }
    if resource.bytes.is_empty() {
        resource.bytes = target.read(false, cancel)?.into();
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(nvlens_core::Error::Cancelled.into());
    }
    match resource.route {
        ResourceRoute::Script(tag) => {
            resource.script = match target {
                Target::Entry { archive, index } => {
                    let opened = archive
                        .source
                        .lock()
                        .map_err(|_| anyhow!("Archive reader is unavailable"))?;
                    nvlens_script::disassemble_with_options_as(
                        tag,
                        &resource.bytes,
                        Some(&Resources(
                            &*opened.archive,
                            &archive.paths,
                            &archive.paths[*index],
                        )),
                        archive.game.resource_options(),
                    )?
                }
                Target::File(path, game) => nvlens_script::disassemble_with_options_as(
                    tag,
                    &resource.bytes,
                    Some(&FileResources(path)),
                    game.resource_options(),
                )?,
                _ => None,
            };
            if resource.script.is_none()
                && let Some(content) = nvlens_script::decode_content_as(tag, &resource.bytes)?
            {
                match content {
                    nvlens_script::ScriptContent::Text(text) => {
                        resource.bytes = text.into_bytes().into()
                    }
                    nvlens_script::ScriptContent::Psb(psb) => resource.psb = Some(psb),
                }
            }
        }
        ResourceRoute::Image(tag) => {
            resource.image = Some(nvlens_image::decode_as(tag, &resource.bytes)?)
        }
        ResourceRoute::Audio(tag) => {
            nvlens_audio::metadata_as(tag, &resource.bytes)?
                .ok_or_else(|| anyhow!("Resource does not match audio route {tag}"))?;
            resource.audio = true;
        }
        _ => {}
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
    route: &ResourceRoute,
    kind: ExportKind,
    script: Option<&nvlens_script::ir::Script>,
    frame: usize,
) -> Result<Vec<u8>> {
    match (kind, route) {
        (ExportKind::Png, ResourceRoute::Image(tag)) => {
            Ok(nvlens_image::decode_frame_as(tag, bytes, frame)?.to_png()?)
        }
        (ExportKind::Wav, ResourceRoute::Audio(tag)) => {
            Ok(nvlens_audio::decode_as(tag, bytes)?.to_wav()?)
        }
        (ExportKind::Ir, ResourceRoute::Script(_)) => Ok(script
            .ok_or_else(|| anyhow!("No disassembly is available"))?
            .to_json()?),
        _ => Err(anyhow!(
            "Conversion does not match the selected resource route"
        )),
    }
}
