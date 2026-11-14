//! PE evidence precedes directory-layout evidence. Parameter recovery runs only
//! after an engine has independent identification evidence.

use crate::context::Context;
use crate::routing::Router;
use crate::{Engine, Identification};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result};
use vnlens_io::{BinaryReader, pe::PeImage};

pub(crate) struct Detector {
    pub engine: Engine,
    pub supersedes: Option<Engine>,
    pub subdirs: &'static [&'static str],
    pub pe: fn(&PeImage<'_>) -> Result<bool>,
    pub layout: fn(&Context) -> bool,
    pub file: fn(&vnlens_io::ArcView) -> Result<bool>,
    pub resolve: fn(&Context, &[PathBuf], &AtomicBool) -> Result<ArchiveOptions>,
    pub scope: fn(&Identification, &Path) -> Option<Identification>,
    pub route: Router,
}
vnlens_core::inventory::collect!(Detector);

pub(crate) struct Middleware {
    pub subdirs: &'static [&'static str],
    pub pe: fn(&PeImage<'_>) -> Result<bool>,
    pub layout: fn(&Context) -> bool,
    pub route: Router,
}
vnlens_core::inventory::collect!(Middleware);

pub(crate) fn detector(engine: Engine) -> Option<&'static Detector> {
    vnlens_core::inventory::iter::<Detector>().find(|d| d.engine == engine)
}

/// Identifies a selected game directory or file. Only the selected directory,
/// its engine plugin directory and the parent of conventional asset directories
/// are considered; recognition never walks arbitrary ancestors or archives.
pub fn identify(path: &Path, cancelled: &AtomicBool) -> Result<Option<Identification>> {
    identify_with_progress(path, cancelled, &|_, _| {})
}

/// Identifies a game while reporting executable-recovery work to its host.
pub fn identify_with_progress(
    path: &Path,
    cancelled: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<Option<Identification>> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    if path.is_file() {
        let view = vnlens_io::ArcView::open(path)?;
        let mut selected = None;
        for item in vnlens_core::inventory::iter::<Detector>() {
            if (item.file)(&view)? {
                if selected.is_some() {
                    return Err(Error::Unsupported(
                        "Conflicting container identity evidence".into(),
                    ));
                }
                selected = Some(item);
            }
        }
        if let Some(item) = selected {
            let context = Context {
                root: path.canonicalize()?.parent().unwrap_or(path).to_path_buf(),
                files: Default::default(),
                sections: Default::default(),
            };
            return Ok(Some(Identification {
                root: context.root.clone(),
                engine: item.engine,
                evidence: format!("Container identity in {}", path.display()),
                options: (item.resolve)(&context, &[], cancelled)?,
                files: context.files,
                middleware: Vec::new(),
                compose_pimg: Default::default(),
            }));
        }
    }
    let directory = (if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    })
    .canonicalize()?;
    let root = normalize_root(&directory).canonicalize()?;
    let context = Context {
        root,
        files: Default::default(),
        sections: Default::default(),
    };
    let identified = identify_context(context, cancelled, progress)?;
    Ok(identified.map(|game| {
        detector(game.engine)
            .and_then(|d| (d.scope)(&game, &directory))
            .unwrap_or(game)
    }))
}

impl Identification {
    /// Resolves an entered directory with its own executable as a separate game.
    /// Directories without local executables share this instance. A candidate
    /// game must identify successfully; unknown engines, conflicts and missing
    /// keys stop processing instead of inheriting this game's parameters.
    /// The existing filesystem overlay is retained, and ancestors are not scanned.
    pub fn for_directory(
        self: &std::sync::Arc<Self>,
        path: &Path,
        cancelled: &AtomicBool,
    ) -> Result<std::sync::Arc<Self>> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let root = self.files.canonicalize(path)?;
        if root == self.root {
            return Ok(self.clone());
        }
        if detector(self.engine).is_some_and(|d| d.route.filesystem_host) {
            return self
                .for_filesystem(root, self.files.clone(), cancelled)
                .map(std::sync::Arc::new);
        }
        if let Some(scoped) = detector(self.engine).and_then(|d| (d.scope)(self, &root)) {
            return Ok(std::sync::Arc::new(scoped));
        }
        for entry in self.files.read_dir(&root)? {
            if cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            if !entry.metadata.directory
                && entry
                    .path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
            {
                let context = Context {
                    root,
                    files: self.files.clone(),
                    sections: Default::default(),
                };
                return identify_context(context, cancelled, &|_, _| {})?
                    .map(|mut game| {
                        game.compose_pimg = self.compose_pimg.clone();
                        std::sync::Arc::new(game)
                    })
                    .ok_or_else(|| {
                        Error::Unsupported(
                            "Game engine was not identified in the nested executable directory"
                                .into(),
                        )
                    });
            }
        }
        Ok(self.clone())
    }
}

pub(crate) fn identify_context(
    mut context: Context,
    cancelled: &AtomicBool,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<Option<Identification>> {
    let root = context.root.clone();
    let mut executables = executable_paths(&context)?;
    let mut visited = std::collections::HashSet::new();
    let mut position = 0;
    while position < executables.len() {
        let executable = executables[position].clone();
        position += 1;
        if !visited.insert(executable.to_string_lossy().to_lowercase()) {
            continue;
        }
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = std::sync::Arc::new(context.files.open(&executable)?);
        let data = view.slice(0, view.len())?;
        let Some(pe) = PeImage::parse(data).ok().flatten() else {
            continue;
        };
        if vnlens_unpack::enigma::recognizes(&pe, cancelled)? {
            let recovered = vnlens_unpack::enigma::recover(
                view.clone(),
                vnlens_unpack::enigma::Mode::Auto,
                cancelled,
                progress,
            )?;
            context
                .sections
                .insert(view.path().to_path_buf(), recovered.sections);
            let parent = executable.parent().unwrap_or(&root);
            for (name, source) in recovered.files {
                let path = parent.join(name);
                // A virtual DLL can replace an already visited physical copy.
                // Recover that effective source before any engine evidence is used.
                if visited.remove(&path.to_string_lossy().to_lowercase()) {
                    executables.push(path.clone());
                }
                context.sections.retain(|stored, _| {
                    !stored
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&path.to_string_lossy())
                });
                std::sync::Arc::make_mut(&mut context.files).insert(path, source)?;
            }
            for path in executable_paths(&context)? {
                if !executables.contains(&path) {
                    executables.push(path);
                }
            }
        }
    }
    // Resolve evidence only after all embedded siblings are visible. Otherwise
    // a physical DLL encountered before its host could supply stale evidence.
    executables = executable_paths(&context)?;
    let mut matches = Vec::new();
    let mut middleware_pe = Vec::new();
    let mut unreadable_pe = None;
    for executable in &executables {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(executable)?;
        let Some(pe) = context.image(&view, cancelled)? else {
            continue;
        };
        for item in vnlens_core::inventory::iter::<Middleware>() {
            match (item.pe)(&pe) {
                Ok(true) if !middleware_pe.iter().any(|m| std::ptr::eq(*m, item)) => {
                    middleware_pe.push(item)
                }
                Ok(_) => {}
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    unreadable_pe.get_or_insert(Error::Io(error));
                }
                Err(error) => return Err(error),
            }
        }
        for detector in vnlens_core::inventory::iter::<Detector>() {
            match (detector.pe)(&pe) {
                Ok(true) => {
                    matches.push((detector, format!("PE features in {}", executable.display())))
                }
                Ok(false) => {}
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Protected executables can retain unmapped resource
                    // directories. This supplies no engine evidence; only an
                    // independent detector/layout can authorize resolution.
                    unreadable_pe.get_or_insert(Error::Io(error));
                }
                Err(error) => return Err(error),
            }
        }
    }
    if matches.is_empty() {
        for detector in vnlens_core::inventory::iter::<Detector>() {
            if (detector.layout)(&context) {
                matches.push((detector, "Game directory layout".into()));
            }
        }
    }
    let superseded: Vec<Engine> = matches.iter().filter_map(|(d, _)| d.supersedes).collect();
    matches.retain(|(d, _)| !superseded.contains(&d.engine));
    let Some((detector, evidence)) = matches.first() else {
        if let Some(error) = unreadable_pe {
            return Err(error);
        }
        return Ok(None);
    };
    if matches
        .iter()
        .any(|(other, _)| other.engine != detector.engine)
    {
        return Err(Error::Unsupported(
            "Conflicting engine evidence in the selected game directory".into(),
        ));
    }
    let options = (detector.resolve)(&context, &executables, cancelled)?;
    let middleware = vnlens_core::inventory::iter::<Middleware>()
        .filter(|item| {
            middleware_pe.iter().any(|m| std::ptr::eq(*m, *item)) || (item.layout)(&context)
        })
        .map(|item| &item.route)
        .collect();
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    Ok(Some(Identification {
        root,
        engine: detector.engine,
        evidence: evidence.clone(),
        files: context.files,
        options,
        middleware,
        compose_pimg: Default::default(),
    }))
}

fn normalize_root(mut root: &Path) -> &Path {
    const GENERIC: &[&str] = &[
        "data",
        "archive",
        "plugin",
        "plugins",
        "dll",
        "mov",
        "movie",
        "bgm",
        "wav",
        "dat",
        "res",
        "media",
        "resources",
    ];
    for subdir in vnlens_core::inventory::iter::<Detector>()
        .flat_map(|d| d.subdirs)
        .chain(vnlens_core::inventory::iter::<Middleware>().flat_map(|m| m.subdirs))
    {
        if let Some((parent, leaf)) = subdir.split_once('/')
            && root
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case(leaf))
            && root
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name.eq_ignore_ascii_case(parent))
        {
            root = root.parent().unwrap_or(root);
        }
    }
    if root.file_name().is_some_and(|name| {
        GENERIC
            .iter()
            .chain(
                vnlens_core::inventory::iter::<Middleware>()
                    .flat_map(|m| m.subdirs.iter().filter(|s| !s.contains('/'))),
            )
            .chain(
                vnlens_core::inventory::iter::<Detector>()
                    .flat_map(|d| d.subdirs.iter().filter(|s| !s.contains('/'))),
            )
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
    }) {
        root = root.parent().unwrap_or(root);
    }
    root
}

/// Searches file-backed PE sections for ASCII or UTF-16LE strings. The marker
/// itself is ASCII; UTF-16 code units still use the shared binary reader.
pub(crate) fn has(pe: &PeImage<'_>, marker: &[u8]) -> Result<bool> {
    for section in &pe.sections {
        let data = pe.section_data(section)?;
        if data
            .windows(marker.len())
            .any(|part| part.eq_ignore_ascii_case(marker))
        {
            return Ok(true);
        }
        if data.windows(marker.len() * 2).any(|part| {
            part.as_chunks::<2>()
                .0
                .iter()
                .zip(marker)
                .all(|(unit, byte)| {
                    let unit = BinaryReader::u16_le(unit);
                    unit <= 0x7f && (unit as u8).eq_ignore_ascii_case(byte)
                })
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn plain(_: &Context, _: &[PathBuf], _: &AtomicBool) -> Result<ArchiveOptions> {
    Ok(ArchiveOptions::default())
}

pub(crate) fn no_container(_: &vnlens_io::ArcView) -> Result<bool> {
    Ok(false)
}

pub(crate) fn unscoped(_: &Identification, _: &Path) -> Option<Identification> {
    None
}

fn executable_paths(context: &Context) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for directory in [
        context.root.clone(),
        context.root.join("plugin"),
        context.root.join("plugins"),
    ] {
        if !context.files.is_dir(&directory) {
            continue;
        }
        for entry in context.files.read_dir(&directory)? {
            if !entry.metadata.directory
                && entry.path.extension().is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("exe")
                        || ext.eq_ignore_ascii_case("dll")
                        || ext.eq_ignore_ascii_case("tpm")
                })
            {
                paths.push(entry.path);
            }
        }
    }
    paths.sort();
    Ok(paths)
}
