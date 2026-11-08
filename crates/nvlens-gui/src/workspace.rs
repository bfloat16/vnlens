//! Desktop navigation, asynchronous tasks, and resource inspection.

use std::ops::Range;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use gpui::{prelude::*, *};

use crate::archive::{self, Progress};
use crate::browser::{self, Folder, Item, Target};

mod audio_view;
mod browser_view;
mod filename;
mod image_view;
mod layout;
mod level_meter;
mod names;
mod script_view;
mod scroll;
mod scrollbar;
mod status_view;
mod view;

const BACKGROUND: u32 = 0x1c1c1e;
const PANEL: u32 = 0x242426;
const BORDER: u32 = 0x37373b;
const SECONDARY: u32 = 0x98989f;
const ACCENT: u32 = 0x0a84ff;
const COLUMN_WIDTH: f32 = 220.;

#[derive(Clone, Copy)]
enum ResizeTarget {
    Column(u64),
    Inspector,
}

actions!(
    workspace,
    [
        Open,
        OpenFolder,
        Export,
        Back,
        Inspector,
        Settings,
        MoveUp,
        MoveDown,
        Enter,
        Cancel,
        Home,
        CopyInstruction,
        TogglePlayback
    ]
);

pub fn bind_keys(cx: &mut App) {
    for modifier in ["ctrl", "cmd"] {
        cx.bind_keys([
            KeyBinding::new(&format!("{modifier}-o"), Open, Some("Workspace")),
            KeyBinding::new(&format!("{modifier}-e"), Export, Some("Workspace")),
            KeyBinding::new(&format!("{modifier}-i"), Inspector, Some("Workspace")),
            KeyBinding::new(&format!("{modifier}-,"), Settings, Some("Workspace")),
            KeyBinding::new(&format!("{modifier}-c"), CopyInstruction, Some("Preview")),
            KeyBinding::new(
                &format!("{modifier}-shift-o"),
                OpenFolder,
                Some("Workspace"),
            ),
        ]);
    }
    cx.bind_keys([
        KeyBinding::new("alt-left", Back, Some("Workspace")),
        KeyBinding::new("left", Back, Some("Browser")),
        KeyBinding::new("right", Enter, Some("Browser")),
        KeyBinding::new("alt-home", Home, Some("Workspace")),
        KeyBinding::new("up", MoveUp, Some("Browser")),
        KeyBinding::new("down", MoveDown, Some("Browser")),
        KeyBinding::new("enter", Enter, Some("Browser")),
        KeyBinding::new("escape", Cancel, Some("Workspace")),
        KeyBinding::new("space", TogglePlayback, Some("Workspace")),
    ]);
}

struct Column {
    id: u64,
    folder: Folder,
    selected: Option<usize>,
    scroll: UniformListScrollHandle,
    scrollbar: scrollbar::Scrollbar,
    hovered: bool,
    width: Pixels,
    loading: bool,
    error: Option<String>,
    cancelled: Arc<AtomicBool>,
}
impl Column {
    fn new(id: u64, folder: Folder) -> Self {
        Self {
            id,
            folder,
            selected: None,
            scroll: UniformListScrollHandle::new(),
            scrollbar: scrollbar::Scrollbar::default(),
            hovered: false,
            width: px(COLUMN_WIDTH),
            loading: false,
            error: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Drop for Column {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

struct Preview {
    bytes: Arc<[u8]>,
    lines: Option<Vec<Range<usize>>>,
    widest_line: usize,
    image: Option<Arc<RenderImage>>,
    image_frames: usize,
    image_frame: usize,
    script: Option<Arc<nvlens_script::ir::Script>>,
    psb: Option<Arc<nvlens_script::psb::Psb>>,
    ir_table: Option<script_view::Table>,
    audio: Option<audio_view::AudioPreview>,
}

impl Preview {
    fn new(resource: crate::resource::Resource, cancelled: &AtomicBool) -> anyhow::Result<Self> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled.into());
        }
        let bytes = resource.bytes;
        let mut widest_line = 0;
        let lines = (resource.script.is_none()
            && resource.psb.is_none()
            && resource.image.is_none()
            && !resource.audio)
            .then(|| {
                std::str::from_utf8(&bytes)
                    .ok()
                    .filter(|text| {
                        !text
                            .chars()
                            .any(|ch| ch.is_control() && !matches!(ch, '\r' | '\n' | '\t'))
                    })
                    .map(|text| {
                        let mut offset = 0;
                        let mut max_width = 0;
                        text.split_inclusive('\n')
                            .enumerate()
                            .map(|(index, line)| {
                                let width: usize = line
                                    .chars()
                                    .map(|ch| match ch {
                                        '\t' => 4,
                                        ch if ch.is_ascii() => 1,
                                        _ => 2,
                                    })
                                    .sum();
                                if width > max_width {
                                    max_width = width;
                                    widest_line = index;
                                }
                                let start = offset;
                                offset += line.len();
                                start..offset
                            })
                            .collect()
                    })
            })
            .flatten();
        let image_frames = if resource.image.is_some() {
            nvlens_image::frame_count(&bytes)?.unwrap_or(1)
        } else {
            0
        };
        let image = resource
            .image
            .map(|image| Self::render_image(image, None))
            .transpose()?;
        let ir_table = if let Some(script) = &resource.script {
            Some(script_view::Table::new(script, cancelled)?)
        } else if let Some(psb) = &resource.psb {
            Some(script_view::Table::from_psb(psb, cancelled)?)
        } else {
            None
        };
        let audio = resource
            .audio
            .then(|| audio_view::AudioPreview::new(&bytes, cancelled))
            .transpose()?;
        Ok(Self {
            bytes,
            lines,
            widest_line,
            image,
            image_frames,
            image_frame: 0,
            script: resource.script.map(Arc::new),
            psb: resource.psb.map(Arc::new),
            ir_table,
            audio,
        })
    }

    fn render_image(
        image: nvlens_image::Image,
        thumbnail: Option<(u32, u32)>,
    ) -> anyhow::Result<Arc<RenderImage>> {
        use nvlens_image::PixelBuffer;
        let width = image.meta.width;
        let height = image.meta.height;
        let (mut bytes, swap_channels) = match image.pixels {
            PixelBuffer::Rgba8(bytes) => (bytes, true),
            PixelBuffer::Bgra8(bytes) => (bytes, false),
            PixelBuffer::Rgba16(words) => {
                let pixels =
                    image::ImageBuffer::<image::Rgba<u16>, _>::from_raw(width, height, words)
                        .ok_or_else(|| anyhow::anyhow!("Invalid preview pixel dimensions"))?;
                (
                    image::DynamicImage::ImageRgba16(pixels)
                        .to_rgba8()
                        .into_raw(),
                    true,
                )
            }
            _ => anyhow::bail!("Unsupported preview pixel buffer"),
        };
        // Prepare GPUI's BGRA texture off-thread before replacing the visible
        // preview. Encoded images would start another asynchronous decode in img().
        if swap_channels {
            nvlens_image::swap_red_blue(&mut bytes);
        }
        let pixels = image::RgbaImage::from_raw(width, height, bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid preview pixel dimensions"))?;
        let pixels = if let Some((width, height)) = thumbnail {
            image::DynamicImage::ImageRgba8(pixels)
                .thumbnail(width, height)
                .into_rgba8()
        } else {
            pixels
        };
        Ok(Arc::new(RenderImage::new([image::Frame::new(pixels)])))
    }

    fn release(self, cx: &mut App) {
        if let Some(image) = self.image {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
        if let Some(audio) = self.audio {
            audio.release(cx);
        }
    }
}

enum Event {
    Names(names::Update),
    NamesRefreshed(anyhow::Result<Vec<names::Refresh>>),
    Imported(Vec<anyhow::Result<Item>>),
    Folder(u64, anyhow::Result<Option<Folder>>),
    Preview(Arc<AtomicBool>, anyhow::Result<Preview>),
    ImageFrame(Arc<AtomicBool>, usize, anyhow::Result<Arc<RenderImage>>),
    ImageThumbnail(Arc<AtomicBool>, usize, anyhow::Result<Arc<RenderImage>>),
    Progress(Progress, Option<String>),
    Finished(anyhow::Result<archive::Extraction>),
    Converted(anyhow::Result<PathBuf>),
    PreferencesSaved(anyhow::Result<()>),
}

pub struct Workspace {
    name_jobs: Vec<names::Job>,
    names_refreshing: bool,
    next_column_id: u64,
    resizing: Option<(ResizeTarget, Pixels, Pixels)>,
    inspector_width: Option<Pixels>,
    viewport_width: Pixels,
    layout: layout::Motion,
    reveal_column: Option<usize>,
    columns: Vec<Column>,
    active: usize,
    selection: Option<(usize, usize)>,
    focus: FocusHandle,
    browser_focus: FocusHandle,
    preview_focus: FocusHandle,
    strip_scroll: ScrollHandle,
    path_scroll: ScrollHandle,
    preview_scroll: UniformListScrollHandle,
    preview_vertical_bar: scrollbar::Scrollbar,
    preview_horizontal_bar: scrollbar::Scrollbar,
    image_view: image_view::State,
    error_scroll: UniformListScrollHandle,
    sender: mpsc::Sender<Event>,
    _events_task: Task<()>,
    pending: usize,
    request: Arc<AtomicBool>,
    preview: Option<Preview>,
    preview_loading: bool,
    preview_error: Option<String>,
    ir_selected: Option<usize>,
    playback: Option<crate::playback::Playback>,
    audio_position: f64,
    audio_meter: level_meter::Meter,
    converting: bool,
    show_inspector: bool,
    show_settings: bool,
    preferences: crate::preferences::Preferences,
    path_switch_changed: Option<Instant>,
    show_export_menu: bool,
    path_menu: Option<(String, Point<Pixels>)>,
    show_errors: bool,
    show_status: bool,
    raw: bool,
    extracting: bool,
    cancel: Arc<AtomicBool>,
    progress: Progress,
    output: Option<PathBuf>,
    status: String,
    errors: Vec<String>,
}

impl Workspace {
    pub fn new(
        window: &mut Window,
        cx: &mut Context<Self>,
        preferences: crate::preferences::Preferences,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let root = Column::new(0, Folder::empty(Target::Opened));
        let task = cx.spawn(async move |weak, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(33))
                    .await;
                let events: Vec<_> = receiver.try_iter().collect();
                if !events.is_empty()
                    && weak
                        .update(cx, |this, cx| {
                            for event in events {
                                this.receive(event, cx);
                            }
                            cx.notify();
                        })
                        .is_err()
                {
                    break;
                }
                let _ = weak.update(cx, |this, cx| {
                    this.tick_audio(cx);
                });
                if weak.upgrade().is_none() {
                    break;
                }
            }
        });
        let browser_focus = cx.focus_handle();
        let focus = cx.focus_handle();
        window.focus(&browser_focus);
        Self {
            name_jobs: Vec::new(),
            names_refreshing: false,
            next_column_id: 1,
            resizing: None,
            inspector_width: None,
            viewport_width: px(0.),
            layout: layout::Motion::default(),
            reveal_column: None,
            columns: vec![root],
            active: 0,
            selection: None,
            focus,
            browser_focus,
            preview_focus: cx.focus_handle(),
            strip_scroll: ScrollHandle::new(),
            path_scroll: ScrollHandle::new(),
            preview_scroll: UniformListScrollHandle::new(),
            preview_vertical_bar: scrollbar::Scrollbar::default(),
            preview_horizontal_bar: scrollbar::Scrollbar::default(),
            image_view: image_view::State::default(),
            error_scroll: UniformListScrollHandle::new(),
            sender,
            _events_task: task,
            pending: 0,
            request: Arc::new(AtomicBool::new(false)),
            preview: None,
            preview_loading: false,
            preview_error: None,
            ir_selected: None,
            playback: None,
            audio_position: 0.,
            audio_meter: level_meter::Meter::default(),
            converting: false,
            show_inspector: true,
            show_settings: false,
            preferences,
            path_switch_changed: None,
            show_export_menu: false,
            path_menu: None,
            show_errors: false,
            show_status: false,
            raw: false,
            extracting: false,
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Progress::default(),
            output: None,
            status: "Ready".into(),
            errors: Vec::new(),
        }
    }

    fn receive(&mut self, event: Event, cx: &mut Context<Self>) {
        match event {
            Event::Names(update) => self.receive_names(update, cx),
            Event::NamesRefreshed(result) => self.receive_name_refresh(result, cx),
            Event::PreferencesSaved(Err(error)) => {
                self.error(format!("Cannot save preferences: {error:#}"))
            }
            Event::Imported(results) => self.receive_imports(results, cx),
            Event::Folder(id, result) => self.receive_folder(id, result, cx),
            Event::Preview(request, result) if Arc::ptr_eq(&request, &self.request) => {
                self.preview_loading = false;
                match result {
                    Ok(preview) => {
                        self.clear_preview(cx);
                        self.preview = Some(preview);
                    }
                    Err(error) => {
                        self.clear_preview(cx);
                        self.preview_error = Some(format!("{error:#}"));
                    }
                }
            }
            Event::ImageFrame(request, frame, result) if Arc::ptr_eq(&request, &self.request) => {
                self.preview_loading = false;
                self.image_view.pending = None;
                match result {
                    Ok(image) => {
                        if let Some(preview) = &mut self.preview {
                            if let Some(old) = preview.image.replace(image) {
                                cx.defer(move |cx| cx.drop_image(old, None));
                            }
                            preview.image_frame = frame;
                        }
                    }
                    Err(error) => self.preview_error = Some(format!("{error:#}")),
                }
            }
            Event::ImageFrame(_, _, Ok(image)) => {
                cx.defer(move |cx| cx.drop_image(image, None));
            }
            Event::ImageThumbnail(request, frame, result) => {
                self.image_view.frames.receive(request, frame, result, cx);
            }
            Event::Preview(_, Ok(preview)) => preview.release(cx),
            Event::Progress(progress, error) => {
                self.progress = progress;
                if let Some(error) = error {
                    self.errors.push(error);
                }
            }
            Event::Finished(result) => {
                self.extracting = false;
                match result {
                    Ok(result) => {
                        self.progress = result.progress;
                        self.status = format!(
                            "{} · {} extracted · {} failed",
                            if result.cancelled {
                                "Cancelled"
                            } else {
                                "Finished"
                            },
                            result.progress.succeeded,
                            result.progress.failed
                        );
                    }
                    Err(error) => self.error(format!("{error:#}")),
                }
            }
            Event::Converted(result) => {
                self.converting = false;
                match result {
                    Ok(path) => {
                        self.status = format!("Exported {}", path.display());
                        self.output = path.parent().map(|p| p.to_path_buf());
                    }
                    Err(error) => self.error(format!("Resource export: {error:#}")),
                }
            }
            _ => {}
        }
    }

    fn error(&mut self, error: String) {
        self.status = error.clone();
        self.errors.push(error);
        self.show_errors = true;
        self.show_status = true;
    }

    fn receive_imports(&mut self, results: Vec<anyhow::Result<Item>>, cx: &mut Context<Self>) {
        self.pending = self.pending.saturating_sub(1);
        let mut last = None;
        for result in results {
            match result {
                Ok(item) => {
                    if let Target::File(_, game) | Target::Directory(_, game) = &item.target {
                        self.start_names(game.clone(), cx);
                    }
                    let root = &mut self.columns[0];
                    let index = root
                        .folder
                        .items
                        .iter()
                        .position(|old| old.target.same(&item.target))
                        .unwrap_or_else(|| {
                            root.folder.items.push(item);
                            root.folder.items.len() - 1
                        });
                    last = Some(index);
                }
                Err(error) => self.error(format!("{error:#}")),
            }
        }
        if let Some(row) = last {
            self.select(0, row, cx);
        }
    }

    fn receive_folder(
        &mut self,
        id: u64,
        result: anyhow::Result<Option<Folder>>,
        cx: &mut Context<Self>,
    ) {
        let Some(depth) = self.columns.iter().position(|column| column.id == id) else {
            return;
        };
        self.columns[depth].loading = false;
        match result {
            Ok(Some(folder)) => {
                let column = &mut self.columns[depth];
                column.folder = folder;
                if depth > 0 {
                    if let Some(row) = self.columns[depth - 1].selected {
                        self.columns[depth - 1].folder.items[row].container = true;
                    }
                    self.reveal_column = Some(depth);
                }
            }
            Ok(None) if depth > 0 => {
                self.columns.truncate(depth);
                let parent = depth - 1;
                self.active = parent;
                if let Some(row) = self.columns[parent].selected {
                    self.columns[parent].folder.items[row].container = false;
                    self.selection = Some((parent, row));
                    self.show_inspector = true;
                    self.read_selection(cx);
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.columns[depth].error = Some(format!("{error:#}"));
            }
        }
        self.refresh_names(cx);
    }

    fn reset_preview(&mut self, cx: &mut Context<Self>) {
        self.inspector_width = None;
        self.request.store(true, Ordering::Relaxed);
        self.request = Arc::new(AtomicBool::new(false));
        self.preview_error = None;
        self.preview_loading = false;
        self.clear_preview(cx);
    }

    fn clear_preview(&mut self, cx: &mut Context<Self>) {
        self.image_view.frames.clear(cx);
        if let Some(preview) = self.preview.take() {
            preview.release(cx);
        }
        self.ir_selected = None;
        self.playback = None;
        self.audio_position = 0.;
        self.audio_meter = level_meter::Meter::default();
        self.preview_scroll = UniformListScrollHandle::new();
        self.preview_vertical_bar = scrollbar::Scrollbar::default();
        self.preview_horizontal_bar = scrollbar::Scrollbar::default();
        self.image_view = image_view::State::default();
    }

    fn open_paths(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        self.pending += 1;
        let sender = self.sender.clone();
        cx.background_executor()
            .spawn(async move {
                let _ = sender.send(Event::Imported(
                    paths.into_iter().map(Item::from_path).collect(),
                ));
            })
            .detach();
        cx.notify();
    }
    fn open_dialog(&mut self, _: &Open, _: &mut Window, cx: &mut Context<Self>) {
        self.path_dialog(false, cx);
    }
    fn path_dialog(&mut self, directories: bool, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: !directories,
            directories,
            multiple: true,
            prompt: Some(
                if directories {
                    "Open folders"
                } else {
                    "Open files"
                }
                .into(),
            ),
        });
        cx.spawn(async move |weak, cx| match paths.await {
            Ok(Ok(Some(paths))) => {
                let _ = weak.update(cx, |this, cx| this.open_paths(paths, cx));
            }
            Ok(Ok(None)) => {}
            result => {
                let _ = weak.update(cx, |this, cx| {
                    this.error(format!("Cannot open file dialog: {result:?}"));
                    cx.notify();
                });
            }
        })
        .detach();
    }
    fn selected_item(&self) -> Option<&Item> {
        let (depth, row) = self.selection?;
        self.columns.get(depth)?.folder.items.get(row)
    }
    fn select(&mut self, depth: usize, row: usize, cx: &mut Context<Self>) {
        let Some(item) = self
            .columns
            .get(depth)
            .and_then(|column| column.folder.items.get(row))
            .cloned()
        else {
            return;
        };
        if self.columns[depth].selected == Some(row) && self.columns.len() > depth + 1 {
            self.activate(depth, cx);
            self.reveal_column = Some(depth + 1);
            return;
        }
        self.columns.truncate(depth + 1);
        self.columns[depth].selected = Some(row);
        self.active = depth;
        self.reveal_column = Some(depth);
        self.selection = None;
        if item.container {
            self.reset_preview(cx);
            self.load_child(depth, &item, cx);
        } else {
            self.selection = Some((depth, row));
            self.show_inspector = true;
            self.read_selection(cx);
        }
        self.path_scroll.scroll_to_item(depth + 1);
        cx.notify();
    }
    fn load_child(&mut self, depth: usize, item: &Item, cx: &mut Context<Self>) {
        self.columns.truncate(depth + 1);
        let id = self.next_column_id;
        self.next_column_id += 1;
        let mut column = Column::new(id, Folder::empty(item.target.clone()));
        column.loading = true;
        let cancel = column.cancelled.clone();
        let target = item.target.clone();
        let sender = self.sender.clone();
        let virtual_paths = self.preferences.virtual_paths();
        self.columns.push(column);
        self.reveal_column = Some(depth + 1);
        cx.background_executor()
            .spawn(async move {
                let _ = sender.send(Event::Folder(
                    id,
                    browser::open(&target, &cancel, virtual_paths),
                ));
            })
            .detach();
    }
    fn retry_column(&mut self, depth: usize, cx: &mut Context<Self>) {
        let Some(column) = self.columns.get_mut(depth) else {
            return;
        };
        column.error = None;
        column.loading = true;
        let id = column.id;
        let target = column.folder.target.clone();
        let cancel = column.cancelled.clone();
        let sender = self.sender.clone();
        let virtual_paths = self.preferences.virtual_paths();
        cx.background_executor()
            .spawn(async move {
                let _ = sender.send(Event::Folder(
                    id,
                    browser::open(&target, &cancel, virtual_paths),
                ));
            })
            .detach();
        cx.notify();
    }
    fn activate(&mut self, depth: usize, cx: &mut Context<Self>) {
        if depth >= self.columns.len() {
            return;
        }
        self.active = depth;
        self.selection = self.columns[depth]
            .selected
            .filter(|&row| !self.columns[depth].folder.items[row].container)
            .map(|row| (depth, row));
        if self.selection.is_some() && self.show_inspector {
            self.read_selection(cx);
        } else {
            self.reset_preview(cx);
        }
        self.reveal_column = Some(depth);
        self.path_scroll.scroll_to_item(depth + 1);
        cx.notify();
    }
    fn read_selection(&mut self, cx: &mut Context<Self>) {
        let Some(target) = self.selected_item().map(|item| item.target.clone()) else {
            return;
        };
        self.request.store(true, Ordering::Relaxed);
        self.request = Arc::new(AtomicBool::new(false));
        self.preview_error = None;
        self.preview_loading = true;
        self.image_view.pending = None;
        self.image_view.frames.cancel();
        let request = self.request.clone();
        let sender = self.sender.clone();
        let raw = self.raw;
        cx.background_executor()
            .spawn(async move {
                let result = crate::resource::read(&target, raw, &request)
                    .and_then(|resource| Preview::new(resource, &request));
                let _ = sender.send(Event::Preview(request, result));
            })
            .detach();
    }

    fn copy_instruction(&mut self, _: &CopyInstruction, _: &mut Window, cx: &mut Context<Self>) {
        let Some(json) = self.preview.as_ref().and_then(|preview| {
            let row = self.ir_selected?;
            let table = preview.ir_table.as_ref()?;
            if let Some(psb) = &preview.psb {
                table.psb_json(row, psb)
            } else {
                let index = table.instruction_index(row)?;
                Some(preview.script.as_ref()?.instructions.get(index)?.to_json())
            }
        }) else {
            return;
        };
        match json {
            Ok(json) => cx.write_to_clipboard(ClipboardItem::new_string(json)),
            Err(error) => {
                self.error(error.to_string());
                cx.notify();
            }
        }
    }

    fn export_preview(&mut self, cx: &mut Context<Self>) {
        use crate::resource::ExportKind;
        if self.extracting
            || self.converting
            || self.preview_loading
            || self.preview_error.is_some()
        {
            return;
        }
        let kind = self
            .preview
            .as_ref()
            .filter(|_| !self.raw)
            .and_then(|preview| {
                if preview.script.is_some() {
                    Some(ExportKind::Ir)
                } else if preview.image.is_some() {
                    Some(ExportKind::Png)
                } else if preview.audio.is_some() {
                    Some(ExportKind::Wav)
                } else {
                    None
                }
            });
        if let Some(kind) = kind {
            self.export_resource(kind, cx);
        } else {
            self.export_dialog(true, cx);
        }
    }

    fn export_resource(&mut self, kind: crate::resource::ExportKind, cx: &mut Context<Self>) {
        if self.converting {
            return;
        }
        let Some(name) = self.selected_item().map(|item| item.target.export_name()) else {
            return;
        };
        let Some(preview) = &self.preview else {
            return;
        };
        let bytes = preview.bytes.clone();
        let script = preview.script.clone();
        let image_frame = preview.image_frame;
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Choose export folder".into()),
        });
        cx.spawn(async move |weak, cx| match paths.await {
            Ok(Ok(Some(paths))) => {
                if let Some(output) = paths.into_iter().next() {
                    let _ = weak.update(cx, |this, cx| {
                        if this.converting {
                            return;
                        }
                        this.converting = true;
                        let sender = this.sender.clone();
                        cx.background_executor()
                            .spawn(async move {
                                let result = (|| -> anyhow::Result<PathBuf> {
                                    let converted = crate::resource::convert(
                                        &bytes,
                                        kind,
                                        script.as_deref(),
                                        image_frame,
                                    )?;
                                    let name = if matches!(kind, crate::resource::ExportKind::Png)
                                        && image_frame != 0
                                    {
                                        format!(
                                            "{name}.frame-{}.{}",
                                            image_frame + 1,
                                            kind.extension()
                                        )
                                    } else {
                                        format!("{name}.{}", kind.extension())
                                    };
                                    Ok(nvlens_io::filesystem::write_under(
                                        &output, &name, &converted,
                                    )?)
                                })();
                                let _ = sender.send(Event::Converted(result));
                            })
                            .detach();
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            result => {
                let _ = weak.update(cx, |this, cx| {
                    this.error(format!("Cannot choose output folder: {result:?}"));
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn enter_nested(&mut self, _: &Enter, window: &mut Window, cx: &mut Context<Self>) {
        let depth = self.active;
        if self.columns.len() > depth + 1 {
            self.activate(depth + 1, cx);
            if !self.columns[depth + 1].folder.items.is_empty() {
                self.select(depth + 1, 0, cx);
            }
        } else if let Some(item) = self
            .columns
            .get(depth)
            .and_then(|column| column.selected.and_then(|row| column.folder.items.get(row)))
            .cloned()
        {
            self.reset_preview(cx);
            self.selection = None;
            self.load_child(depth, &item, cx);
        }
        window.focus(&self.browser_focus);
        cx.notify();
    }
    fn back(&mut self, _: &Back, window: &mut Window, cx: &mut Context<Self>) {
        if self.active > 0 {
            self.activate(self.active - 1, cx);
        } else if self.columns.len() > 1 {
            self.columns.truncate(1);
            self.columns[0].selected = None;
            self.selection = None;
            self.reset_preview(cx);
            cx.notify();
        }
        window.focus(&self.browser_focus);
    }
    fn home(&mut self, _: &Home, window: &mut Window, cx: &mut Context<Self>) {
        self.path_menu = None;
        self.columns.truncate(1);
        self.columns[0].selected = None;
        self.activate(0, cx);
        window.focus(&self.browser_focus);
    }
    fn collapse_path(&mut self, depth: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(column) = self.columns.get(depth) else {
            return;
        };
        let container = column
            .selected
            .is_some_and(|row| column.folder.items[row].container);
        let target = if container && depth + 1 < self.columns.len() {
            self.columns[depth + 1].selected = None;
            depth + 1
        } else {
            depth
        };
        self.path_menu = None;
        self.columns.truncate(target + 1);
        self.activate(target, cx);
        window.focus(&self.browser_focus);
    }
    fn move_selection(&mut self, down: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(column) = self.columns.get(self.active) else {
            return;
        };
        let next = match (column.selected, down) {
            (Some(index), true) => (index + 1).min(column.folder.items.len().saturating_sub(1)),
            (Some(index), false) => index.saturating_sub(1),
            (None, _) => 0,
        };
        if next < column.folder.items.len() {
            column.scroll.scroll_to_item(next, ScrollStrategy::Center);
            self.select(self.active, next, cx);
            window.focus(&self.browser_focus);
        }
    }

    fn toggle_inspector(&mut self, _: &Inspector, window: &mut Window, cx: &mut Context<Self>) {
        self.show_inspector = !self.show_inspector;
        self.inspector_width = None;
        self.reveal_column = Some(self.active);
        if !self.show_inspector {
            self.reset_preview(cx);
            window.focus(&self.browser_focus);
        }
        if self.show_inspector && self.selection.is_some() && self.preview.is_none() {
            self.read_selection(cx);
        }
        cx.notify();
    }

    fn toggle_settings(&mut self, _: &Settings, window: &mut Window, cx: &mut Context<Self>) {
        self.show_settings = !self.show_settings;
        self.show_export_menu = false;
        self.path_menu = None;
        window.focus(if self.show_settings {
            &self.focus
        } else {
            &self.browser_focus
        });
        cx.notify();
    }

    fn toggle_virtual_paths(&mut self, cx: &mut Context<Self>) {
        self.preferences
            .set_virtual_paths(!self.preferences.virtual_paths());
        self.path_switch_changed = Some(Instant::now());
        let preferences = self.preferences.clone();
        let sender = self.sender.clone();
        cx.background_executor()
            .spawn(async move {
                let _ = sender.send(Event::PreferencesSaved(preferences.save()));
            })
            .detach();
        // Reopen the outermost archive, including an in-flight mount. New column
        // IDs discard stale results and nested views cannot retain the old mode.
        if let Some(depth) = self.columns.iter().position(|column| {
            matches!(
                column.folder.target,
                Target::ArchiveDirectory { .. } | Target::File(..) | Target::Entry { .. }
            )
        }) && depth > 0
            && let Some(item) = self.columns[depth - 1]
                .selected
                .and_then(|row| self.columns[depth - 1].folder.items.get(row))
                .cloned()
        {
            self.active = depth - 1;
            self.selection = None;
            self.reset_preview(cx);
            self.path_menu = None;
            self.load_child(depth - 1, &item, cx);
        }
        cx.notify();
    }

    fn cancel(&mut self, _: &Cancel, window: &mut Window, cx: &mut Context<Self>) {
        if self.show_settings {
            self.toggle_settings(&Settings, window, cx);
            return;
        }
        if self.path_menu.take().is_some() {
            window.focus(&self.browser_focus);
            cx.notify();
            return;
        }
        if self.show_export_menu {
            self.show_export_menu = false;
            cx.notify();
            return;
        }
        if self.show_status {
            self.show_status = false;
            cx.notify();
            return;
        }
        if self.show_inspector && self.selection.is_some() {
            self.toggle_inspector(&Inspector, window, cx);
            return;
        }
        if self.extracting {
            self.cancel_extraction(cx);
        } else {
            self.show_errors = false;
            self.show_status = false;
        }
        cx.notify();
    }

    fn cancel_extraction(&mut self, cx: &mut Context<Self>) {
        self.cancel.store(true, Ordering::Relaxed);
        cx.notify();
    }

    fn export_dialog(&mut self, selected: bool, cx: &mut Context<Self>) {
        self.show_export_menu = false;
        cx.notify();
        if self.extracting {
            return;
        }
        let Some(column) = self.columns.get(
            if self.columns.len() > self.active + 1
                && self.columns[self.active]
                    .selected
                    .is_some_and(|row| self.columns[self.active].folder.items[row].container)
            {
                self.active + 1
            } else {
                self.active
            },
        ) else {
            return;
        };
        let items = if selected {
            let Some(item) = self.selected_item() else {
                return;
            };
            vec![item.clone()]
        } else {
            if matches!(column.folder.target, Target::Opened) {
                return;
            }
            column.folder.items.clone()
        };
        if items.is_empty() {
            return;
        }
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Choose export folder".into()),
        });
        let raw = self.raw;
        cx.spawn(async move |weak, cx| match paths.await {
            Ok(Ok(Some(paths))) => {
                if let Some(output) = paths.into_iter().next() {
                    let _ = weak.update(cx, |this, cx| {
                        if this.extracting {
                            return;
                        }
                        this.extracting = true;
                        this.cancel = Arc::new(AtomicBool::new(false));
                        this.progress = Progress {
                            total: items.len(),
                            ..Progress::default()
                        };
                        this.output = Some(output.clone());
                        let cancel = this.cancel.clone();
                        let sender = this.sender.clone();
                        cx.background_executor()
                            .spawn(async move {
                                let mut last_update = Instant::now();
                                let result = browser::export(
                                    &items,
                                    &output,
                                    raw,
                                    &cancel,
                                    |progress, error| {
                                        if error.is_some()
                                            || progress.completed == progress.total
                                            || last_update.elapsed() >= Duration::from_millis(80)
                                        {
                                            let _ = sender.send(Event::Progress(progress, error));
                                            last_update = Instant::now();
                                        }
                                    },
                                );
                                let _ = sender.send(Event::Finished(result));
                            })
                            .detach();
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            result => {
                let _ = weak.update(cx, |this, cx| {
                    this.error(format!("Cannot choose output folder: {result:?}"));
                    cx.notify();
                });
            }
        })
        .detach();
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.request.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::rust_2024::test;

    #[test]
    fn preview_pixels_are_ready_in_bgra_without_an_image_loader() -> anyhow::Result<()> {
        use nvlens_image::{Image, ImageMeta, OffsetUnit, PixelBuffer};
        let meta = ImageMeta {
            width: 1,
            height: 1,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        };
        for (pixels, expected) in [
            (PixelBuffer::Rgba8(vec![10, 20, 30, 40]), [30, 20, 10, 40]),
            (PixelBuffer::Bgra8(vec![30, 20, 10, 40]), [30, 20, 10, 40]),
            (
                PixelBuffer::Rgba16(vec![0x1010, 0x8080, 0xffff, 0x4040]),
                [255, 128, 16, 64],
            ),
        ] {
            let image = Preview::render_image(
                Image {
                    meta: meta.clone(),
                    pixels,
                },
                None,
            )?;
            assert_eq!(image.as_bytes(0), Some(expected.as_slice()));
        }
        assert!(
            Preview::render_image(
                Image {
                    meta,
                    pixels: PixelBuffer::Rgba8(vec![10, 20, 30]),
                },
                None
            )
            .is_err()
        );
        Ok(())
    }
}
