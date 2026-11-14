use super::*;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use vnlens_core::{Error, ResourceKind, ResourceOrigin, ResourceRoute};
use vnlens_io::{BinaryWriter, ReadAt};

struct Unread(Arc<AtomicUsize>);
impl ReadAt for Unread {
    fn len(&self) -> u64 {
        100
    }
    fn read_at(&self, _: u64, _: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(std::io::Error::other("Payload must stay unread"))
    }
}
fn context(missing: Option<&str>) -> Result<(Context, Arc<AtomicUsize>)> {
    let root = PathBuf::from("gss.romfs");
    let mut files = vnlens_io::FileSystem::isolated(root.clone());
    let reads = Arc::new(AtomicUsize::new(0));
    for name in [
        "BMPDATA.BIN",
        "BMPDATA.ARC",
        "SCRDATA.BIN",
        "SCRDATA.ARC",
        "WAVDATA.BIN",
        "WAVDATA.ARC",
    ] {
        if Some(name) != missing {
            files.insert(root.join(name), Arc::new(Unread(reads.clone())))?;
        }
    }
    Ok((
        Context {
            root,
            files: Arc::new(files),
            sections: Default::default(),
        },
        reads,
    ))
}
#[test]
fn directory_and_ns_identification_are_lazy_and_routes_do_not_cross_engines() -> Result<()> {
    let (incomplete, _) = context(Some("SCRDATA.BIN"))?;
    assert!(!layout(&incomplete));
    let (context, reads) = context(None)?;
    let host = crate::Identification {
        root: PathBuf::new(),
        engine: Engine::NintendoSwitch,
        evidence: "Test".into(),
        options: Default::default(),
        files: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    let game = host.for_filesystem(context.root.clone(), context.files, &AtomicBool::new(false))?;
    assert_eq!(game.engine, Engine::Gss);
    assert!(game.warning().is_none());
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert!(
        matches!(game.resource_route("SCRDATA.BIN", ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "lsdarc/gss")
    );
    for (name, origin, bytes, expected) in [
        (
            "AUTOEXEC",
            ResourceOrigin::Entry(ResourceKind::Script),
            &b""[..],
            ResourceRoute::Script("scr/gss"),
        ),
        (
            "BGM01",
            ResourceOrigin::Entry(ResourceKind::Audio),
            &b""[..],
            ResourceRoute::Other(ResourceKind::Audio),
        ),
        (
            "name.obj",
            ResourceOrigin::File,
            &b""[..],
            ResourceRoute::Script("scr/gss"),
        ),
        (
            "name.opu",
            ResourceOrigin::File,
            &b""[..],
            ResourceRoute::Audio("opus/gss"),
        ),
        (
            "name",
            ResourceOrigin::File,
            &b"SCR 3.00"[..],
            ResourceRoute::Script("scr/gss"),
        ),
        (
            "BGM01",
            ResourceOrigin::Entry(ResourceKind::Audio),
            &b"\x01\0\0\x80\x18\0\0\0"[..],
            ResourceRoute::Audio("opus/gss"),
        ),
        (
            "BGM01",
            ResourceOrigin::Entry(ResourceKind::Audio),
            &b"OggS"[..],
            ResourceRoute::Media {
                audio: "audio/standard",
                video: "ffmpeg",
            },
        ),
        (
            "name",
            ResourceOrigin::File,
            &b"\x89PNG\r\n\x1a\n"[..],
            ResourceRoute::Image("image/standard"),
        ),
        (
            "name.unknown",
            ResourceOrigin::File,
            &b"SCR 3.00"[..],
            ResourceRoute::Other(ResourceKind::Unknown),
        ),
        (
            "foreign.xp3",
            ResourceOrigin::File,
            &b""[..],
            ResourceRoute::Other(ResourceKind::Unknown),
        ),
        (
            "foreign.tid",
            ResourceOrigin::File,
            &b""[..],
            ResourceRoute::Other(ResourceKind::Unknown),
        ),
    ] {
        assert_eq!(game.resource_route(name, origin, bytes), expected);
    }
    let names = [
        "BMPDATA.BIN",
        "BMPDATA.ARC",
        "SCRDATA.BIN",
        "SCRDATA.ARC",
        "WAVDATA.BIN",
        "WAVDATA.ARC",
    ]
    .map(|name| context.root.join(name));
    let sets = game.archive_sets(&names);
    assert_eq!(sets.len(), 3);
    assert!(sets.iter().all(
        |set| set.primary.extension().is_some_and(|ext| ext == "BIN") && set.members.len() == 2
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    Ok(())
}
#[test]
fn executable_requires_both_runtime_markers_and_index_identity_is_explicit() -> Result<()> {
    fn image(markers: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 0x200 + markers.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (at, value) in [
            (0x3c, 0x80),
            (0xb4, 0x400000),
            (0xd4, 0x200),
            (0x184, 0x1000),
            (0x188, markers.len() as u32),
            (0x18c, 0x200),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[at..]);
        }
        for (at, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
            BinaryWriter::u16_le(value, &mut bytes[at..]);
        }
        bytes[0x200..].copy_from_slice(markers);
        bytes
    }
    for (markers, expected) in [
        (&b"gss err : Exec 01"[..], false),
        (&b"script\\OBJ\\AutoExec.OBJ"[..], false),
        (&b"gss err : Exec 01\0script\\OBJ\\AutoExec.OBJ\0"[..], true),
    ] {
        let bytes = image(markers);
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert_eq!(pe(&image)?, expected);
    }
    let view = ArcView::from_bytes("SCRDATA.BIN".into(), Arc::from(&b"LSDARC V.100"[..]));
    assert!(file(&view)?);
    Ok(())
}
