use super::*;
use std::prelude::rust_2024::test;

#[test]
fn unknown_utf8_resources_still_use_hex_without_starting_the_gui() -> anyhow::Result<()> {
    for (kind, text) in [
        (vnlens_core::ResourceKind::Unknown, false),
        (vnlens_core::ResourceKind::Data, true),
    ] {
        let resource = crate::resource::Resource {
            route: vnlens_core::ResourceRoute::Other(kind),
            bytes: Arc::from(b"unrecognized content\n".as_slice()),
            script: None,
            psb: None,
            image: None,
            model: None,
            audio: false,
            video: None,
        };
        let preview = Preview::new(resource, &Arc::new(AtomicBool::new(false)))?;
        assert_eq!(preview.lines.is_some(), text);
        assert_eq!(&*preview.bytes, b"unrecognized content\n");
        assert!(preview.image.is_none() && preview.audio.is_none() && preview.video.is_none());
    }
    Ok(())
}
