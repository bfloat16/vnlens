use super::*;
use vnlens_io::BinaryWriter;

#[test]
fn collection_is_lazy_companions_cache_on_request_and_video_is_not_a_voice() -> Result<()> {
    let root = std::env::temp_dir().join(format!(
        "vnlens-dataset-resources-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("pac"))?;
    std::fs::create_dir(root.join("ysbin"))?;
    let output = root.join("output");
    std::fs::create_dir(&output)?;
    let result = (|| {
        std::fs::write(root.join("yscfg.dat"), [])?;
        let mut empty = vec![0; 32];
        empty[..4].copy_from_slice(b"YPF\0");
        BinaryWriter::u32_le(0x1f4, &mut empty[4..]);
        BinaryWriter::u32_le(32, &mut empty[12..]);
        std::fs::write(root.join("pac/empty.ypf"), empty)?;
        let companion = root.join("ysbin/ysc.ybn");
        std::fs::write(&companion, b"YSCMfirst")?;
        std::fs::write(root.join("movie.ogg"), b"OggSinvalid video")?;
        let cancel = Arc::new(AtomicBool::new(false));
        let game = Arc::new(vnlens_engine::identify(&root, &cancel)?.ok_or(Error::InvalidFormat)?);
        vnlens_archive::init();
        vnlens_script::init();
        let output = output.canonicalize()?;
        let resources = Resources::collect(
            game,
            &output,
            cancel.clone(),
            &mut Progress::default(),
            &mut |_, _| {},
        )?;
        assert!(
            resources
                .items
                .iter()
                .all(|item| item.companion.get().is_none())
        );
        std::fs::write(&companion, b"YSCMsecond")?;
        assert_eq!(
            resources.read_resource("ysbin/ysc.ybn")?,
            Some(b"YSCMsecond".to_vec())
        );
        std::fs::write(&companion, b"YSCMthird")?;
        assert_eq!(
            resources.read_resource("ysbin/ysc.ybn")?,
            Some(b"YSCMsecond".to_vec())
        );
        let video = resources.find("movie.ogg").ok_or(Error::InvalidFormat)?;
        assert!(resources.write(video, &output, "invalid.ogg").is_err());
        assert!(!output.join("invalid.ogg").exists());
        assert!(resources.read_resource("missing.ybn")?.is_none());
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(
            resources.read_resource("ysbin/ysc.ybn"),
            Err(Error::Cancelled)
        ));
        Ok(())
    })();
    std::fs::remove_dir_all(&root)?;
    result
}
