use super::*;
use vnlens_io::BinaryWriter;

fn scene_fixture() -> Vec<u8> {
    fn array(out: &mut Vec<u8>, values: &[u8]) {
        out.extend([0x0d, values.len() as u8, 0x0d]);
        out.extend(values);
    }
    let mut out = vec![0; 44];
    out[..4].copy_from_slice(b"PSB\0");
    BinaryWriter::u16_le(3, &mut out[4..]);
    BinaryWriter::u32_le(44, &mut out[8..]);
    let names = out.len();
    array(&mut out, &[0; 120]);
    let mut parents = [0; 120];
    parents[119] = b'e';
    parents[usize::from(b'e')] = b'c';
    parents[usize::from(b'c')] = b'i';
    parents[usize::from(b'i')] = b'o';
    parents[usize::from(b'o')] = b'v';
    array(&mut out, &parents);
    array(&mut out, &[119]);
    let strings = out.len();
    array(&mut out, &[0, 10]);
    let text = out.len();
    out.extend(b"scene_001\0unrelated\0");
    let offsets = out.len();
    array(&mut out, &[0]);
    let lengths = out.len();
    array(&mut out, &[1]);
    let entries = out.len();
    out.push(0x21);
    array(&mut out, &[0]);
    array(&mut out, &[0]);
    out.extend([0x15, 0]);
    let resource = out.len();
    out.push(0);
    for (at, value) in [
        (12, names),
        (16, strings),
        (20, text),
        (24, offsets),
        (28, lengths),
        (32, resource),
        (36, entries),
    ] {
        BinaryWriter::u32_le(value as u32, &mut out[at..]);
    }
    out
}

#[test]
fn mdf_scenario_voice_fields_generate_sound_and_companion_names() -> Result<()> {
    use std::io::Write;

    let cancel = AtomicBool::new(false);
    let plain = scene_fixture();
    let mut header = b"mdf\0\0\0\0\0".to_vec();
    BinaryWriter::u32_le(plain.len() as u32, &mut header[4..]);
    let mut encoder = flate2::write::ZlibEncoder::new(header, flate2::Compression::fast());
    encoder.write_all(&plain)?;
    let mdf = encoder.finish()?;
    let parse = |data: &[u8]| {
        let bytes: std::sync::Arc<[u8]> = data.into();
        vnlens_middleware::psb::PsbFile::open(std::sync::Arc::new(bytes), Default::default())
    };
    let plain_file = parse(&plain)?;
    let wrapped_file = parse(&mdf)?;
    assert_eq!(plain_file.document.root, wrapped_file.document.root);
    let raw = psb_name_candidates(&plain_file.document, &cancel)?;
    let wrapped = psb_name_candidates(&wrapped_file.document, &cancel)?;
    assert_eq!(raw, wrapped);
    assert!(wrapped.contains(&"scene_001.opus".into()));
    assert!(wrapped.contains(&"scene_001.opus.sli".into()));
    assert!(!wrapped.contains(&"unrelated.opus".into()));
    assert!(!wrapped.contains(&"scene_002.opus".into()));
    assert!(matches!(
        psb_name_candidates(&wrapped_file.document, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn sysse_aliases_channels_and_explicit_extensions() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let input=b"# skipped = phantom\nvoice.test = sys_011 : 9\nclick=@select\nend = music.opus*chorus\nexpression = &getVoice()\n";
    let names = name_candidates(input, "main/sysse.ini", &cancel)?;
    assert!(names.contains(&"sys_011.opus".into()));
    assert!(names.contains(&"music.opus.sli".into()));
    for name in [
        "select.opus",
        "phantom.opus",
        "music.opus.opus",
        "getVoice().opus",
    ] {
        assert!(!names.contains(&name.into()));
    }
    assert!(!name_candidates(input, "other.txt", &cancel)?.contains(&"sys_011.opus".into()));
    Ok(())
}
#[test]
fn exact_text_concatenations_and_scene_rules_only() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let names = name_candidates(
        br#"var a="scenario/" + "first.ks"; var b="bg"+unknown+"01"; @image storage=bg/room.png"#,
        "test.tjs",
        &cancel,
    )?;
    assert!(names.contains(&"scenario/first.ks".into()));
    assert!(names.contains(&"bg/room.png".into()));
    assert!(!names.contains(&"bg01".into()));
    assert!(!names.contains(&"first.tjs".into()));
    let names = name_candidates(b"chapter01.txt\tlabel", "!scnlist.txt", &cancel)?;
    assert!(names.contains(&"scenario/chapter01.scn".into()));
    assert!(matches!(
        name_candidates(b"text", "x", &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn stand_filename_properties_use_composite_suffixes_without_evaluating_code() -> Result<()> {
    let source = br#"[%["filename" => "actor" + "1", "note" => "unused"],
        %["filename", "actor2"], %["filename": "explicit.pimg"],
        %["filename" => "prefix" + unknown], %["filename" => &getFile()],
        // "filename" => "commented"
        %["filename" => "%dress|fallback"]]"#;
    let cancel = AtomicBool::new(false);
    let names = name_candidates(source, "characters/actor.stand", &cancel)?;
    for name in ["actor1.pimg", "actor1.txt", "actor2.txt", "explicit.pimg"] {
        assert!(names.iter().any(|value| value == name), "{name}");
    }
    for name in [
        "unused.pimg",
        "prefix.pimg",
        "commented.pimg",
        "%dress|fallback.pimg",
        "explicit.pimg.pimg",
    ] {
        assert!(!names.iter().any(|value| value == name), "{name}");
    }
    assert!(
        !name_candidates(source, "unrelated.tjs", &cancel)?
            .iter()
            .any(|value| value == "actor1.pimg")
    );
    Ok(())
}

#[test]
fn stage_time_templates_use_declared_labels_and_prefixes() -> Result<()> {
    let input = br#"%["times", %[
        "day", %["label", "a"], "evening", %["prefix" => "b"],
        "dynamic", %["label", &getTime()]],
        "stages", %["room", %["image", "bg01TIMEo"],
        "fixed", %["image", "fixed"],
        // "unused", %["image", "commentTIME"],
        "dynamic", %["image", "prefix"+unknown]]];"#;
    let cancel = AtomicBool::new(false);
    let names = name_candidates(input, "base.stage", &cancel)?;
    for name in ["bg01ao.png", "bg01bo.jpg", "fixed.tlg"] {
        assert!(names.iter().any(|value| value == name), "{name}");
    }
    for name in ["bg01co.png", "commenta.png", "prefix.png"] {
        assert!(!names.iter().any(|value| value == name), "{name}");
    }
    assert!(
        !name_candidates(input, "unrelated.tjs", &cancel)?
            .iter()
            .any(|value| value == "bg01ao.png")
    );
    Ok(())
}
