use super::*;
use nvlens_io::BinaryWriter;

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
    let cancel = AtomicBool::new(false);
    let plain = scene_fixture();
    let mdf = crate::mdf::tests::encode_fixture(&plain);
    let json = crate::decode_text_as("script/krkr", &plain)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(
        crate::decode_text_as("script/krkr", &mdf)?,
        Some(json.clone())
    );
    for data in [&plain, &mdf] {
        let Some(crate::ScriptContent::Psb(psb)) = crate::decode_content_as("script/krkr", data)?
        else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(psb.to_json()?, json);
        assert_eq!(psb.root.to_json()?, json);
    }
    assert!(crate::decode_content_as("script/krkr", b"unrecognized")?.is_none());
    assert!(crate::decode_content_as("missing/script", &plain).is_err());
    let tree: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| Error::Unsupported(e.to_string()))?;
    assert_eq!(tree["voice"], "scene_001");
    let raw = name_candidates(&plain, "scene.scn", &cancel)?;
    let wrapped = name_candidates(&mdf, "hashed", &cancel)?;
    assert_eq!(raw, wrapped);
    assert!(wrapped.contains(&"scene_001.opus".into()));
    assert!(wrapped.contains(&"scene_001.opus.sli".into()));
    assert!(!wrapped.contains(&"unrelated.opus".into()));
    assert!(!wrapped.contains(&"scene_002.opus".into()));
    let mut broken = mdf.clone();
    let end = broken.len() - 1;
    broken[end] ^= 1;
    assert!(crate::decode_content_as("script/krkr", &broken).is_err());
    assert!(name_candidates(&broken, "scene.scn", &cancel).is_err());
    assert!(matches!(
        name_candidates(&mdf, "scene.scn", &AtomicBool::new(true)),
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
