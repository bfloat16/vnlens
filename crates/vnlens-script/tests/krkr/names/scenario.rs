use super::*;

fn text(value: &str) -> PsbValue {
    PsbValue::String {
        index: 0,
        value: value.into(),
    }
}
fn object(fields: &[(&str, PsbValue)]) -> PsbValue {
    PsbValue::Object(
        fields
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone()))
            .collect(),
    )
}
fn list(values: &[PsbValue]) -> PsbValue {
    PsbValue::List(values.to_vec())
}
fn scene(value: PsbValue) -> PsbValue {
    object(&[("name", text("chapter.ks")), ("scenes", list(&[value]))])
}
fn names(root: &PsbValue) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    candidates(root, &AtomicBool::new(false), &mut out)?;
    Ok(out)
}

#[test]
fn saved_environments_preserve_image_sound_and_transition_roles() -> Result<()> {
    let root = scene(object(&[
        (
            "redraw",
            object(&[("imageFile", object(&[("file", text("bg/room"))]))]),
        ),
        ("replay", object(&[("filename", text("bgm/theme*loop"))])),
        ("trans", object(&[("rule", text("map00"))])),
        ("unrelated", text("unused")),
        ("filename", text("not_a_sound")),
    ]));
    let out = names(&root)?;
    for expected in [
        "chapter.ks.scn",
        "bg/room.png",
        "bg/room.tlg",
        "bgm/theme.opus",
        "bgm/theme.opus.sli",
        "map00.png",
    ] {
        assert!(out.contains(expected), "{expected}");
    }
    for absent in [
        "chapter.scn",
        "unused.png",
        "not_a_sound.opus",
        "bg/room.opus",
        "map00.opus",
    ] {
        assert!(!out.contains(absent), "{absent}");
    }
    // An unrelated PSB object has no SCN command semantics.
    let other = object(&[("imageFile", object(&[("file", text("texture"))]))]);
    assert!(names(&other)?.is_empty());
    Ok(())
}

#[test]
fn nexts_selects_commands_and_tags_use_their_own_loaders() -> Result<()> {
    let root = scene(object(&[
        ("nexts", list(&[object(&[("storage", text("next.ks"))])])),
        (
            "selects",
            list(&[object(&[("storage", text("selected.ks.scn"))])]),
        ),
        ("_init", object(&[("storage", text("menu"))])),
        (
            "lines",
            list(&[
                list(&[
                    text("simpleanim"),
                    text("file"),
                    text("effect"),
                    text("script"),
                    text("sanim_rotate"),
                ]),
                object(&[
                    ("tagname", text("simpleanim")),
                    ("file", text("tag_effect")),
                    ("script", text("sanim_move")),
                ]),
                list(&[text("bgm"), text("file"), text("theme")]),
                list(&[text("sysmovie"), text("file"), text("opening")]),
                list(&[text("mapinit"), text("storage"), text("mapselect")]),
            ]),
        ),
    ]));
    let out = names(&root)?;
    for expected in [
        "next.ks.scn",
        "selected.ks.scn",
        "selected.ks.scn.scn",
        "menu.pimg",
        "mapselect.pimg",
        "effect.tlg",
        "tag_effect.png",
        "sanim_rotate.tjs",
        "sanim_move.tjs",
        "theme.ogg.sli",
        "opening.mp4",
    ] {
        assert!(out.contains(expected), "{expected}");
    }
    for absent in [
        "next.scn",
        "menu.opus",
        "sanim_rotate.png",
        "opening.opus",
        "effect.tjs",
    ] {
        assert!(!out.contains(absent), "{absent}");
    }
    Ok(())
}

#[test]
fn raster_extensions_are_replaced_and_dynamic_parameters_are_not_expanded() -> Result<()> {
    let root = scene(list(&[
        object(&[("imageFile", object(&[("file", text("actor.stand"))]))]),
        list(&[
            text("simpleanim"),
            text("file"),
            text("effect.PNG"),
            text("script"),
            text("rotate.tjs"),
        ]),
        list(&[text("image"), text("storage"), text("&getImage()")]),
        list(&[text("image"), text("storage"), text("${image}")]),
        list(&[text("image"), text("storage"), text("%file|fallback")]),
    ]));
    let out = names(&root)?;
    for expected in ["actor.stand", "effect.PNG", "effect.tlg", "rotate.tjs"] {
        assert!(out.contains(expected), "{expected}");
    }
    for absent in [
        "actor.stand.png",
        "effect.PNG.png",
        "rotate.tjs.tjs",
        "&getImage().png",
        "${image}.png",
        "%file|fallback.png",
    ] {
        assert!(!out.contains(absent), "{absent}");
    }
    assert!(matches!(
        candidates(&root, &AtomicBool::new(true), &mut BTreeSet::new()),
        Err(vnlens_core::Error::Cancelled)
    ));
    Ok(())
}
