use super::*;

#[test]
fn maps_names_without_losing_components() {
    for (input, expected) in [
        ("..", "%2E%2E"),
        (".", "%2E"),
        ("", "%"),
        ("%", "%25"),
        ("C:", "C%3A"),
        ("NUL.txt", "%4EUL.txt"),
        ("a:b", "a%3Ab"),
        ("file.", "file%2E"),
    ] {
        assert_eq!(output_component(input), expected);
        assert!(is_safe_relative_path(expected));
    }
    assert_eq!(output_component("image.png"), "image.png");
}

#[test]
fn rejects_nonportable_and_escaping_names() {
    for name in [
        "",
        "/file",
        "\\file",
        "C:foo",
        "a/../b",
        "a/./b",
        "a//b",
        "file:stream",
        "NUL.txt",
        "COM1",
        "lpt².log",
        "a/.. ",
        "a\0b",
        "file.",
    ] {
        assert!(!is_safe_relative_path(name), "{name:?}");
    }
    for name in [
        "dir/file.bin",
        "dir\\file.bin",
        "日本語.txt",
        "COM10",
        "a.b",
    ] {
        assert!(is_safe_relative_path(name), "{name}");
    }
}

#[test]
fn streamed_output_is_atomic_and_removes_failed_temporaries() -> io::Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let root = std::env::temp_dir().join(format!("nvlens-stream-{}-{stamp}", std::process::id()));
    let destination = write_under(&root, "movie.webm", b"previous")?;
    let result = write_under_with(&root, "movie.webm", |file| {
        file.write_all(b"partial")?;
        Err(io::Error::other("producer cancelled"))
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&destination)?, b"previous");
    assert_eq!(fs::read_dir(&root)?.count(), 1);
    write_under_with(&root, "movie.webm", |file| {
        for _ in 0..17 {
            file.write_all(&[31; 8192])?;
        }
        Ok(())
    })?;
    assert_eq!(fs::read(destination)?, vec![31; 8192 * 17]);
    fs::remove_dir_all(root)?;
    Ok(())
}
