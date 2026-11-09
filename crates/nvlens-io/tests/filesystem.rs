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
