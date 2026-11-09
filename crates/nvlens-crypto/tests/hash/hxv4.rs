use super::*;
#[test]
fn stored_directory_byte_order_and_domain() {
    assert_eq!(
        directory("", "xp3hnp"),
        [0x94, 0xd4, 0xa9, 0x7c, 0x61, 0x49, 0x86, 0x21]
    );
    assert_ne!(
        directory("scenario", "xp3hnp"),
        directory("scenario/", "xp3hnp")
    );
    assert_ne!(filename("a.tjs", "xp3hnp"), filename("a.tjs", "other"));
}
