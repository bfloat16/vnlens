use super::*;

#[path = "local.rs"]
mod local;

#[test]
fn only_native_update_archive_names_override_base_resources() {
    for number in 1..=9 {
        assert_eq!(archive_priority(&format!("pac/UPDATE{number}.YPF")), number);
    }
    for name in [
        "update.ypf",
        "update0.ypf",
        "update10.ypf",
        "ysbin.ypf",
        "update1.dat",
        "pac/update1.ypf/other.ypf",
    ] {
        assert_eq!(archive_priority(name), 0);
    }
}
