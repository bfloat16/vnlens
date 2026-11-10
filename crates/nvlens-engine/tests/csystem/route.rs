use super::*;
#[test]
fn resource_names_follow_native_volume_templates() {
    for name in [
        "arc00.dat",
        "arc08a.dat",
        "data00.dat",
        "data000.dat",
        "resources/data071.dat",
    ] {
        assert!(archive_name(name));
    }
    for name in [
        "data01.dat",
        "data0.dat",
        "data0000.dat",
        "arc001.dat",
        "data.pac",
    ] {
        assert!(!archive_name(name));
    }
}
