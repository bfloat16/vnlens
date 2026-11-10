use super::*;

#[test]
fn archive_info_possible_names_match_freemote_rules() {
    assert_eq!(
        archive_info_possible_file_names("image/man003", ".psb.m"),
        [
            "man003.psb.m",
            "man003",
            "image/man003.psb.m",
            "image/man003"
        ]
    );
    assert_eq!(
        archive_info_possible_file_names("bg_c_whit.m", ".psb.m"),
        ["bg_c_whit.m.psb.m", "bg_c_whit.m", "bg_c_whit"]
    );
    assert_eq!(
        archive_info_possible_file_names("mmm22.ks", ".scn.m"),
        ["mmm22.ks.scn.m", "mmm22.ks", "mmm22", "mmm22.scn.m"]
    );
}
