#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn splits_speaker_preserves_ruby_base_and_rejects_unparsed_commands() {
    let mut config = Config::default();
    config.names.insert("アリス".into());
    config.markers.insert("「".into());

    assert_eq!(
        split("【アリス】「≪明日／あした≫\\R行くよ」", &config),
        Some(("アリス".into(), "「明日\n行くよ」".into()))
    );
    assert_eq!(
        split("アリス「おはよう」", &config),
        Some(("アリス".into(), "「おはよう」".into()))
    );
    assert_eq!(split("【アリス】「\\Ruby」", &config), None);
    assert_eq!(split("【】「テスト」", &config), None);
    assert!(identity("アリス"));
    assert!(!identity("？？？"));
    assert!(!identity("アリス＆ボブ"));
    assert_eq!(
        split("【アリス】  「テスト」  ", &config),
        Some(("アリス".into(), "  「テスト」  ".into()))
    );
    config.names.insert("A".into());
    config.names.insert("AB".into());
    config.markers.insert("B".into());
    assert_eq!(split("AB「ambiguous」", &config), None);
}
