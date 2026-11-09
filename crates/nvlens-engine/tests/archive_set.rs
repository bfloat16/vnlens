use super::*;
use nvlens_core::ArchiveOptions;

fn game(engine: Engine) -> Identification {
    Identification {
        engine,
        root: PathBuf::from("game"),
        evidence: "synthetic".into(),
        options: ArchiveOptions::default(),
        emote: None,
    }
}
fn files(names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|name| PathBuf::from("game").join(name))
        .collect()
}

#[test]
fn split_indices_and_volumes_keep_one_reader_and_all_original_members() {
    let paths = files(&[
        "BG.GPK",
        "BG.GTB",
        "voice.vpk",
        "voice.vtb",
        "orphan.gtb",
        "other/BG.GTB",
    ]);
    let sets = game(Engine::SystemNnn).archive_sets(&paths);
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].primary, paths[0]);
    assert_eq!(sets[0].members, paths[..2]);
    assert_eq!(sets[1].members, paths[2..4]);
    let paths = files(&[
        "game.RIO",
        "game.RIO.ici",
        "game.RIO.002",
        "game.RIO.003",
        "game.RIO.ruo",
        "game.RIO.004.bak",
        "other.RIO.002",
    ]);
    let sets = game(Engine::Rugp).archive_sets(&paths);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].primary, paths[0]);
    assert_eq!(sets[0].members.len(), 5);
    assert!(paths[..5].iter().all(|path| sets[0].members.contains(path)));
}

#[test]
fn exhibit_uses_hex_group_boundary_and_requires_the_index_volume() {
    let paths = files(&[
        "res2a00.grp",
        "res2a01.grp",
        "res2a0f.grp",
        "res2b00.grp",
        "res2b01.grp",
        "res2c01.grp",
    ]);
    let sets = game(Engine::Exhibit).archive_sets(&paths);
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].members, paths[..3]);
    assert_eq!(sets[1].members, paths[3..5]);
}

#[test]
fn emote_uses_the_same_body_priority_as_the_reader() {
    let mut game = game(Engine::Krkr);
    let paths = files(&[
        "sample_info.psb.m",
        "sample_body.bin",
        "samplebody.bin",
        "sample.bin",
    ]);
    assert!(game.archive_sets(&paths).is_empty());
    game.emote = Some(ArchiveOptions::default());
    let sets = game.archive_sets(&paths);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].members, paths[..2]);
}
