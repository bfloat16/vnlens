//! Canonical external key paths grouped by engine.

/// AGES-MK2 (`smash::fw`) engine key blobs.
pub mod ages_mk2 {
    /// 64 KiB scramble base table (FPD index/data descrambling).
    pub const SCRAMBLE_BASE: &str = "ages_mk2/scramble_base.bin";
    /// EPK (`Crypt`) custom-Blowfish P/S table (4168 bytes).
    pub const EPK_BLOWFISH_DATAS: &str = "ages_mk2/epk_blowfish_datas.bin";
    /// FCD audio (`SoundCrypt`) custom-Blowfish P/S table (4168 bytes).
    pub const SOUND_BLOWFISH_DATAS: &str = "ages_mk2/sound_blowfish_datas.bin";
    /// 0x4000-byte FCD audio key-derivation salt.
    pub const SOUND_MD5_SALT: &str = "ages_mk2/sound_md5_salt.bin";
}

/// Public-domain Vorbis 1.0 setup packets used by rUGP OptimizedObs.
pub mod rugp {
    pub const VORBIS_SETUPS: [&str; 6] = [
        "rugp/vorbis_setup01.bin",
        "rugp/vorbis_setup02.bin",
        "rugp/vorbis_setup03.bin",
        "rugp/vorbis_setup04.bin",
        "rugp/vorbis_setup05.bin",
        "rugp/vorbis_setup06.bin",
    ];
}
