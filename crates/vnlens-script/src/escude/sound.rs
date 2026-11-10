//! Headerless SOUNDFX presets from misc/sound.h and acpx.h. Eight LE u32
//! enable flags precede the eight DirectSound effect parameter structures.
//! This is configuration metadata, not encoded audio.
use super::*;
use crate::ir::ArgName as A;

#[derive(Debug, Default)]
struct Sound;
impl Format for Sound {
    fn tag(&self) -> &'static str {
        "sfx/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["sfx"]
    }
    fn description(&self) -> &'static str {
        "Escu:de sound effect presets"
    }
}
impl ScriptFormat for Sound {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        decode_envelope(data)
    }
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        let mut r = BinaryReader::new(data);
        let mut flags = Vec::new();
        for _ in 0..8 {
            flags.push(r.read_u32_le()?);
        }
        let mut out = script(data, "sfx/escude", 1);
        let mut effects = Vec::new();
        for (index, (name, fields)) in EFFECTS.iter().enumerate() {
            let start = r.position();
            let mut values = vec![number(A::Flags, index * 4, flags[index])];
            for (parameter, &(name, integer)) in fields.iter().enumerate() {
                let at = r.position();
                let raw = r.read_u32_le()?;
                let mut value = arg(
                    A::ValueAt(parameter as u64),
                    at,
                    4,
                    if integer {
                        Value::Integer(i64::from(raw as i32))
                    } else {
                        Value::Float32Bits(raw)
                    },
                );
                value.native_name = Some(name.into());
                values.push(value);
            }
            let mut effect = arg(
                A::ValueAt(index as u64),
                start,
                r.position() - start,
                Value::Group(values),
            );
            effect.native_name = Some((*name).into());
            effects.push(effect);
        }
        let end = r.position();
        record(
            &mut out,
            0,
            end,
            Qualifier::Configuration,
            vec![arg(A::Metadata, 0, end, Value::Group(effects))],
        );
        if r.remaining() != 0 {
            let at = r.position();
            let bytes = r.read_bytes(r.remaining())?;
            record(
                &mut out,
                at,
                bytes.len(),
                Qualifier::Bytes,
                vec![arg(A::Data, at, bytes.len(), Value::Bytes(bytes.to_vec()))],
            );
        }
        Ok(Some(out))
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Sound))}

type EffectFields = &'static [(&'static str, bool)];
const EFFECTS: &[(&str, EffectFields)] = &[
    (
        "chorus",
        &[
            ("wet_dry_mix", false),
            ("depth", false),
            ("feedback", false),
            ("frequency", false),
            ("waveform", true),
            ("delay", false),
            ("phase", true),
        ],
    ),
    (
        "compressor",
        &[
            ("gain", false),
            ("attack", false),
            ("release", false),
            ("threshold", false),
            ("ratio", false),
            ("predelay", false),
        ],
    ),
    (
        "distortion",
        &[
            ("gain", false),
            ("edge", false),
            ("post_eq_center_frequency", false),
            ("post_eq_bandwidth", false),
            ("pre_lowpass_cutoff", false),
        ],
    ),
    (
        "echo",
        &[
            ("wet_dry_mix", false),
            ("feedback", false),
            ("left_delay", false),
            ("right_delay", false),
            ("pan_delay", true),
        ],
    ),
    (
        "flanger",
        &[
            ("wet_dry_mix", false),
            ("depth", false),
            ("feedback", false),
            ("frequency", false),
            ("waveform", true),
            ("delay", false),
            ("phase", true),
        ],
    ),
    ("gargle", &[("rate_hz", true), ("wave_shape", true)]),
    (
        "param_eq",
        &[("center", false), ("bandwidth", false), ("gain", false)],
    ),
    (
        "reverb",
        &[
            ("in_gain", false),
            ("reverb_mix", false),
            ("reverb_time", false),
            ("high_freq_rt_ratio", false),
        ],
    ),
];
