//! KiriKiri layer type values follow ScriptMgnIntf.cpp. Channel formulas follow
//! the KiriKiri Graphic System's Layer Types reference, including its power-law
//! soft light and Photoshop 5 dodge/difference variants. PNG output uses straight
//! alpha; compositing accounts for transparent destination pixels.
use vnlens_core::{Error, Result};

#[derive(Clone, Copy)]
pub(super) struct Mode(u8);

impl Mode {
    pub(super) fn new(value: i64) -> Result<Self> {
        match value {
            1..=5 | 8..=28 => Ok(Self(value as u8)),
            _ => Err(Error::Unsupported(format!("PIMG layer blend mode {value}"))),
        }
    }

    pub(super) fn apply(self, dest: &mut [u8; 4], source: [u8; 4], opacity: u8) {
        let alpha = if matches!(self.0, 1..=5 | 8..=11) {
            255
        } else {
            u32::from(source[3])
        };
        let sa = (alpha * u32::from(opacity) + 127) / 255;
        let da = u32::from(dest[3]);
        let total = sa * 255 + da * (255 - sa);
        if total == 0 {
            return;
        }
        if matches!(self.0, 1 | 2 | 13) {
            for channel in 0..3 {
                let color = u32::from(source[channel]) * sa * 255
                    + u32::from(dest[channel]) * da * (255 - sa);
                dest[channel] = ((color + total / 2) / total) as u8;
            }
        } else {
            let a = f64::from(sa) / 255.;
            let b = f64::from(da) / 255.;
            let out_alpha = f64::from(total) / (255. * 255.);
            for channel in 0..3 {
                let d = f64::from(dest[channel]) / 255.;
                let s = f64::from(source[channel]) / 255.;
                let premultiplied = if self.0 == 12 {
                    d * b * (1. - a) + s * f64::from(opacity) / 255.
                } else {
                    b * self.channel(d, s, a) + (1. - b) * a * s
                };
                dest[channel] = (premultiplied / out_alpha * 255.).round().clamp(0., 255.) as u8;
            }
        }
        dest[3] = ((total + 127) / 255) as u8;
    }

    fn channel(self, dest: f64, source: f64, alpha: f64) -> f64 {
        // Photoshop 5 applies opacity inside the operation, rather than
        // interpolating the complete effect with the destination afterwards.
        if self.0 == 22 {
            return dodge(dest, source * alpha);
        }
        if self.0 == 27 {
            return (dest - source * alpha).abs();
        }
        let blend = match self.0 {
            3 | 14 => (dest + source).min(1.),
            4 | 15 => (dest + source - 1.).max(0.),
            5 | 16 => dest * source,
            8 | 21 => dodge(dest, source),
            9 | 25 => dest.min(source),
            10 | 24 => dest.max(source),
            11 | 17 => 1. - (1. - dest) * (1. - source),
            18 => overlay(dest, source),
            19 => overlay(source, dest),
            20 => dest.powf(if source >= 0.5 {
                0.5 / source
            } else {
                (1. - source) * 2.
            }),
            23 if source == 0. => 0.,
            23 => (1. - (1. - dest) / source).max(0.),
            26 => (dest - source).abs(),
            28 => dest + source - 2. * dest * source,
            _ => source,
        };
        dest * (1. - alpha) + blend * alpha
    }
}

fn dodge(dest: f64, source: f64) -> f64 {
    if source == 1. {
        1.
    } else {
        (dest / (1. - source)).min(1.)
    }
}

fn overlay(dest: f64, source: f64) -> f64 {
    if dest < 0.5 {
        2. * dest * source
    } else {
        1. - 2. * (1. - dest) * (1. - source)
    }
}

#[cfg(test)]
#[path = "../../../tests/krkr/pimg/blend.rs"]
mod tests;
