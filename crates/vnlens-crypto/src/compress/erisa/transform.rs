//! ERISA DCT and LOT transforms, matching ERISA-Library FastDCT/FastIDCT,
//! OddGivensInverseMatrix, FastIPLOT and FastILOT. Recurrences retain their
//! native f32 evaluation order; cosine/revolve generation uses f64.
use std::{f64::consts::PI, io};
use vnlens_io::BinaryIo;

#[derive(Debug)]
pub struct Dct {
    tables: Vec<Vec<f32>>,
}
impl Dct {
    pub fn new(degree: u32) -> io::Result<Self> {
        if !(2..=12).contains(&degree) {
            return Err(BinaryIo::invalid_input(
                "ERISA DCT degree must be 2 through 12",
            ));
        }
        let mut tables = vec![Vec::new()];
        for i in 1..degree {
            let count = 1usize << i;
            let step = PI / (4.0 * count as f64);
            let mut angle = step;
            tables.push(
                (0..count)
                    .map(|_| {
                        let value = angle.cos() as f32;
                        angle += 2.0 * step;
                        value
                    })
                    .collect(),
            );
        }
        Ok(Self { tables })
    }
    pub fn inverse(&self, source: &[f32]) -> io::Result<Vec<f32>> {
        if source.len() < 4
            || !source.len().is_power_of_two()
            || source.len().ilog2() as usize > self.tables.len()
        {
            return Err(BinaryIo::invalid_input(
                "ERISA inverse DCT buffer does not match its degree",
            ));
        }
        Ok(self.inverse_inner(source))
    }
    fn inverse_inner(&self, source: &[f32]) -> Vec<f32> {
        let half = source.len() / 2;
        let degree = source.len().ilog2() as usize;
        let c = (PI / 4.0).cos() as f32;
        if source.len() == 4 {
            let a = source[0] + c * source[2];
            let b = source[0] - c * source[2];
            let x = self.tables[1][0] * source[1];
            let y = self.tables[1][1] * source[3];
            let e = x + y;
            let f = 2.0 * c * (x - y) - e;
            return vec![a + e, b + f, b - f, a - e];
        }
        let even: Vec<_> = source.iter().step_by(2).copied().collect();
        let even = self.inverse_inner(&even);
        let odd: Vec<_> = source
            .iter()
            .skip(1)
            .step_by(2)
            .zip(&self.tables[degree - 1])
            .map(|(&x, &c)| x * c)
            .collect();
        let mut odd = self.forward(&odd);
        for value in &mut odd {
            *value += *value;
        }
        for i in 1..half {
            odd[i] -= odd[i - 1];
        }
        let mut out = vec![0.0; source.len()];
        for i in 0..half {
            out[i] = even[i] + odd[i];
            out[source.len() - 1 - i] = even[i] - odd[i];
        }
        out
    }
    fn forward(&self, source: &[f32]) -> Vec<f32> {
        let half = source.len() / 2;
        let degree = source.len().ilog2() as usize;
        let c = (PI / 4.0).cos() as f32;
        if source.len() == 4 {
            let a = source[0] + source[3];
            let b = source[1] + source[2];
            let x = self.tables[1][0] * (source[0] - source[3]);
            let y = self.tables[1][1] * (source[1] - source[2]);
            let e = x + y;
            return vec![0.5 * (a + b), e, c * (a - b), 2.0 * c * (x - y) - e];
        }
        let even: Vec<_> = (0..half)
            .map(|i| source[i] + source[source.len() - 1 - i])
            .collect();
        let odd: Vec<_> = (0..half)
            .map(|i| (source[i] - source[source.len() - 1 - i]) * self.tables[degree - 1][i])
            .collect();
        let even = self.forward(&even);
        let mut odd = self.forward(&odd);
        for value in &mut odd {
            *value += *value;
        }
        for i in 1..half {
            odd[i] -= odd[i - 1];
        }
        let mut out = vec![0.0; source.len()];
        for i in 0..half {
            out[i * 2] = even[i];
            out[i * 2 + 1] = odd[i];
        }
        out
    }
}

pub fn revolve_parameters(count: usize) -> io::Result<Vec<(f32, f32)>> {
    if !(16..=4096).contains(&count) || !count.is_power_of_two() {
        return Err(BinaryIo::invalid_input(
            "ERISA revolve buffer does not match a supported LOT degree",
        ));
    }
    let k = PI / (count * 2) as f64;
    let mut result: Vec<(f32, f32)> = Vec::new();
    let mut step = 2;
    loop {
        let first = result.len();
        for i in 0..7 {
            let mut weight = 1.0;
            let mut angle = 0.0;
            for j in 0..i {
                angle += step as f64;
                let (sin, cos) = result[first + j];
                weight = weight * f64::from(sin) + f64::from(cos) * (angle * k).cos();
            }
            let angle = weight.atan2(((angle + step as f64) * k).cos());
            result.push((angle.sin() as f32, angle.cos() as f32));
        }
        step *= 8;
        if step >= count {
            break;
        }
    }
    Ok(result)
}

fn rotate(source: &mut [f32], k: usize, step: usize, parameter: (f32, f32)) {
    let (sin, cos) = parameter;
    let a = source[k];
    let b = source[k + step];
    source[k] = a * cos + b * sin;
    source[k + step] = b * cos - a * sin;
}
pub fn odd_givens_inverse(source: &mut [f32], params: &[(f32, f32)]) -> io::Result<()> {
    if source.len() < 16 || !source.len().is_power_of_two() || source.len() > 4096 {
        return Err(BinaryIo::invalid_input(
            "ERISA Givens buffer does not match a supported LOT degree",
        ));
    }
    let mut levels = 1;
    let mut width = 16;
    while width < source.len() {
        levels += 1;
        width *= 8;
    }
    if params.len() != levels * 7 {
        return Err(BinaryIo::invalid_input(
            "ERISA Givens parameter count differs from degree",
        ));
    }
    let limit = source.len() / 16;
    let mut index = 1;
    let mut step = 2;
    let mut count = limit;
    let mut parameter = 0;
    loop {
        parameter += 7;
        index += step * 7;
        step *= 8;
        if count <= 8 {
            break;
        }
        count /= 8;
    }
    for j in (0..count.saturating_sub(1)).rev() {
        rotate(source, index + step * j, step, params[parameter + j]);
    }
    while count <= limit {
        parameter -= 7;
        step /= 8;
        index -= step * 7;
        for i in 0..count {
            for j in (0..7).rev() {
                rotate(
                    source,
                    i * step * 8 + index + step * j,
                    step,
                    params[parameter + j],
                );
            }
        }
        count *= 8;
    }
    Ok(())
}

pub fn inverse_plot(source: &mut [f32]) -> io::Result<()> {
    if !source.len().is_multiple_of(2) {
        return Err(BinaryIo::invalid_input("ERISA PLOT needs pairs of samples"));
    }
    for pair in source.as_chunks_mut::<2>().0 {
        let a = pair[0];
        let b = pair[1];
        pair[0] = 0.5 * (a + b);
        pair[1] = 0.5 * (a - b);
    }
    Ok(())
}
pub fn inverse_lot(previous: &[f32], current: &[f32]) -> io::Result<Vec<f32>> {
    if previous.len() != current.len() || !current.len().is_multiple_of(2) {
        return Err(BinaryIo::invalid_input(
            "ERISA LOT buffers differ or lack sample pairs",
        ));
    }
    let mut out = vec![0.0; current.len()];
    for i in (0..current.len()).step_by(2) {
        out[i] = previous[i] + current[i + 1];
        out[i + 1] = previous[i] - current[i + 1];
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../../tests/compress/erisa/transform.rs"]
mod tests;
