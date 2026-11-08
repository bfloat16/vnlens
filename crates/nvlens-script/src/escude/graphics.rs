//! LSF and MOT structured animation resources, as declared by
//! misc/anime.h::LSF_FILE_HEADER/LSF_LAYER_INFO and load_anime_impl.
use super::*;
use crate::ir::{ArgName as A, Qualifier as Q};

fn fixed(r: &mut BinaryReader<'_>, name: A, size: usize) -> Result<Arg> {
    let at = r.position();
    let bytes = r.read_bytes(size)?;
    Ok(arg(
        name,
        at,
        size,
        text(bytes.split(|&b| b == 0).next().unwrap_or_default()),
    ))
}
fn u16_arg(r: &mut BinaryReader<'_>, name: A) -> Result<Arg> {
    let at = r.position();
    Ok(arg(
        name,
        at,
        2,
        Value::Unsigned(u64::from(r.read_u16_le()?)),
    ))
}
fn i32_arg(r: &mut BinaryReader<'_>, name: A) -> Result<Arg> {
    let at = r.position();
    Ok(arg(
        name,
        at,
        4,
        Value::Integer(i64::from(r.read_u32_le()? as i32)),
    ))
}

pub(super) fn lsf(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new_at(data, 4)?;
    let version = r.read_u16_le()?;
    if version != 2 {
        return Err(Error::Unsupported(format!("LSF revision {version}")));
    }
    let mut args = vec![
        arg(A::Signature, 0, 4, Value::Bytes(data[..4].to_vec())),
        arg(A::Version, 4, 2, Value::Unsigned(u64::from(version))),
        u16_arg(&mut r, A::Flags)?,
        u16_arg(&mut r, A::Id)?,
    ];
    let count = r.read_u16_le()?;
    args.push(arg(A::Count, 10, 2, Value::Unsigned(u64::from(count))));
    for role in [A::Width, A::Height, A::OriginX, A::OriginY] {
        args.push(i32_arg(&mut r, role)?);
    }
    let start = r.position();
    let mut layers = Vec::new();
    for index in 0..count {
        let at = r.position();
        let mut fields = vec![fixed(&mut r, A::Resource, 64)?, fixed(&mut r, A::Text, 64)?];
        for role in [
            A::RectLeft,
            A::RectTop,
            A::RectRight,
            A::RectBottom,
            A::OriginX,
            A::OriginY,
        ] {
            fields.push(i32_arg(&mut r, role)?);
        }
        for role in [A::Index, A::State, A::Mode, A::Opacity] {
            let at = r.position();
            fields.push(arg(role, at, 1, Value::Unsigned(u64::from(r.read_u8()?))));
        }
        for role in [A::Color, A::Value] {
            let at = r.position();
            fields.push(number(role, at, r.read_u32_le()?));
        }
        layers.push(arg(
            A::ValueAt(u64::from(index)),
            at,
            r.position() - at,
            Value::Group(fields),
        ));
    }
    args.push(arg(
        A::Resources,
        start,
        r.position() - start,
        Value::Group(layers),
    ));
    let mut out = script(data, "lsf/escude", u32::from(version));
    record(&mut out, 0, r.position(), Q::Layer, args);
    trailing(&mut out, &mut r)?;
    Ok(out)
}

pub(super) fn mot(data: &[u8]) -> Result<Script> {
    let version = if data.starts_with(b"mot\0") { 1 } else { 2 };
    let mut r = BinaryReader::new_at(data, 4)?;
    let bitmaps = r.read_u32_le()?;
    let patterns = r.read_u32_le()?;
    let code_size = r.read_u32_le()?;
    let mut out = script(data, "mot/escude", version);
    let mut args = vec![
        arg(A::Signature, 0, 4, Value::Bytes(data[..4].to_vec())),
        number(A::Count, 4, bitmaps),
        number(A::FrameCount, 8, patterns),
        number(A::ByteCount, 12, code_size),
    ];
    let start = r.position();
    let mut resources = Vec::new();
    for index in 0..bitmaps {
        let at = r.position();
        let fields = vec![
            fixed(&mut r, A::Resource, if version == 1 { 32 } else { 64 })?,
            u16_arg(&mut r, A::Mode)?,
        ];
        resources.push(arg(
            A::ValueAt(u64::from(index)),
            at,
            r.position() - at,
            Value::Group(fields),
        ));
    }
    args.push(arg(
        A::Resources,
        start,
        r.position() - start,
        Value::Group(resources),
    ));
    let start = r.position();
    let mut frames = Vec::new();
    for index in 0..patterns {
        let at = r.position();
        let mut fields = vec![u16_arg(&mut r, A::ResourceId)?];
        for role in [
            A::RectLeft,
            A::RectTop,
            A::RectRight,
            A::RectBottom,
            A::OriginX,
            A::OriginY,
        ] {
            fields.push(i32_arg(&mut r, role)?);
        }
        frames.push(arg(
            A::ValueAt(u64::from(index)),
            at,
            r.position() - at,
            Value::Group(fields),
        ));
    }
    args.push(arg(
        A::Frames,
        start,
        r.position() - start,
        Value::Group(frames),
    ));
    record(&mut out, 0, r.position(), Q::Animation, args);
    let start = r.position();
    let code = r.read_bytes(code_size as usize)?;
    super::motion::parse(&mut out, code, start)?;
    trailing(&mut out, &mut r)?;
    Ok(out)
}
fn trailing(out: &mut Script, r: &mut BinaryReader<'_>) -> Result<()> {
    if r.remaining() != 0 {
        let at = r.position();
        let bytes = r.read_bytes(r.remaining())?;
        record(
            out,
            at,
            bytes.len(),
            Q::Bytes,
            vec![arg(A::Data, at, bytes.len(), Value::Bytes(bytes.to_vec()))],
        );
    }
    Ok(())
}
