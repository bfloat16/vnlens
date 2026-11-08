//! Lua chunk headers copied and adapted from unluac_rs codec/classic.rs and
//! codec/modern.rs. Numeric sentinels determine byte order and storage widths.
use super::super::{
    chunk::{Header, Layout},
    corrupt,
};
use nvlens_core::{Error, Result};
use nvlens_io::{BinaryReader, Endian};

fn modern(r: &mut BinaryReader<'_>, version: u8) -> Result<Header> {
    if r.read_u8()? != 0 || r.read_bytes(6)? != b"\x19\x93\r\n\x1a\n" {
        return Err(corrupt(r.position(), "Invalid modern Lua header"));
    }
    let mut integer_size = 4;
    let mut size_t_size = 8;
    let mut endian = Endian::Little;
    if version == 0x53 {
        integer_size = width(r, "integer", 1..=8)?;
        size_t_size = width(r, "size_t", 1..=8)?;
    } else if version == 0x55 {
        integer_size = width(r, "integer", 2..=8)?;
        endian = test_integer(r, integer_size, -0x5678)?;
    }
    let instruction_size = width(r, "instruction", 4..=4)?;
    if version == 0x55 && test_integer(r, 4, 0x12345678)? != endian {
        return Err(corrupt(
            r.position(),
            "Inconsistent Lua instruction endianness",
        ));
    }
    let lua_integer_size = width(r, "Lua integer", 2..=8)?;
    if version == 0x55 && test_integer(r, lua_integer_size, -0x5678)? != endian {
        return Err(corrupt(r.position(), "Inconsistent Lua integer endianness"));
    }
    let number_size = width(r, "number", 4..=8)?;
    if !matches!(number_size, 4 | 8) {
        return Err(corrupt(r.position(), "Lua number width must be 4 or 8"));
    }
    if version != 0x55 {
        endian = test_integer(r, lua_integer_size, 0x5678)?;
    }
    let probe = r.read_compact_u64(number_size, endian)?;
    let number = if version == 0x55 {
        -370.5_f64
    } else {
        370.5_f64
    };
    let expected = if number_size == 4 {
        u64::from((number as f32).to_bits())
    } else {
        number.to_bits()
    };
    if probe != expected {
        return Err(corrupt(r.position(), "Invalid Lua float probe"));
    }
    Ok(Header {
        version,
        endian,
        integer_size,
        size_t_size,
        instruction_size,
        number_size,
        number_integral: false,
        lua_integer_size,
        main_upvalues: r.read_u8()?,
        lua50_layout: None,
    })
}

fn test_integer(r: &mut BinaryReader<'_>, size: u8, expected: i64) -> Result<Endian> {
    let bytes = r.read_bytes(usize::from(size))?;
    for endian in [Endian::Little, Endian::Big] {
        if BinaryReader::new(bytes).read_compact_i64(size, endian)? == expected {
            return Ok(endian);
        }
    }
    Err(corrupt(r.position(), "Invalid Lua integer probe"))
}

fn width(r: &mut BinaryReader<'_>, name: &str, range: std::ops::RangeInclusive<u8>) -> Result<u8> {
    let value = r.read_u8()?;
    if !range.contains(&value) {
        return Err(corrupt(
            r.position() - 1,
            format!("Unsupported Lua {name} width {value}"),
        ));
    }
    Ok(value)
}

pub(super) fn read(r: &mut BinaryReader<'_>) -> Result<Header> {
    if r.read_bytes(4)? != b"\x1bLua" {
        return Err(Error::InvalidFormat);
    }
    let version = r.read_u8()?;
    match version {
        0x50..=0x52 => classic(r, version),
        0x53..=0x55 => modern(r, version),
        _ => Err(Error::Unsupported(format!("Lua version {version:#x}"))),
    }
}
fn classic(r: &mut BinaryReader<'_>, version: u8) -> Result<Header> {
    let format = if version == 0x50 { 0 } else { r.read_u8()? };
    if format != 0 {
        return Err(corrupt(r.position() - 1, "nonstandard Lua format"));
    }
    let endianness = match r.read_u8()? {
        0 => Endian::Big,
        1 => Endian::Little,
        _ => return Err(corrupt(r.position() - 1, "endianness must be 0 or 1")),
    };
    let integer_size = width(r, "integer", 1..=8)?;
    let size_t_size = width(r, "size_t", 1..=8)?;
    let instruction_size = width(r, "instruction", 4..=8)?;
    let supported_instruction = instruction_size == 4 || (version == 0x50 && instruction_size == 8);
    if !supported_instruction {
        return Err(corrupt(
            r.position() - 1,
            "unsupported instruction storage width",
        ));
    }
    let lua50_layout = if version == 0x50 {
        let layout = Layout {
            opcode: width(r, "opcode bits", 1..=8)?,
            a: width(r, "A bits", 1..=31)?,
            b: width(r, "B bits", 1..=30)?,
            c: width(r, "C bits", 1..=30)?,
        };
        if u32::from(layout.opcode)
            + u32::from(layout.a)
            + u32::from(layout.b)
            + u32::from(layout.c)
            != 32
        {
            return Err(corrupt(
                r.position(),
                "instruction fields must total 32 bits",
            ));
        }
        Some(layout)
    } else {
        None
    };
    let number_size = r.read_u8()?;
    if number_size != 4 && number_size != 8 {
        return Err(corrupt(r.position() - 1, "number width must be 4 or 8"));
    }
    let number_integral = if version == 0x50 {
        let bits = r.read_compact_u64(number_size, endianness)?;
        let test = 31415926.535897933_f64;
        if (number_size == 8 && bits == test.to_bits())
            || (number_size == 4 && bits == u64::from((test as f32).to_bits()))
        {
            false
        } else if bits == 31415926 {
            true
        } else {
            return Err(corrupt(r.position(), "unrecognized Lua 5.0 number test"));
        }
    } else {
        match r.read_u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(corrupt(
                    r.position() - 1,
                    "number integrality must be 0 or 1",
                ));
            }
        }
    };
    if version == 0x52 && r.read_bytes(6)? != b"\x19\x93\r\n\x1a\n" {
        return Err(corrupt(r.position() - 6, "invalid Lua 5.2 tail signature"));
    }
    Ok(Header {
        version,
        endian: endianness,
        integer_size,
        size_t_size,
        instruction_size,
        number_size,
        number_integral,
        lua50_layout,
        lua_integer_size: number_size,
        main_upvalues: 0,
    })
}
