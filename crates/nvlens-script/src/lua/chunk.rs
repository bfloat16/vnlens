//! Private Lua binary model, reduced from unluac_rs's chunk structures.
//! Functions use flat indices so parsing, decoding and dropping a deeply
//! nested chunk do not recurse. Uninterpreted debug data stays in the source.

use nvlens_io::Endian;
use std::ops::Range;

pub(super) struct Chunk<'a> {
    pub header: Header,
    pub functions: Vec<Function<'a>>,
}

pub(super) struct Header {
    pub version: u8,
    pub endian: Endian,
    pub integer_size: u8,
    pub size_t_size: u8,
    pub instruction_size: u8,
    pub number_size: u8,
    pub number_integral: bool,
    pub lua_integer_size: u8,
    pub main_upvalues: u8,
    pub lua50_layout: Option<Layout>,
}

#[derive(Clone, Copy)]
pub(super) struct Layout {
    pub opcode: u8,
    pub a: u8,
    pub b: u8,
    pub c: u8,
}

#[derive(Default)]
pub(super) struct Function<'a> {
    pub parent: Option<(usize, usize)>,
    pub source: Option<&'a [u8]>,
    pub line_defined: u32,
    pub num_params: u8,
    pub vararg_flags: u8,
    pub max_stack_size: u8,
    pub num_upvalues: u8,
    pub code: Vec<u32>,
    pub code_range: Range<usize>,
    pub constants: Vec<Constant<'a>>,
    pub children: Vec<usize>,
    pub line_info: Vec<u32>,
    pub absolute_lines: Vec<(u32, u32)>,
}

pub(super) enum Constant<'a> {
    Nil,
    Boolean(bool),
    Integer(i64),
    Float32(u32),
    Float64(u64),
    String(Option<&'a [u8]>),
}
