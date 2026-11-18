//! Static geometry in the source coordinate system. Original model bytes and
//! material records remain available independently of a host's rendering mode.
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct Vertex {
    pub position: [f32; 3],
    pub normal: Option<[f32; 3]>,
    pub color: [f32; 4],
    pub uv: Option<[f32; 2]>,
}

#[derive(Clone, Debug)]
pub struct Mesh {
    pub indices: Vec<u32>,
    pub material: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct TextureBinding {
    pub parameter_hash: u32,
    pub texture: u16,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Material {
    pub name_hash: u32,
    pub shader: u32,
    pub textures: Vec<TextureBinding>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Model {
    pub vertices: Vec<Vertex>,
    pub meshes: Vec<Mesh>,
    pub materials: Vec<Material>,
    pub bounds: [[f32; 3]; 2],
    pub source: Arc<[u8]>,
}
