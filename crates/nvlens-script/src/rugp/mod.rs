//! rUGP serialized script objects and their native class metadata.
mod animation;
mod fade;
pub use animation::{Animation, AnimationFrame, animation_index};
mod font;
mod objects;
mod parse;
mod structure;
mod vm;
pub mod wire;
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use nvlens_core::{ArchiveOptions, Format, ResourceResolver, Result};
use nvlens_io::BinaryReader;

const SIGNATURES: &[u32] = &[
    wire::OBJECT_SIGNATURE,
    wire::ENCRYPTED_SIGNATURE,
    wire::RIO_SIGNATURE,
];

/// Classes whose serialized fields may own external or embedded resources.
/// This is a lazy navigation hint, not proof that a particular object has children.
#[must_use]
pub fn has_references(name: &str) -> bool {
    matches!(
        name,
        "CRsi"
            | "CRsa"
            | "CRmt"
            | "CPmBgm"
            | "CPmEffect"
            | "CProcessOcean"
            | "CBoxOcean"
            | "CrelicUnitedGameProject"
            | "CVmVarObj"
            | "CCharVoiceOcean"
            | "CBox"
            | "CImgBox"
            | "CImgAreaBox"
            | "CFrameBuffer"
            | "CCharBox"
            | "CCharBox2"
            | "CParseBgBox"
            | "CMessBox"
            | "CMsgSelBox"
            | "CFloatingRedirectMessBox"
            | "CVideoSeq"
            | "CTextStaffrollSeq"
            | "CFlashLayerEffect"
            | "CLayerSimpleFlush"
            | "CMenuAvatar"
            | "CRimp"
            | "CRbx"
            | "CBg2d"
            | "CLayoutTextImg"
            | "CPostureMoment"
            | "CSinpleSequence"
            | "CMoveAcsOngen"
            | "CDcAgesModelQsT"
            | "CCommandRef"
            | "CImgSel"
            | "CBg2dLayerParam"
            | "CBg2dLayerRip007Image"
            | "Cr6Ti"
            | "Cr6Tix"
            | "CRip007"
            | "CRip008"
            | "CFontAttr"
            | "CS5RFont"
    ) || fade::fields(name, 0).is_some()
}

#[must_use]
pub fn object_name(object: &wire::Object) -> String {
    object
        .name
        .clone()
        .unwrap_or_else(|| format!("{:08X}.{}", object.offset, object.class.name))
}

#[derive(Debug, Clone)]
pub struct Embedded {
    pub class: wire::Class,
    pub span: crate::ir::Span,
    pub raw: Vec<u8>,
    pub data: Vec<u8>,
}

/// External references and self-contained inline resources from one object.
pub fn contents(
    data: &[u8],
    options: &ArchiveOptions,
) -> Result<(Vec<wire::Object>, Vec<Embedded>)> {
    let parsed = parse::parse(data, options)?;
    Ok((parsed.objects, parsed.embedded))
}

#[derive(Debug, Default)]
struct Rugp;
impl Format for Rugp {
    fn tag(&self) -> &'static str {
        "object/rugp"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["crsa", "cprocessocean", "cstdb"]
    }
    fn description(&self) -> &'static str {
        "rUGP serialized scripts and objects"
    }
}
impl ScriptFormat for Rugp {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        self.disassemble_with_options(data, None, &ArchiveOptions::default())
    }
    fn disassemble_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        options: &ArchiveOptions,
    ) -> Result<Option<Script>> {
        if data.len() < 4 || !SIGNATURES.contains(&BinaryReader::u32_le(data)) {
            return Ok(None);
        }
        let mut reader = wire::Reader::new(data, false);
        let (signature, _, _, class) = reader.header()?;
        if signature == wire::ENCRYPTED_SIGNATURE {
            reader.children()?;
            if reader.bytes.remaining() == 0 {
                return Ok(Some(parse::parse(data, options)?.script));
            }
        }
        if matches!(
            class.name.as_str(),
            "Cr6Ti"
                | "Cr6Tix"
                | "CRmti"
                | "CSbm"
                | "CS5i"
                | "CIcon"
                | "CWaveAudio"
                | "CrelicHicompAudio"
                | "COptimizedObs"
                | "COptimizedObsforR"
        ) {
            return Ok(None);
        }
        Ok(Some(parse::parse(data, options)?.script))
    }
}
nvlens_core::inventory::submit! {ScriptRegistration(||Box::new(Rugp))}
