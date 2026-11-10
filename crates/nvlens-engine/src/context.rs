//! One game's physical files, embedded files and restored executable sections.
use nvlens_core::Result;
use nvlens_io::{ArcView, FileSystem, pe::PeImage};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Debug)]
pub(crate) struct Context {
    pub root: PathBuf,
    pub files: Arc<FileSystem>,
    pub sections: BTreeMap<PathBuf, Vec<nvlens_unpack::enigma::Section>>,
}
impl Context {
    pub fn image<'a>(&self, view: &'a ArcView, cancel: &AtomicBool) -> Result<Option<PeImage<'a>>> {
        let Some(mut image) = PeImage::parse(view.slice(0, view.len())?)? else {
            return Ok(None);
        };
        if let Some(sections) = self.sections.get(view.path()) {
            for section in sections {
                image.restore_section(
                    section.rva,
                    section.bytes.clone(),
                    section.characteristics,
                )?;
            }
        }
        nvlens_unpack::steamstub::unpack(&mut image, cancel)?;
        Ok(Some(image))
    }
}
