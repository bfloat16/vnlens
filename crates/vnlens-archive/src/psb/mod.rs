//! PSB archive registration. All shell, index, naming and resource processing
//! belongs to middleware; this adapter supplies engine-resolved parameters.
use std::sync::Arc;
use vnlens_core::{
    ArcView, Archive, ArchiveFormat, ArchiveOptions, Format, Result, register_archive,
};
use vnlens_io::ReadAt;
use vnlens_middleware::psb::PsbFile;

const SIGNATURES: &[u32] = &[0x0042_5350, 0x0066_646d, 0x0073_7a6d, 0x005a_5350];

#[derive(Debug, Default)]
struct PsbContainer;
impl Format for PsbContainer {
    fn tag(&self) -> &'static str {
        "psb"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "psb", "m", "mdf", "mzs", "psz", "pimg", "mmo", "emtbytes", "mtn", "dpak", "scn",
        ]
    }
    fn description(&self) -> &'static str {
        "PSB container and embedded resources"
    }
}
impl ArchiveFormat for PsbContainer {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        Ok(Box::new(PsbFile::open_configured(
            view.clone(),
            view.file_name(),
            options,
            None,
        )?))
    }
    fn open_source(
        &self,
        source: Arc<dyn ReadAt>,
        name: &str,
        options: &ArchiveOptions,
    ) -> Result<Option<Box<dyn Archive>>> {
        Ok(Some(Box::new(PsbFile::open_configured(
            source, name, options, None,
        )?)))
    }
}

register_archive!(PsbContainer);

#[cfg(test)]
#[path = "../../tests/psb/mod.rs"]
mod tests;
