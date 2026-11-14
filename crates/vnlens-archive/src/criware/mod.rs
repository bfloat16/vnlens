//! Directed adapters for CRIWARE's CPK archives, ACB cue sheets and AWB banks.
//! All shared framing, tables and payload transforms are owned by middleware.
use std::{any::Any, borrow::Cow, sync::Arc};
use vnlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Format, Result};
use vnlens_io::{ArcView, ReadAt};
use vnlens_middleware::criware::{
    acb::{Bank, TableKind},
    awb::Awb,
    cpk::Cpk,
};

#[derive(Debug)]
enum Mounted {
    Cpk(Arc<Cpk>),
    Awb(Arc<Awb>),
    Bank(Arc<Bank>),
}
impl Archive for Mounted {
    fn entries(&self) -> &[Entry] {
        match self {
            Self::Cpk(v) => &v.entries,
            Self::Awb(v) => &v.entries,
            Self::Bank(v) => &v.entries,
        }
    }
    fn metadata(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        Some(match self {
            Self::Cpk(v) => v.clone(),
            Self::Awb(v) => v.clone(),
            Self::Bank(v) => v.clone(),
        })
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        match self {
            Self::Cpk(v) => v.read(entry),
            Self::Awb(v) => v.read(entry),
            Self::Bank(v) => v.read(entry),
        }
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        match self {
            Self::Cpk(v) => v.read_raw(entry),
            Self::Awb(v) => v.read(entry),
            Self::Bank(v) => v.read_raw(entry),
        }
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        match self {
            Self::Cpk(v) => v.source(entry),
            Self::Awb(v) => v.source(entry),
            Self::Bank(v) => v.source(entry),
        }
        .map(Some)
    }
}

macro_rules! register_container {
    ($ty:ident, $tag:literal, $signatures:expr, $extensions:expr, $description:literal, $open:expr) => {
        #[derive(Debug, Default)]
        struct $ty;
        impl Format for $ty {
            fn tag(&self) -> &'static str {
                $tag
            }
            fn signatures(&self) -> &'static [u32] {
                $signatures
            }
            fn extensions(&self) -> &'static [&'static str] {
                $extensions
            }
            fn description(&self) -> &'static str {
                $description
            }
        }
        impl ArchiveFormat for $ty {
            fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
                Ok(Box::new(($open)(view.clone())?))
            }
            fn open_source(
                &self,
                source: Arc<dyn ReadAt>,
                _: &str,
                _: &ArchiveOptions,
            ) -> Result<Option<Box<dyn Archive>>> {
                Ok(Some(Box::new(($open)(source)?)))
            }
        }
        vnlens_core::register_archive!($ty);
    };
}
register_container!(
    CpkFormat,
    "cri/cpk",
    &[0x204b5043],
    &["cpk", "pck"],
    "CRIWARE CPK archive",
    |source| Cpk::open(source).map(|v| Mounted::Cpk(Arc::new(v)))
);
register_container!(
    AwbFormat,
    "cri/awb",
    &[0x32534641],
    &["awb", "afs2"],
    "CRIWARE AWB waveform bank",
    |source| Awb::open(source).map(|v| Mounted::Awb(Arc::new(v)))
);
register_container!(
    AcbFormat,
    "cri/acb",
    &[0x46545540],
    &["acb"],
    "CRIWARE ACB cue sheet",
    |source| Bank::open(source, TableKind::Acb).map(|v| Mounted::Bank(Arc::new(v)))
);
register_container!(
    UtfFormat,
    "cri/utf",
    &[0x46545540, 0xf5f39e1f],
    &["utf"],
    "CRIWARE UTF table members",
    |source| Bank::open(source, TableKind::Utf).map(|v| Mounted::Bank(Arc::new(v)))
);

#[cfg(test)]
#[path = "../../tests/criware/mod.rs"]
mod tests;
