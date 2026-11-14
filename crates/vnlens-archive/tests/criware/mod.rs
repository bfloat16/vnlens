use super::*;
use vnlens_core::{ArchiveRoute, Catalog};

#[test]
fn each_cri_container_is_registered_and_never_falls_back() {
    let catalog = Catalog::load();
    for tag in ["cri/cpk", "cri/acb", "cri/awb", "cri/utf"] {
        let source: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(vec![0; 32]));
        let result = catalog.open_source(source, "bad", &ArchiveRoute::new(tag));
        assert!(result.is_err());
        assert!(!matches!(result, Err(vnlens_core::Error::Unsupported(_))));
    }
}
