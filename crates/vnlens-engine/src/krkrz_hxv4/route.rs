//! KiriKiri Z Hxv4 shares KiriKiri's resource and XP3 archive routing.
pub(super) const ROUTER: crate::routing::Router = crate::krkr::route::ROUTER;

#[cfg(test)]
#[path = "../../tests/krkrz_hxv4/route.rs"]
mod tests;
