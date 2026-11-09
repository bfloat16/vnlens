//! GPUI 0.2.2's Windows zoom() only calls SW_MAXIMIZE. Restore the existing
//! window through its borrowed native handle until GPUI exposes this action.
#![allow(unsafe_code)]

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::UI::WindowsAndMessaging::{SW_RESTORE, ShowWindowAsync};

pub(super) fn restore(window: &impl HasWindowHandle) -> anyhow::Result<()> {
    let handle = HasWindowHandle::window_handle(window)
        .map_err(|error| anyhow::anyhow!("Cannot obtain native window handle: {error}"))?;
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        anyhow::bail!("GPUI window did not provide a Win32 handle");
    };
    // SAFETY: The handle is borrowed from the live GPUI window on its event
    // thread. ShowWindowAsync accepts an opaque HWND and a fixed show command;
    // it does not dereference Rust memory or take ownership of the window.
    if unsafe { ShowWindowAsync(handle.hwnd.get() as _, SW_RESTORE) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
