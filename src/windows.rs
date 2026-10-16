mod device;
mod transport;
pub(crate) use device::Backend;
pub use transport::Writer;

use crate::Result;
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn check(ok: i32) -> Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct Handle(HANDLE);
impl Handle {
    fn new(raw: HANDLE) -> Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // The handle is uniquely owned and was validated by Handle::new.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
