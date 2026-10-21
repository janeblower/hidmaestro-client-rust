//! Safe wrappers over the Win32 calls this client makes; the only module
//! allowed to use `unsafe`.

mod devnode;
mod kernel;
mod registry;
mod setup;
mod swdevice;

pub(super) use devnode::{DevNode, interface};
pub(super) use kernel::*;
pub(super) use registry::Key;
pub(super) use setup::DeviceSet;
pub(super) use swdevice::{Description, SoftwareDevice};

use crate::Result;
use std::io;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;

pub(super) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The UTF-16LE bytes of `value` with its terminator, as registry strings hold them.
pub(super) fn utf16_bytes(value: &str) -> Vec<u8> {
    wide(value).into_iter().flat_map(u16::to_le_bytes).collect()
}

fn check(ok: i32) -> Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn status(code: u32) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
