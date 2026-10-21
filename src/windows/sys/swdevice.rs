use super::wide;
use crate::Result;
use std::{io, mem::size_of, ptr, sync::mpsc, time::Duration};
use windows_sys::{Win32::Devices::Enumeration::Pnp::*, core::GUID};

struct Callback {
    sender: mpsc::Sender<(i32, String)>,
}

/// A software device that exists while this handle is open.
pub struct SoftwareDevice {
    handle: HSWDEVICE,
    id: String,
    _callback: Box<Callback>,
}
impl Drop for SoftwareDevice {
    fn drop(&mut self) {
        unsafe {
            // SwDeviceClose joins callbacks before _callback is freed:
            // https://learn.microsoft.com/windows/win32/api/swdevice/nf-swdevice-swdeviceclose
            SwDeviceClose(self.handle);
        }
    }
}

unsafe extern "system" fn created(
    _device: HSWDEVICE,
    result: i32,
    context: *const std::ffi::c_void,
    id: *const u16,
) {
    // SoftwareDevice keeps the boxed context alive until SwDeviceClose joins us.
    let callback = unsafe { &*context.cast::<Callback>() };
    let mut len = 0;
    if !id.is_null() {
        // Windows supplies a NUL-terminated ID valid for this callback.
        unsafe {
            while *id.add(len) != 0 {
                len += 1;
            }
        }
    }
    let id = if len == 0 {
        String::new()
    } else {
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(id, len) })
    };
    let _ = callback.sender.send((result, id));
}

/// What SwDeviceCreate needs to know about a new device.
pub struct Description<'a> {
    pub enumerator: &'a str,
    pub parent: &'a str,
    pub instance: &'a str,
    /// Each ID followed by a NUL; the multi-string's final NUL is added.
    pub hardware_ids: &'a str,
    /// Each ID followed by a NUL; the multi-string's final NUL is added.
    pub compatible_ids: &'a str,
    pub container: GUID,
    pub description: &'a str,
}

impl SoftwareDevice {
    /// Creates the device and waits for Windows to report its instance ID.
    pub fn create(device: &Description<'_>) -> Result<Self> {
        let instance = wide(device.instance);
        let hardware = wide(device.hardware_ids);
        let compatible = wide(device.compatible_ids);
        let description = wide(device.description);
        let info = SW_DEVICE_CREATE_INFO {
            cbSize: size_of::<SW_DEVICE_CREATE_INFO>() as u32,
            pszInstanceId: instance.as_ptr(),
            pszzHardwareIds: hardware.as_ptr(),
            pszzCompatibleIds: compatible.as_ptr(),
            pContainerId: &device.container,
            CapabilityFlags: (SWDeviceCapabilitiesDriverRequired
                | SWDeviceCapabilitiesSilentInstall
                | SWDeviceCapabilitiesNoDisplayInUI) as u32,
            pszDeviceDescription: description.as_ptr(),
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        let context = Box::new(Callback { sender: tx });
        let mut handle = ptr::null_mut();
        // SwDeviceCreate copies create-info; the boxed callback address is stable.
        let hr = unsafe {
            SwDeviceCreate(
                wide(device.enumerator).as_ptr(),
                wide(device.parent).as_ptr(),
                &info,
                0,
                ptr::null(),
                Some(created),
                (&*context as *const Callback).cast(),
                &mut handle,
            )
        };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "SwDeviceCreate HRESULT {hr:#010x}"
            )));
        }
        let mut device = SoftwareDevice {
            handle,
            id: String::new(),
            _callback: context,
        };
        let (hr, id) = rx
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SwDeviceCreate callback"))?;
        if hr < 0 {
            return Err(io::Error::other(format!(
                "SwDeviceCreate callback HRESULT {hr:#010x}"
            )));
        }
        if id.is_empty() {
            return Err(io::Error::other(
                "SwDeviceCreate returned an empty device ID",
            ));
        }
        device.id = id;
        Ok(device)
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_callback_keeps_context_alive() {
        let (tx, rx) = mpsc::channel();
        let context = Box::new(Callback { sender: tx });
        assert!(rx.recv_timeout(Duration::from_millis(1)).is_err());
        unsafe {
            created(
                ptr::null_mut(),
                0,
                (&*context as *const Callback).cast(),
                ptr::null(),
            );
        }
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap().0, 0);
    }

    #[test]
    fn callback_preserves_actual_instance_id() {
        let (tx, rx) = mpsc::channel::<(i32, String)>();
        let context = Box::new(Callback { sender: tx });
        let id = wide(r"SWD\HIDMAESTRO\decorated-instance");
        unsafe {
            created(
                ptr::null_mut(),
                0,
                (&*context as *const Callback).cast(),
                id.as_ptr(),
            );
        }
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap().1,
            r"SWD\HIDMAESTRO\decorated-instance"
        );
    }
}
