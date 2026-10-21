use super::{DevNode, check, wide};
use crate::Result;
use std::{io, marker::PhantomData, mem::size_of, path::Path, ptr};
use windows_sys::{Win32::Devices::DeviceAndDriverInstallation::*, core::GUID};

/// A SetupAPI device information set, used from one thread.
pub struct DeviceSet(HDEVINFO, PhantomData<*const ()>);

/// An element of the set that opened or created it.
///
/// SP_DEVINFO_DATA points into the set, so an element borrows its set and is
/// only ever passed back to it.
pub struct DeviceInfo<'set> {
    set: &'set DeviceSet,
    data: SP_DEVINFO_DATA,
}

fn info() -> SP_DEVINFO_DATA {
    SP_DEVINFO_DATA {
        cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    }
}

impl DeviceSet {
    pub fn new() -> Result<Self> {
        let h = unsafe { SetupDiCreateDeviceInfoList(ptr::null(), ptr::null_mut()) };
        if h == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(h, PhantomData))
        }
    }

    pub fn open(&self, id: &str) -> Result<DeviceInfo<'_>> {
        let mut data = info();
        check(unsafe {
            SetupDiOpenDeviceInfoW(self.0, wide(id).as_ptr(), ptr::null_mut(), 0, &mut data)
        })?;
        Ok(DeviceInfo { set: self, data })
    }

    pub fn create(&self, id: &str, class: &GUID, description: &str) -> Result<DeviceInfo<'_>> {
        let mut data = info();
        check(unsafe {
            SetupDiCreateDeviceInfoW(
                self.0,
                wide(id).as_ptr(),
                class,
                wide(description).as_ptr(),
                ptr::null_mut(),
                0,
                &mut data,
            )
        })?;
        Ok(DeviceInfo { set: self, data })
    }
}
impl Drop for DeviceSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

impl DeviceInfo<'_> {
    pub fn node(&self) -> DevNode {
        DevNode(self.data.DevInst)
    }

    /// Reads a registry property of up to 1024 bytes as its type and bytes.
    pub fn property(&self, property: u32) -> Result<(u32, Vec<u8>)> {
        let mut buffer = vec![0u8; 1024];
        let mut size = 0;
        let mut kind = 0;
        check(unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.set.0,
                &self.data,
                property,
                &mut kind,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut size,
            )
        })?;
        buffer.truncate(size as usize);
        Ok((kind, buffer))
    }

    pub fn set_property(&mut self, property: u32, bytes: &[u8]) -> Result<()> {
        check(unsafe {
            SetupDiSetDeviceRegistryPropertyW(
                self.set.0,
                &mut self.data,
                property,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        })
    }

    pub fn call_class_installer(&self, function: u32) -> Result<()> {
        check(unsafe { SetupDiCallClassInstaller(function, self.set.0, &self.data) })
    }

    /// Installs the first compatible driver of one INF quietly; true when
    /// Windows needs a restart to start the device.
    pub fn install(&mut self, inf: &Path) -> Result<bool> {
        let set = self.set.0;
        let mut params = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        check(unsafe { SetupDiGetDeviceInstallParamsW(set, &self.data, &mut params) })?;
        params.Flags |= DI_ENUMSINGLEINF | DI_QUIETINSTALL;
        let path = wide(&inf.to_string_lossy());
        if path.len() > params.DriverPath.len() {
            return Err(io::Error::other("INF path is too long"));
        }
        params.DriverPath[..path.len()].copy_from_slice(&path);
        check(unsafe { SetupDiSetDeviceInstallParamsW(set, &self.data, &params) })?;
        check(unsafe { SetupDiBuildDriverInfoList(set, &mut self.data, SPDIT_COMPATDRIVER) })?;
        let mut driver = SP_DRVINFO_DATA_V2_W {
            cbSize: size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
            ..Default::default()
        };
        let mut reboot = 0;
        let mut rc =
            unsafe { SetupDiEnumDriverInfoW(set, &self.data, SPDIT_COMPATDRIVER, 0, &mut driver) };
        if rc != 0 {
            rc = unsafe {
                DiInstallDevice(ptr::null_mut(), set, &self.data, &driver, 0, &mut reboot)
            };
        }
        let error = io::Error::last_os_error();
        unsafe {
            SetupDiDestroyDriverInfoList(set, &self.data, SPDIT_COMPATDRIVER);
        }
        if rc == 0 {
            return Err(error);
        }
        Ok(reboot != 0)
    }
}
