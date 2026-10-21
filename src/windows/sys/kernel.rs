use super::{check, wide};
use crate::Result;
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::atomic::{AtomicI32, AtomicU8, AtomicU16, AtomicU32, AtomicU64},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, GetTokenInformation,
        SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_OUTBOUND},
    System::{
        Memory::*,
        Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS},
        Threading::*,
    },
    UI::Input::XboxController::{XINPUT_STATE, XInputGetState},
};

/// Takes ownership of a handle a Win32 call just returned, failing on its error values.
fn owned(raw: HANDLE) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        // The call returned a fresh handle that nothing else owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}

/// Owns a handle to a named object, or `None` when no object has that name.
fn open_named(raw: HANDLE) -> Result<Option<OwnedHandle>> {
    match owned(raw) {
        Ok(handle) => Ok(Some(handle)),
        Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A security descriptor for the named objects this client creates.
pub struct Security(*mut std::ffi::c_void);
impl Security {
    pub fn new(sddl: &str) -> Result<Self> {
        let mut sd = ptr::null_mut();
        // Windows allocates sd; Security releases it with LocalFree.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut sd,
                ptr::null_mut(),
            )
        })?;
        Ok(Self(sd))
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

/// Calls f with attributes naming `security`, or with null for the default.
fn with_attributes<T>(
    security: Option<&Security>,
    f: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T,
) -> T {
    let sa = security.map(|s| SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: s.0,
        bInheritHandle: 0,
    });
    f(sa.as_ref().map_or(ptr::null(), |sa| sa))
}

/// Waits up to `ms` for the handle; false on timeout.
pub fn wait(handle: BorrowedHandle<'_>, ms: u32) -> Result<bool> {
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        u32::MAX => Err(io::Error::last_os_error()),
        rc => Err(io::Error::other(format!("wait returned {rc:#x}"))),
    }
}

/// Duplicates a handle within this process with the given access.
#[cfg(test)]
pub fn duplicate(handle: BorrowedHandle<'_>, access: u32) -> Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::DuplicateHandle;
    let mut target = ptr::null_mut();
    // The source is borrowed for the call; target receives a new handle.
    check(unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw_handle(),
            GetCurrentProcess(),
            &mut target,
            access,
            0,
            0,
        )
    })?;
    owned(target)
}

pub struct Event(OwnedHandle);
impl Event {
    /// Creates or opens a named event; true when it already existed.
    pub fn create(name: &str, security: Option<&Security>, manual: bool) -> Result<(Self, bool)> {
        let name = wide(name);
        // Attributes and name outlive the call; the error code is read right after it.
        let (handle, existed) = with_attributes(security, |sa| unsafe {
            let handle = CreateEventW(sa, manual.into(), 0, name.as_ptr());
            (handle, GetLastError() == ERROR_ALREADY_EXISTS)
        });
        Ok((Self(owned(handle)?), existed))
    }

    pub fn open(name: &str, access: u32) -> Result<Option<Self>> {
        let name = wide(name);
        Ok(open_named(unsafe { OpenEventW(access, 0, name.as_ptr()) })?.map(Self))
    }

    pub fn set(&self) -> Result<()> {
        check(unsafe { SetEvent(self.0.as_raw_handle()) })
    }

    pub fn reset(&self) -> Result<()> {
        check(unsafe { ResetEvent(self.0.as_raw_handle()) })
    }

    pub fn wait(&self, ms: u32) -> Result<bool> {
        wait(self.handle(), ms)
    }

    pub fn handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}
impl From<OwnedHandle> for Event {
    fn from(handle: OwnedHandle) -> Self {
        Self(handle)
    }
}

/// Integers that the drivers and other processes may access concurrently.
///
/// # Safety
/// Implementors must be atomics, since `Mapping::at` hands out shared
/// references into memory that other processes write.
pub unsafe trait Shared {}
unsafe impl Shared for AtomicU8 {}
unsafe impl Shared for AtomicU16 {}
unsafe impl Shared for AtomicI32 {}
unsafe impl Shared for AtomicU32 {}
unsafe impl Shared for AtomicU64 {}

/// A read-write view of a section, accessed only through atomics.
pub struct Mapping {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    size: usize,
    handle: OwnedHandle,
}

// The view is only reached through atomics, so sharing it across threads is
// no different from sharing it with the other processes that map it.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    pub fn from_handle(handle: OwnedHandle, size: u32) -> Result<Self> {
        // A returned view maps size writable bytes, possibly as the zeroed
        // tail of a smaller section's last page; the owned section handle
        // stays live until the view is unmapped.
        let view = unsafe {
            MapViewOfFile(
                handle.as_raw_handle(),
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                size as usize,
            )
        };
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            view,
            size: size as usize,
            handle,
        })
    }

    /// Creates a pagefile-backed section, or with `reuse` opens an existing
    /// one; true when it already existed.
    pub fn create(
        name: &str,
        size: u32,
        security: Option<&Security>,
        reuse: bool,
    ) -> Result<(Self, bool)> {
        let path = name;
        let name = wide(name);
        // Attributes and name outlive the call; the error code is read right after it.
        let (handle, existed) = with_attributes(security, |sa| unsafe {
            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                sa,
                PAGE_READWRITE,
                0,
                size,
                name.as_ptr(),
            );
            (handle, GetLastError() == ERROR_ALREADY_EXISTS)
        });
        let handle = owned(handle)?;
        if existed && !reuse {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                path.to_owned(),
            ));
        }
        Ok((Self::from_handle(handle, size)?, existed))
    }

    /// Opens an existing named section for reading.
    pub fn open(name: &str) -> Result<Option<OwnedHandle>> {
        let name = wide(name);
        open_named(unsafe { OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr()) })
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }

    /// Views the shared integer at offset; panics if it is out of bounds or misaligned.
    pub fn at<T: Shared>(&self, offset: usize) -> &T {
        assert!(offset <= self.size && size_of::<T>() <= self.size - offset);
        let ptr = self
            .view
            .Value
            .cast::<u8>()
            .wrapping_add(offset)
            .cast::<T>();
        assert!(ptr.is_aligned());
        // The view lives as long as self and the bounds are checked. Other
        // mappings of the section change it behind our back, which atomics
        // permit; no reference to plain data in the view is ever created.
        unsafe { &*ptr }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // References from at borrow self, so none outlive the view.
        unsafe {
            UnmapViewOfFile(self.view);
        }
    }
}

/// Creates or opens a named mutex without acquiring it; true when it already existed.
pub fn create_mutex(name: &str, security: Option<&Security>) -> Result<(OwnedHandle, bool)> {
    let name = wide(name);
    // Attributes and name outlive the call; the error code is read right after it.
    let (handle, existed) = with_attributes(security, |sa| unsafe {
        let handle = CreateMutexW(sa, 0, name.as_ptr());
        (handle, GetLastError() == ERROR_ALREADY_EXISTS)
    });
    Ok((owned(handle)?, existed))
}

/// Creates an outbound instance of a local named pipe with two instances.
pub fn create_pipe(name: &str, first: bool, security: Option<&Security>) -> Result<OwnedHandle> {
    let name = wide(name);
    let flags = PIPE_ACCESS_OUTBOUND
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    // Attributes and name outlive the call.
    let handle = with_attributes(security, |sa| unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            flags,
            PIPE_REJECT_REMOTE_CLIENTS,
            2,
            0,
            0,
            0,
            sa,
        )
    });
    owned(handle)
}

/// Whether this process runs with an elevated token.
pub fn elevated() -> Result<bool> {
    let mut token = ptr::null_mut();
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    let token = owned(token)?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    check(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    })?;
    Ok(elevation.TokenIsElevated != 0)
}

/// Polls every XInput slot, which makes XInput notice removed devices.
pub fn poll_xinput() {
    for slot in 0..4 {
        let _ = xinput_buttons(slot);
    }
}

/// The buttons of a connected XInput slot.
pub fn xinput_buttons(slot: u32) -> Option<u16> {
    let mut state = XINPUT_STATE::default();
    (unsafe { XInputGetState(slot, &mut state) } == 0).then_some(state.Gamepad.wButtons)
}

#[cfg(test)]
pub use device_file::*;

#[cfg(test)]
mod device_file {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    };

    /// Opens a NUL-terminated device interface path.
    pub fn open_device(path: &[u16]) -> Result<OwnedHandle> {
        assert_eq!(path.last(), Some(&0));
        owned(unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        })
    }

    /// Sends a synchronous IOCTL and returns the output length.
    pub fn ioctl(
        device: BorrowedHandle<'_>,
        code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32> {
        let mut returned = 0;
        let input_ptr = if input.is_empty() {
            ptr::null()
        } else {
            input.as_ptr().cast()
        };
        // Both buffers live through the synchronous call with their lengths.
        check(unsafe {
            DeviceIoControl(
                device.as_raw_handle(),
                code,
                input_ptr,
                input.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        })?;
        Ok(returned)
    }
}
