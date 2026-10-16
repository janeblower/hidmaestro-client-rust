use super::{Handle, check, wide};
use crate::{Result, report::EncodedFrame};
use std::{
    io,
    mem::size_of,
    ptr,
    sync::atomic::{Ordering, fence},
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_OUTBOUND},
    System::{Memory::*, Pipes::*, Threading::*},
};

struct Security(*mut std::ffi::c_void);
impl Security {
    fn new() -> Result<Self> {
        let mut sd = ptr::null_mut();
        // Windows allocates sd; Security releases it with LocalFree.
        unsafe {
            check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)").as_ptr(),
                1,
                &mut sd,
                ptr::null_mut(),
            ))?;
        }
        Ok(Self(sd))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Mapping {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    _handle: Handle,
}
impl Mapping {
    fn create(name: &str, size: u32, sa: &SECURITY_ATTRIBUTES) -> Result<Self> {
        // Pagefile-backed mapping; sa and name remain valid through the call.
        unsafe {
            let handle = Handle::new(CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                sa,
                PAGE_READWRITE,
                0,
                size,
                wide(name).as_ptr(),
            ))?;
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    name.to_owned(),
                ));
            }
            let view = MapViewOfFile(
                handle.0,
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                size as usize,
            );
            if view.Value.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                view,
                _handle: handle,
            })
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // No client code accesses the view after Mapping is dropped.
        unsafe {
            UnmapViewOfFile(self.view);
        }
    }
}

fn event(name: &str, sa: &SECURITY_ATTRIBUTES) -> Result<Handle> {
    unsafe {
        let h = Handle::new(CreateEventW(sa, 0, 0, wide(name).as_ptr()))?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                name.to_owned(),
            ));
        }
        Ok(h)
    }
}

pub(super) struct Transport {
    input: Mapping,
    input_event: Handle,
    companion_event: Handle,
    _output: Mapping,
    _output_event: Handle,
    _ack: Mapping,
    _ack_event: Handle,
    _pipes: Vec<Handle>,
    _mutex: Handle,
    sequence: u32,
}

impl Transport {
    #[cfg(test)]
    pub fn create() -> Result<Self> {
        Self::create_with(|| Ok(()))
    }

    pub fn create_with(recover: impl FnOnce() -> Result<()>) -> Result<Self> {
        let sd = Security::new()?;
        let sa = sd.attributes();
        let mutex = unsafe {
            let h = Handle::new(CreateMutexW(
                &sa,
                0,
                wide("Global\\HIDMaestroRustController0").as_ptr(),
            ))?;
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "controller is already owned",
                ));
            }
            h
        };
        recover()?;
        let input = Mapping::create("Global\\HIDMaestroInput0", 362, &sa)?;
        let output = Mapping::create("Global\\HIDMaestroOutput0", 8 + 64 * 264, &sa)?;
        let ack = Mapping::create("Global\\HIDMaestroInputAck0", 16 + 8 * 84, &sa)?;
        let input_event = event("Global\\HIDMaestroInputEvent0", &sa)?;
        let companion_event = event("Global\\HIDMaestroCompanionInputEvent0", &sa)?;
        let output_event = event("Global\\HIDMaestroOutputEvent0", &sa)?;
        let ack_event = event("Global\\HIDMaestroInputAckEvent0", &sa)?;
        let mut pipes = Vec::new();
        for i in 0..2 {
            let flags = PIPE_ACCESS_OUTBOUND
                | if i == 0 {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            // A restarted HID driver needs a second pipe instance to reconnect.
            pipes.push(unsafe {
                Handle::new(CreateNamedPipeW(
                    wide(r"\\.\pipe\HIDMaestroOwner0").as_ptr(),
                    flags,
                    PIPE_REJECT_REMOTE_CLIENTS,
                    2,
                    0,
                    0,
                    0,
                    &sa,
                ))?
            });
        }
        Ok(Self {
            input,
            input_event,
            companion_event,
            _output: output,
            _output_event: output_event,
            _ack: ack,
            _ack_event: ack_event,
            _pipes: pipes,
            _mutex: mutex,
            sequence: 0,
        })
    }

    pub fn publish(&mut self, frame: &EncodedFrame) -> Result<()> {
        // The mapping is live, page aligned, 362 bytes long and has one writer.
        unsafe {
            write_frame(self.input.view.Value.cast(), &mut self.sequence, frame);
            check(SetEvent(self.input_event.0))?;
            check(SetEvent(self.companion_event.0))
        }
    }

    pub fn release(self) -> Handle {
        self._mutex
    }
}

unsafe fn write_frame(view: *mut u8, sequence: &mut u32, frame: &EncodedFrame) {
    // SeqNo is page aligned; byte stores avoid references to shared/packed data.
    unsafe {
        view.cast::<u32>().write_volatile(sequence.wrapping_add(1));
        fence(Ordering::SeqCst);
        for (offset, data) in [
            (4, 18u32.to_le_bytes().as_slice()),
            (8, frame.hid.as_slice()),
            (264, frame.gip.as_slice()),
            (278, &[0; 4]),
        ] {
            for (i, byte) in data.iter().enumerate() {
                view.add(offset + i).write_volatile(*byte);
            }
        }
        fence(Ordering::SeqCst);
        *sequence = sequence.wrapping_add(2);
        view.cast::<u32>().write_volatile(*sequence);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{State, report};

    #[test]
    fn wire_layout_and_sequence_wrap() {
        let mut memory = [0u32; 91];
        let view = memory.as_mut_ptr().cast::<u8>();
        let frame = report::encode(&State {
            left_trigger: 255,
            ..State::default()
        })
        .unwrap();
        let mut sequence = 0xffff_fffe;
        unsafe {
            write_frame(view, &mut sequence, &frame);
        }
        let bytes = unsafe { std::slice::from_raw_parts(view, 362) };
        assert_eq!(&bytes[0..4], &[0; 4]);
        assert_eq!(&bytes[4..8], &18u32.to_le_bytes());
        assert_eq!(&bytes[264 + 8..264 + 10], &1023u16.to_le_bytes());
        assert_eq!(&bytes[278..282], &[0; 4]);
        assert_eq!(sequence, 0);
    }

    #[test]
    #[ignore = "explicit elevated test creates Global mappings"]
    fn exclusive_transport_and_reopen() {
        let mut first = Transport::create().unwrap();
        first
            .publish(&report::encode(&State::default()).unwrap())
            .unwrap();
        assert!(Transport::create().is_err());
        drop(first);
        drop(Transport::create().unwrap());
    }
}
