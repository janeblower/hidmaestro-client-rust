use super::{Handle, check, wide};
use crate::{Result, report::EncodedFrame};
use std::{
    io,
    mem::size_of,
    os::windows::io::{BorrowedHandle, IntoRawHandle, OwnedHandle},
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
    fn from_handle(handle: Handle, size: u32) -> Result<Self> {
        // The owned section handle stays live until the view is unmapped.
        let view = unsafe {
            MapViewOfFile(
                handle.0,
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
            _handle: handle,
        })
    }
    fn create(name: &str, size: u32, sa: &SECURITY_ATTRIBUTES, reuse: bool) -> Result<Self> {
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
            let existed = GetLastError() == ERROR_ALREADY_EXISTS;
            if existed && !reuse {
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
            if existed {
                // Recovery has verified ownership and removed the previous devices.
                view.Value.cast::<u8>().write_bytes(0, size as usize);
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

// HIDMAESTRO_VERSION_INFO in driver/hm_contract.h of HIDMaestro v2.0.0.
const VERSION_SIZE: u32 = 64;
const CONTRACT_PROTOCOL: i32 = 4;
const REMOVE_PROTOCOL: i32 = 5;

/// The 64-bit FNV-1a hash of the token's UTF-16LE code units (HmIdentityTag).
pub(super) fn identity_tag(token: &str) -> u64 {
    token
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

struct Version(Mapping);
impl Version {
    fn create(sa: &SECURITY_ATTRIBUTES, reuse: bool, tag: u64) -> Result<Self> {
        let version = Self(Mapping::create(
            "Global\\HIDMaestroVersion0",
            VERSION_SIZE,
            sa,
            reuse,
        )?);
        // The drivers read the configuration under the contract only once
        // this half names protocol 4 and the devnodes' identity tag. The SDK
        // version is the HIDMaestro release whose contract this client speaks.
        unsafe {
            let view = version.0.view.Value.cast::<u8>();
            for (offset, value) in [(0, 1), (4, CONTRACT_PROTOCOL), (8, CONTRACT_PROTOCOL)] {
                view.add(offset).cast::<i32>().write_volatile(value);
            }
            for (i, part) in [2u16, 0, 0].into_iter().enumerate() {
                view.add(12 + 2 * i).cast::<u16>().write_volatile(part);
            }
            view.add(48).cast::<u64>().write_volatile(tag);
        }
        Ok(version)
    }

    fn read(&self, offset: usize) -> i32 {
        // Offsets are 4-byte aligned within the live 64-byte view.
        let value = unsafe {
            self.0
                .view
                .Value
                .cast::<u8>()
                .add(offset)
                .cast::<i32>()
                .read_volatile()
        };
        // Each driver writes its protocol last; callers read it first, and this
        // fence orders that read before the fields read after it.
        fence(Ordering::SeqCst);
        value
    }

    fn check(&self, who: &str, protocol: usize, min: usize, error: usize) -> Result<()> {
        let error = self.read(error);
        if error != 0 {
            let value = match (who, error) {
                ("XUSB companion", 1) => "XusbAnswers".to_owned(),
                (_, 1) => "FeatureAnswers".to_owned(),
                (_, 2) => "CachedInputReportIds".to_owned(),
                (_, 3) => "LiveFeatureReport".to_owned(),
                (_, error) => format!("value {error}"),
            };
            return Err(io::Error::other(format!(
                "HIDMaestro {who} could not read {value}"
            )));
        }
        let (protocol, min) = (self.read(protocol), self.read(min));
        if !(min..=protocol).contains(&CONTRACT_PROTOCOL) {
            return Err(io::Error::other(format!(
                "HIDMaestro {who} serves protocols {min} to {protocol}; this client speaks {CONTRACT_PROTOCOL}"
            )));
        }
        Ok(())
    }
}

fn event(name: &str, sa: &SECURITY_ATTRIBUTES, reuse: bool) -> Result<Handle> {
    unsafe {
        let h = Handle::new(CreateEventW(sa, 0, 0, wide(name).as_ptr()))?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if !reuse {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    name.to_owned(),
                ));
            }
            check(ResetEvent(h.0))?;
        }
        Ok(h)
    }
}

/// Writes directly to an existing HIDMaestro input mapping.
pub struct Writer {
    input: Mapping,
    input_event: Handle,
    companion_event: Handle,
    sequence: u32,
}

// Writer owns its view and events; submission requires exclusive access.
unsafe impl Send for Writer {}

impl Writer {
    fn create(name: &str, sa: &SECURITY_ATTRIBUTES, reuse: bool) -> Result<Self> {
        Ok(Self {
            input: Mapping::create(name, 362, sa, reuse)?,
            companion_event: event(&name.replace("Input", "CompanionInputEvent"), sa, reuse)?,
            input_event: event(&name.replace("Input", "InputEvent"), sa, reuse)?,
            sequence: 0,
        })
    }

    /// Imports the input section, input event and companion event, in that order.
    ///
    /// # Safety
    /// The handles must refer to HIDMaestro's 362-byte input section and its
    /// events. No other writer may submit until this writer has been dropped.
    pub unsafe fn from_handles(handles: [OwnedHandle; 3]) -> Result<Self> {
        let [input, input_event, companion_event] = handles.map(|h| Handle(h.into_raw_handle()));
        let input = Mapping::from_handle(input, 362)?;
        // The caller guarantees that the previous writer has stopped.
        let sequence = unsafe { input.view.Value.cast::<u32>().read_volatile() };
        if sequence & 1 != 0 {
            return Err(io::Error::other("input writer stopped during publication"));
        }
        Ok(Self {
            input,
            input_event,
            companion_event,
            sequence,
        })
    }

    /// Returns the section and two events for duplication into another process.
    pub fn handles(&self) -> [BorrowedHandle<'_>; 3] {
        // These handles are owned by self for the lifetime of the borrows.
        unsafe {
            [
                self.input._handle.0,
                self.input_event.0,
                self.companion_event.0,
            ]
            .map(|h| BorrowedHandle::borrow_raw(h))
        }
    }

    /// Publishes a validated state and wakes both driver input paths.
    pub fn submit(&mut self, state: &crate::State) -> Result<()> {
        self.publish(&crate::report::encode(state)?)
    }

    fn neutral(&mut self) -> Result<()> {
        // A crashed writer may have stopped after publishing an odd sequence.
        self.sequence = unsafe { self.input.view.Value.cast::<u32>().read_volatile() } & !1;
        self.submit(&crate::State::default())
    }

    fn publish(&mut self, frame: &EncodedFrame) -> Result<()> {
        // The mapping is live, page aligned, 362 bytes long and has one writer.
        unsafe {
            write_frame(self.input.view.Value.cast(), &mut self.sequence, frame);
            check(SetEvent(self.input_event.0))?;
            check(SetEvent(self.companion_event.0))
        }
    }
}

pub(super) struct Transport {
    writer: Writer,
    delegated: bool,
    _output: Mapping,
    _output_event: Handle,
    _ack: Mapping,
    _ack_event: Handle,
    version: Version,
    remove_event: Handle,
    removed_event: Handle,
    _pipes: Vec<Handle>,
    _mutex: Handle,
}

impl Transport {
    #[cfg(test)]
    pub fn create() -> Result<Self> {
        Self::create_with(identity_tag("HM_RUST_CLIENT_TEST"), || Ok(true))
    }

    pub fn create_with(tag: u64, recover: impl FnOnce() -> Result<bool>) -> Result<Self> {
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
        let reuse = recover()?;
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
        let output = Mapping::create("Global\\HIDMaestroOutput0", 8 + 64 * 264, &sa, reuse)?;
        let ack = Mapping::create("Global\\HIDMaestroInputAck0", 16 + 8 * 84, &sa, reuse)?;
        let output_event = event("Global\\HIDMaestroOutputEvent0", &sa, reuse)?;
        let ack_event = event("Global\\HIDMaestroInputAckEvent0", &sa, reuse)?;
        let remove_event = event("Global\\HIDMaestroRemoveEvent0", &sa, reuse)?;
        let removed_event = event("Global\\HIDMaestroRemovedEvent0", &sa, reuse)?;
        let version = Version::create(&sa, reuse, tag)?;
        // The driver opens the other objects once, when the input event first opens.
        let writer = Writer::create("Global\\HIDMaestroInput0", &sa, reuse)?;
        Ok(Self {
            writer,
            delegated: false,
            _output: output,
            _output_event: output_event,
            _ack: ack,
            _ack_event: ack_event,
            version,
            remove_event,
            removed_event,
            _pipes: pipes,
            _mutex: mutex,
        })
    }

    /// Fails unless the started HID driver read the configuration under protocol 4.
    pub fn check_driver(&self) -> Result<()> {
        self.version.check("driver", 20, 36, 56)
    }

    /// Fails unless the started XUSB companion read its answers under protocol 4.
    pub fn check_companion(&self) -> Result<()> {
        self.version.check("XUSB companion", 40, 44, 60)
    }

    /// Asks a protocol 5 driver to fail its device, which Windows then removes
    /// with its HID children as an unplugged device, whatever holds them open.
    pub fn eject(&self) -> bool {
        if self.version.read(20) < REMOVE_PROTOCOL {
            return false;
        }
        // A stale answer to an earlier request is not this one.
        unsafe {
            ResetEvent(self.removed_event.0) != 0
                && SetEvent(self.remove_event.0) != 0
                && WaitForSingleObject(self.removed_event.0, 2000) == 0
        }
    }

    pub fn publish(&mut self, frame: &EncodedFrame) -> Result<()> {
        if self.delegated {
            return Err(io::Error::other("input writer has been delegated"));
        }
        self.writer.publish(frame)
    }

    pub fn take_writer(&mut self) -> Result<Writer> {
        if self.delegated {
            return Err(io::Error::other("input writer has been delegated"));
        }
        let handles = self.writer.handles().map(|h| h.try_clone_to_owned());
        let [a, b, c] = handles;
        // The controller stops publishing until cleanup; the caller stops the
        // delegated writer before cleanup, as required by take_writer.
        let writer = unsafe { Writer::from_handles([a?, b?, c?]) }?;
        self.delegated = true;
        Ok(writer)
    }

    pub fn neutral(&mut self) -> Result<()> {
        self.writer.neutral()
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
    fn identity_tag_matches_driver_contract() {
        // Reference values from driver/hm_contract.h.
        assert_eq!(identity_tag("HM_0000"), 0x1fd0_4891_6b8d_461f);
        assert_eq!(identity_tag("HM_0123456789ABCDEF"), 0x3b86_f363_4086_d831);
    }

    #[test]
    fn version_half_names_contract_and_reads_driver_errors() {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let mapping = Mapping::create(
            &format!("Local\\HIDMaestroVersionTest{}", std::process::id()),
            VERSION_SIZE,
            &sa,
            false,
        )
        .unwrap();
        let view = mapping.view.Value.cast::<u8>();
        let version = Version(mapping);
        assert!(version.check("driver", 20, 36, 56).is_err());
        unsafe {
            view.add(36).cast::<i32>().write_volatile(4);
            view.add(20).cast::<i32>().write_volatile(5);
        }
        version.check("driver", 20, 36, 56).unwrap();
        unsafe { view.add(56).cast::<i32>().write_volatile(1) };
        let error = version.check("driver", 20, 36, 56).unwrap_err();
        assert!(error.to_string().contains("FeatureAnswers"));
        unsafe { view.add(36).cast::<i32>().write_volatile(5) };
        unsafe { view.add(56).cast::<i32>().write_volatile(0) };
        assert!(version.check("driver", 20, 36, 56).is_err());
    }

    #[test]
    fn retained_mapping_is_reset_on_reopen() {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let name = format!("Local\\HIDMaestroRetainedTest{}", std::process::id());
        let old = Mapping::create(&name, 8192, &sa, false).unwrap();
        unsafe { old.view.Value.cast::<u8>().write_bytes(0xff, 8192) };
        assert!(Mapping::create(&name, 8192, &sa, false).is_err());
        assert!(Mapping::create(&name, 16384, &sa, true).is_err());
        assert_eq!(unsafe { old.view.Value.cast::<u8>().read_volatile() }, 0xff);
        let reopened = Mapping::create(&name, 8192, &sa, true).unwrap();
        let bytes = unsafe { std::slice::from_raw_parts(reopened.view.Value.cast::<u8>(), 8192) };
        assert!(bytes.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn retained_event_is_reset_on_reopen() {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let name = format!("Local\\HIDMaestroRetainedEventTest{}", std::process::id());
        let old = event(&name, &sa, false).unwrap();
        check(unsafe { SetEvent(old.0) }).unwrap();
        assert!(event(&name, &sa, false).is_err());
        let reopened = event(&name, &sa, true).unwrap();
        assert_eq!(unsafe { WaitForSingleObject(reopened.0, 0) }, 258);
    }

    #[test]
    fn imported_writer_continues_sequence_and_signals_both_events() {
        let sd = Security::new().unwrap();
        let sa = sd.attributes();
        let name = format!("Local\\HIDMaestroInputTest{}", std::process::id());
        let mut writer = Writer::create(&name, &sa, false).unwrap();
        writer.submit(&State::default()).unwrap();
        let handles = writer.handles().map(|h| h.try_clone_to_owned().unwrap());
        drop(writer);
        // The original writer is gone and these are its only writable handles.
        let mut imported = unsafe { Writer::from_handles(handles) }.unwrap();
        imported
            .submit(&State {
                buttons: crate::Buttons::A,
                ..State::default()
            })
            .unwrap();
        let view = imported.input.view.Value.cast::<u8>();
        unsafe {
            assert_eq!(view.cast::<u32>().read_volatile(), 4);
            assert_eq!(view.add(276).read_volatile(), 1);
            assert_eq!(WaitForSingleObject(imported.input_event.0, 0), 0);
            assert_eq!(WaitForSingleObject(imported.companion_event.0, 0), 0);
        }
    }

    #[test]
    fn neutral_recovers_a_writer_killed_mid_frame() {
        let sd = Security::new().unwrap();
        let mut writer = Writer::create(
            &format!("Local\\HIDMaestroInputCrashTest{}", std::process::id()),
            &sd.attributes(),
            false,
        )
        .unwrap();
        let view = writer.input.view.Value.cast::<u8>();
        // Simulate a dead publisher with a partly written A press.
        unsafe {
            view.cast::<u32>().write_volatile(3);
            view.add(276).write_volatile(1);
        }
        writer.neutral().unwrap();
        unsafe {
            assert_eq!(view.cast::<u32>().read_volatile(), 4);
            assert_eq!(view.add(276).read_volatile(), 0);
        }
    }

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
            .publish(
                &report::encode(&State {
                    buttons: crate::Buttons::A,
                    ..State::default()
                })
                .unwrap(),
            )
            .unwrap();
        assert!(Transport::create().is_err());
        let input = first.writer.handles()[0].try_clone_to_owned().unwrap();
        let retained = Mapping::from_handle(Handle(input.into_raw_handle()), 362).unwrap();
        let pipe = unsafe { BorrowedHandle::borrow_raw(first._pipes[0].0) }
            .try_clone_to_owned()
            .unwrap();
        drop(first);
        assert!(Transport::create().is_err());
        assert_eq!(
            unsafe { retained.view.Value.cast::<u8>().add(276).read_volatile() },
            1
        );
        drop(pipe);
        assert!(Transport::create_with(identity_tag("HM_RUST_CLIENT_TEST"), || Ok(false)).is_err());
        assert_eq!(
            unsafe { retained.view.Value.cast::<u8>().add(276).read_volatile() },
            1
        );
        drop(Transport::create().unwrap());
    }
}
