use super::{Handle, check, wide};
use crate::{Result, report::EncodedFrame};
use std::{
    io,
    mem::size_of,
    os::windows::io::{BorrowedHandle, IntoRawHandle, OwnedHandle},
    ptr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicI32, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering, fence},
    },
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

/// Integers that the drivers and other processes may access concurrently.
trait Shared {}
impl Shared for AtomicU8 {}
impl Shared for AtomicU16 {}
impl Shared for AtomicI32 {}
impl Shared for AtomicU32 {}
impl Shared for AtomicU64 {}

struct Mapping {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    size: usize,
    _handle: Handle,
}
impl Mapping {
    fn from_handle(handle: Handle, size: u32) -> Result<Self> {
        // MapViewOfFile fails unless the section has at least size bytes;
        // the owned section handle stays live until the view is unmapped.
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
            size: size as usize,
            _handle: handle,
        })
    }
    fn create(name: &str, size: u32, sa: &SECURITY_ATTRIBUTES, reuse: bool) -> Result<Self> {
        // Pagefile-backed mapping; sa and name remain valid through the call.
        let (handle, existed) = unsafe {
            let handle = Handle::new(CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                sa,
                PAGE_READWRITE,
                0,
                size,
                wide(name).as_ptr(),
            ))?;
            (handle, GetLastError() == ERROR_ALREADY_EXISTS)
        };
        if existed && !reuse {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                name.to_owned(),
            ));
        }
        let mapping = Self::from_handle(handle, size)?;
        if existed {
            // Recovery has verified ownership and removed the previous devices.
            for offset in 0..mapping.size {
                mapping.at::<AtomicU8>(offset).store(0, Ordering::Relaxed);
            }
        }
        Ok(mapping)
    }

    /// Views the shared integer at offset; panics if it is out of bounds or misaligned.
    fn at<T: Shared>(&self, offset: usize) -> &T {
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
        let view = &version.0;
        for (offset, value) in [(0, 1), (4, CONTRACT_PROTOCOL), (8, CONTRACT_PROTOCOL)] {
            view.at::<AtomicI32>(offset).store(value, Ordering::Relaxed);
        }
        for (i, part) in [2u16, 0, 0].into_iter().enumerate() {
            view.at::<AtomicU16>(12 + 2 * i)
                .store(part, Ordering::Relaxed);
        }
        view.at::<AtomicU64>(48).store(tag, Ordering::Relaxed);
        Ok(version)
    }

    fn read(&self, offset: usize) -> i32 {
        let value = self.0.at::<AtomicI32>(offset).load(Ordering::Relaxed);
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

struct Input {
    mapping: Mapping,
    input_event: Handle,
    companion_event: Handle,
    publisher: Mutex<Publisher>,
}

struct Publisher {
    sequence: u32,
    closed: bool,
}

// The handles never change and the view is accessed only through atomics.
unsafe impl Send for Input {}
unsafe impl Sync for Input {}

impl Input {
    fn lock(&self) -> MutexGuard<'_, Publisher> {
        // write_frame does not panic, so a poisoned lock still holds a whole frame.
        self.publisher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, publisher: &mut Publisher, frame: &EncodedFrame) -> Result<()> {
        write_frame(&self.mapping, &mut publisher.sequence, frame);
        unsafe {
            check(SetEvent(self.input_event.0))?;
            check(SetEvent(self.companion_event.0))
        }
    }
}

/// Writes directly to an existing HIDMaestro input mapping.
pub struct Writer(Arc<Input>);

impl Writer {
    fn create(name: &str, sa: &SECURITY_ATTRIBUTES, reuse: bool) -> Result<Self> {
        Ok(Self(Arc::new(Input {
            mapping: Mapping::create(name, 362, sa, reuse)?,
            companion_event: event(&name.replace("Input", "CompanionInputEvent"), sa, reuse)?,
            input_event: event(&name.replace("Input", "InputEvent"), sa, reuse)?,
            publisher: Mutex::new(Publisher {
                sequence: 0,
                closed: false,
            }),
        })))
    }

    /// Imports the input section, input event and companion event, in that order.
    ///
    /// # Safety
    /// The handles must refer to HIDMaestro's 362-byte input section and its
    /// events. No other writer may submit until this writer has been dropped,
    /// including the controller, which publishes neutral when it closes.
    pub unsafe fn from_handles(handles: [OwnedHandle; 3]) -> Result<Self> {
        let [input, input_event, companion_event] = handles.map(|h| Handle(h.into_raw_handle()));
        let mapping = Mapping::from_handle(input, 362)?;
        // The caller guarantees that the previous writer has stopped.
        let sequence = mapping.at::<AtomicU32>(0).load(Ordering::Relaxed);
        if sequence & 1 != 0 {
            return Err(io::Error::other("input writer stopped during publication"));
        }
        Ok(Self(Arc::new(Input {
            mapping,
            input_event,
            companion_event,
            publisher: Mutex::new(Publisher {
                sequence,
                closed: false,
            }),
        })))
    }

    /// Returns the section and two events for duplication into another process.
    pub fn handles(&self) -> [BorrowedHandle<'_>; 3] {
        // These handles are owned by self for the lifetime of the borrows.
        unsafe {
            [
                self.0.mapping._handle.0,
                self.0.input_event.0,
                self.0.companion_event.0,
            ]
            .map(|h| BorrowedHandle::borrow_raw(h))
        }
    }

    /// Publishes a validated state and wakes both driver input paths.
    ///
    /// Fails once the controller that delegated this writer has closed.
    pub fn submit(&mut self, state: &crate::State) -> Result<()> {
        self.publish(&crate::report::encode(state)?)
    }

    fn share(&self) -> Self {
        Self(Arc::clone(&self.0))
    }

    /// Publishes neutral and stops every writer sharing this input.
    fn neutral(&mut self) -> Result<()> {
        let mut publisher = self.0.lock();
        publisher.closed = true;
        // A crashed writer may have stopped after publishing an odd sequence.
        publisher.sequence = self.0.mapping.at::<AtomicU32>(0).load(Ordering::Relaxed) & !1;
        let frame = crate::report::encode(&crate::State::default())?;
        self.0.publish(&mut publisher, &frame)
    }

    fn publish(&mut self, frame: &EncodedFrame) -> Result<()> {
        let mut publisher = self.0.lock();
        if publisher.closed {
            return Err(io::Error::other("controller is closed"));
        }
        self.0.publish(&mut publisher, frame)
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
        self.delegated = true;
        Ok(self.writer.share())
    }

    pub fn neutral(&mut self) -> Result<()> {
        self.writer.neutral()
    }

    pub fn release(self) -> Handle {
        self._mutex
    }
}

fn write_frame(input: &Mapping, sequence: &mut u32, frame: &EncodedFrame) {
    let seq = input.at::<AtomicU32>(0);
    seq.store(sequence.wrapping_add(1), Ordering::Relaxed);
    fence(Ordering::SeqCst);
    // The packed report fields are not aligned for wider stores.
    for (offset, data) in [
        (4, 18u32.to_le_bytes().as_slice()),
        (8, frame.hid.as_slice()),
        (264, frame.gip.as_slice()),
        (278, &[0; 4]),
    ] {
        for (i, byte) in data.iter().enumerate() {
            input
                .at::<AtomicU8>(offset + i)
                .store(*byte, Ordering::Relaxed);
        }
    }
    fence(Ordering::SeqCst);
    *sequence = sequence.wrapping_add(2);
    seq.store(*sequence, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{State, report};

    fn byte(mapping: &Mapping, offset: usize) -> u8 {
        mapping.at::<AtomicU8>(offset).load(Ordering::Relaxed)
    }

    fn sequence(mapping: &Mapping) -> u32 {
        mapping.at::<AtomicU32>(0).load(Ordering::Relaxed)
    }

    fn local(name: &str, size: u32) -> Mapping {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let name = format!("Local\\HIDMaestro{name}Test{}", std::process::id());
        Mapping::create(&name, size, &sa, false).unwrap()
    }

    #[test]
    #[should_panic]
    fn shared_access_past_the_view_panics() {
        local("Bounds", 362).at::<AtomicU32>(360);
    }

    #[test]
    #[should_panic]
    fn misaligned_shared_access_panics() {
        local("Align", 362).at::<AtomicU32>(2);
    }

    #[test]
    fn identity_tag_matches_driver_contract() {
        // Reference values from driver/hm_contract.h.
        assert_eq!(identity_tag("HM_0000"), 0x1fd0_4891_6b8d_461f);
        assert_eq!(identity_tag("HM_0123456789ABCDEF"), 0x3b86_f363_4086_d831);
    }

    #[test]
    fn version_half_names_contract_and_reads_driver_errors() {
        let version = Version(local("Version", VERSION_SIZE));
        let set = |offset, value| {
            version
                .0
                .at::<AtomicI32>(offset)
                .store(value, Ordering::Relaxed)
        };
        assert!(version.check("driver", 20, 36, 56).is_err());
        set(36, 4);
        set(20, 5);
        version.check("driver", 20, 36, 56).unwrap();
        set(56, 1);
        let error = version.check("driver", 20, 36, 56).unwrap_err();
        assert!(error.to_string().contains("FeatureAnswers"));
        set(36, 5);
        set(56, 0);
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
        for offset in 0..8192 {
            old.at::<AtomicU8>(offset).store(0xff, Ordering::Relaxed);
        }
        assert!(Mapping::create(&name, 8192, &sa, false).is_err());
        assert!(Mapping::create(&name, 16384, &sa, true).is_err());
        assert_eq!(byte(&old, 0), 0xff);
        let reopened = Mapping::create(&name, 8192, &sa, true).unwrap();
        assert!((0..8192).all(|offset| byte(&reopened, offset) == 0));
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
        assert_eq!(sequence(&imported.0.mapping), 4);
        assert_eq!(byte(&imported.0.mapping, 276), 1);
        unsafe {
            assert_eq!(WaitForSingleObject(imported.0.input_event.0, 0), 0);
            assert_eq!(WaitForSingleObject(imported.0.companion_event.0, 0), 0);
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
        let view = &writer.0.mapping;
        // Simulate a dead publisher with a partly written A press.
        view.at::<AtomicU32>(0).store(3, Ordering::Relaxed);
        view.at::<AtomicU8>(276).store(1, Ordering::Relaxed);
        writer.neutral().unwrap();
        assert_eq!(sequence(&writer.0.mapping), 4);
        assert_eq!(byte(&writer.0.mapping, 276), 0);
    }

    #[test]
    fn shared_writer_stops_once_the_owner_publishes_neutral() {
        let sd = Security::new().unwrap();
        let mut owner = Writer::create(
            &format!("Local\\HIDMaestroInputShareTest{}", std::process::id()),
            &sd.attributes(),
            false,
        )
        .unwrap();
        let mut shared = owner.share();
        let pressed = State {
            buttons: crate::Buttons::A,
            ..State::default()
        };
        shared.submit(&pressed).unwrap();
        assert_eq!(byte(&owner.0.mapping, 276), 1);
        owner.neutral().unwrap();
        assert!(shared.submit(&pressed).is_err());
        assert_eq!(sequence(&owner.0.mapping), 4);
        assert_eq!(byte(&owner.0.mapping, 276), 0);
    }

    #[test]
    fn wire_layout_and_sequence_wrap() {
        let view = local("Wire", 362);
        let frame = report::encode(&State {
            left_trigger: 255,
            ..State::default()
        })
        .unwrap();
        let mut next = 0xffff_fffe;
        write_frame(&view, &mut next, &frame);
        let bytes: Vec<u8> = (0..362).map(|offset| byte(&view, offset)).collect();
        assert_eq!(&bytes[0..4], &[0; 4]);
        assert_eq!(&bytes[4..8], &18u32.to_le_bytes());
        assert_eq!(&bytes[264 + 8..264 + 10], &1023u16.to_le_bytes());
        assert_eq!(&bytes[278..282], &[0; 4]);
        assert_eq!(next, 0);
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
        assert_eq!(byte(&retained, 276), 1);
        drop(pipe);
        assert!(Transport::create_with(identity_tag("HM_RUST_CLIENT_TEST"), || Ok(false)).is_err());
        assert_eq!(byte(&retained, 276), 1);
        drop(Transport::create().unwrap());
    }
}
