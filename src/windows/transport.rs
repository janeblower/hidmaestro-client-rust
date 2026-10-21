use super::sys::{Event, Mapping, Security, create_mutex, create_pipe};
use crate::{Result, report::EncodedFrame};
use std::{
    io,
    os::windows::io::{BorrowedHandle, OwnedHandle},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicI32, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering, fence},
    },
};

const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)";

/// Creates a section, or reopens and clears one retained by a recovered session.
fn section(name: &str, size: u32, security: Option<&Security>, reuse: bool) -> Result<Mapping> {
    let (mapping, existed) = Mapping::create(name, size, security, reuse)?;
    if existed {
        // Recovery has verified ownership and removed the previous devices.
        for offset in 0..mapping.size() {
            mapping.at::<AtomicU8>(offset).store(0, Ordering::Relaxed);
        }
    }
    Ok(mapping)
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
    fn create(security: Option<&Security>, reuse: bool, tag: u64) -> Result<Self> {
        let version = Self(section(
            "Global\\HIDMaestroVersion0",
            VERSION_SIZE,
            security,
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

fn event(name: &str, security: Option<&Security>, reuse: bool) -> Result<Event> {
    let (event, existed) = Event::create(name, security, false)?;
    if existed {
        if !reuse {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                name.to_owned(),
            ));
        }
        event.reset()?;
    }
    Ok(event)
}

struct Input {
    mapping: Mapping,
    input_event: Event,
    companion_event: Event,
    publisher: Mutex<Publisher>,
}

struct Publisher {
    sequence: u32,
    closed: bool,
}

impl Input {
    fn lock(&self) -> MutexGuard<'_, Publisher> {
        // write_frame does not panic, so a poisoned lock still holds a whole frame.
        self.publisher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, publisher: &mut Publisher, frame: &EncodedFrame) -> Result<()> {
        write_frame(&self.mapping, &mut publisher.sequence, frame);
        self.input_event.set()?;
        self.companion_event.set()
    }
}

/// Writes directly to an existing HIDMaestro input mapping.
pub struct Writer(Arc<Input>);

impl Writer {
    fn create(name: &str, security: Option<&Security>, reuse: bool) -> Result<Self> {
        Ok(Self(Arc::new(Input {
            mapping: section(name, 362, security, reuse)?,
            companion_event: event(
                &name.replace("Input", "CompanionInputEvent"),
                security,
                reuse,
            )?,
            input_event: event(&name.replace("Input", "InputEvent"), security, reuse)?,
            publisher: Mutex::new(Publisher {
                sequence: 0,
                closed: false,
            }),
        })))
    }

    /// Imports the input section, input event and companion event, in that order.
    ///
    /// Fails unless the first handle is a section that maps 362 writable
    /// bytes; events of the wrong kind make `submit` fail.
    ///
    /// The handles should refer to HIDMaestro's input section and its events,
    /// and no other writer should submit until this one is dropped, including
    /// the controller, which publishes neutral when it closes. Otherwise the
    /// drivers may read torn frames; memory safety does not depend on it.
    pub fn from_handles(handles: [OwnedHandle; 3]) -> Result<Self> {
        let [input, input_event, companion_event] = handles;
        let mapping = Mapping::from_handle(input, 362)?;
        let sequence = mapping.at::<AtomicU32>(0).load(Ordering::Relaxed);
        if sequence & 1 != 0 {
            return Err(io::Error::other("input writer stopped during publication"));
        }
        Ok(Self(Arc::new(Input {
            mapping,
            input_event: input_event.into(),
            companion_event: companion_event.into(),
            publisher: Mutex::new(Publisher {
                sequence,
                closed: false,
            }),
        })))
    }

    /// Returns the section and two events for duplication into another process.
    pub fn handles(&self) -> [BorrowedHandle<'_>; 3] {
        [
            self.0.mapping.handle(),
            self.0.input_event.handle(),
            self.0.companion_event.handle(),
        ]
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
    _output_event: Event,
    _ack: Mapping,
    _ack_event: Event,
    version: Version,
    remove_event: Event,
    removed_event: Event,
    _pipes: Vec<OwnedHandle>,
    _mutex: OwnedHandle,
}

impl Transport {
    #[cfg(test)]
    pub fn create() -> Result<Self> {
        Self::create_with(identity_tag("HM_RUST_CLIENT_TEST"), || Ok(true))
    }

    pub fn create_with(tag: u64, recover: impl FnOnce() -> Result<bool>) -> Result<Self> {
        let sd = Security::new(SDDL)?;
        let sa = Some(&sd);
        let (mutex, existed) = create_mutex("Global\\HIDMaestroRustController0", sa)?;
        if existed {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "controller is already owned",
            ));
        }
        let reuse = recover()?;
        // A restarted HID driver needs a second pipe instance to reconnect.
        let pipes = [true, false]
            .into_iter()
            .map(|first| create_pipe(r"\\.\pipe\HIDMaestroOwner0", first, sa))
            .collect::<Result<_>>()?;
        let output = section("Global\\HIDMaestroOutput0", 8 + 64 * 264, sa, reuse)?;
        let ack = section("Global\\HIDMaestroInputAck0", 16 + 8 * 84, sa, reuse)?;
        let output_event = event("Global\\HIDMaestroOutputEvent0", sa, reuse)?;
        let ack_event = event("Global\\HIDMaestroInputAckEvent0", sa, reuse)?;
        let remove_event = event("Global\\HIDMaestroRemoveEvent0", sa, reuse)?;
        let removed_event = event("Global\\HIDMaestroRemovedEvent0", sa, reuse)?;
        let version = Version::create(sa, reuse, tag)?;
        // The driver opens the other objects once, when the input event first opens.
        let writer = Writer::create("Global\\HIDMaestroInput0", sa, reuse)?;
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
        self.removed_event.reset().is_ok()
            && self.remove_event.set().is_ok()
            && self.removed_event.wait(2000).unwrap_or(false)
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

    pub fn release(self) -> OwnedHandle {
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
    use crate::{State, report, windows::sys::duplicate};
    use std::os::windows::io::AsHandle;
    use windows_sys::Win32::System::Memory::FILE_MAP_READ;

    fn byte(mapping: &Mapping, offset: usize) -> u8 {
        mapping.at::<AtomicU8>(offset).load(Ordering::Relaxed)
    }

    fn sequence(mapping: &Mapping) -> u32 {
        mapping.at::<AtomicU32>(0).load(Ordering::Relaxed)
    }

    fn name(what: &str) -> String {
        format!("Local\\HIDMaestro{what}Test{}", std::process::id())
    }

    fn local(what: &str, size: u32) -> Mapping {
        section(&name(what), size, None, false).unwrap()
    }

    fn owned(handle: BorrowedHandle<'_>) -> OwnedHandle {
        handle.try_clone_to_owned().unwrap()
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
        let name = name("Retained");
        let old = section(&name, 8192, None, false).unwrap();
        for offset in 0..8192 {
            old.at::<AtomicU8>(offset).store(0xff, Ordering::Relaxed);
        }
        assert!(section(&name, 8192, None, false).is_err());
        assert!(section(&name, 16384, None, true).is_err());
        assert_eq!(byte(&old, 0), 0xff);
        let reopened = section(&name, 8192, None, true).unwrap();
        assert!((0..8192).all(|offset| byte(&reopened, offset) == 0));
    }

    #[test]
    fn retained_event_is_reset_on_reopen() {
        let name = name("RetainedEvent");
        let old = event(&name, None, false).unwrap();
        old.set().unwrap();
        assert!(event(&name, None, false).is_err());
        let reopened = event(&name, None, true).unwrap();
        assert!(!reopened.wait(0).unwrap());
    }

    #[test]
    fn imported_writer_continues_sequence_and_signals_both_events() {
        let sd = Security::new(SDDL).unwrap();
        let mut writer = Writer::create(&name("Input"), Some(&sd), false).unwrap();
        writer.submit(&State::default()).unwrap();
        let handles = writer.handles().map(owned);
        drop(writer);
        let mut imported = Writer::from_handles(handles).unwrap();
        imported
            .submit(&State {
                buttons: crate::Buttons::A,
                ..State::default()
            })
            .unwrap();
        assert_eq!(sequence(&imported.0.mapping), 4);
        assert_eq!(byte(&imported.0.mapping, 276), 1);
        assert!(imported.0.input_event.wait(0).unwrap());
        assert!(imported.0.companion_event.wait(0).unwrap());
    }

    #[test]
    fn import_rejects_what_is_not_a_writable_section() {
        let sd = Security::new(SDDL).unwrap();
        let sa = Some(&sd);
        let section = section(&name("ImportInput"), 362, sa, false).unwrap();
        let input = event(&name("ImportInputEvent"), sa, false).unwrap();
        let companion = event(&name("ImportCompanion"), sa, false).unwrap();
        let read_only = duplicate(section.handle(), FILE_MAP_READ).unwrap();
        for wrong in [input.handle(), read_only.as_handle()] {
            let handles = [
                owned(wrong),
                owned(input.handle()),
                owned(companion.handle()),
            ];
            assert!(Writer::from_handles(handles).is_err());
        }
    }

    #[test]
    fn import_with_wrong_events_fails_to_submit() {
        let sd = Security::new(SDDL).unwrap();
        let section = section(&name("WrongEventsInput"), 362, Some(&sd), false).unwrap();
        let mut writer = Writer::from_handles([(); 3].map(|_| owned(section.handle()))).unwrap();
        assert!(writer.submit(&State::default()).is_err());
    }

    #[test]
    fn neutral_recovers_a_writer_killed_mid_frame() {
        let sd = Security::new(SDDL).unwrap();
        let mut writer = Writer::create(&name("InputCrash"), Some(&sd), false).unwrap();
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
        let sd = Security::new(SDDL).unwrap();
        let mut owner = Writer::create(&name("InputShare"), Some(&sd), false).unwrap();
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
        let retained = Mapping::from_handle(owned(first.writer.handles()[0]), 362).unwrap();
        let pipe = first._pipes[0].try_clone().unwrap();
        drop(first);
        assert!(Transport::create().is_err());
        assert_eq!(byte(&retained, 276), 1);
        drop(pipe);
        assert!(Transport::create_with(identity_tag("HM_RUST_CLIENT_TEST"), || Ok(false)).is_err());
        assert_eq!(byte(&retained, 276), 1);
        drop(Transport::create().unwrap());
    }
}
