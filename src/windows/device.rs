use super::{
    sys::{
        self, Description, DevNode, DeviceSet, Event, Key, Mapping, SoftwareDevice, interface,
        utf16_bytes,
    },
    transport::{Transport, identity_tag},
};
use crate::{Result, State, report};
use std::{
    collections::BTreeMap,
    io,
    os::windows::io::OwnedHandle,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::*, System::Registry::*,
        System::Threading::EVENT_MODIFY_STATE,
    },
    core::GUID,
};

const CONFIG: &str = r"SOFTWARE\HIDMaestro\Controller0";
const JOURNAL: &str = r"SOFTWARE\HIDMaestroRustClient\Controller0";
// Both drivers find the index of the devnodes ending in TOKEN here before they start.
const IDENTITY: &str = r"SOFTWARE\HIDMaestro\Identity\HM_RUST_CLIENT_0";
const TOKEN: &str = "HM_RUST_CLIENT_0";
const OWNER: &str = "hidmaestro-client-rust/v1/xbox360";
const SWD_HARDWARE: &str = "root\\VID_045E&PID_028E&XI_00\0root\\HIDMaestroXUSB\0";
const ROOT_ID: &str = r"ROOT\VID_045E&PID_028E&IG_00\HM_RUST_CLIENT_0";
#[cfg(test)]
const SWD_ID: &str = r"SWD\HIDMAESTRO\HM_RUST_CLIENT_0";
const HARDWARE: &str =
    "root\\VID_045E&PID_028E&IG_00\0root\\HIDMaestroRustXbox360\0root\\HIDMaestro\0";
const NAME: &str = "Controller (XBOX 360 For Windows)";
const HID_CLASS: GUID = GUID::from_u128(0x745a17a0_74d3_11d0_b6fe_00a0c90f57da);
const CONTAINER: GUID = GUID::from_u128(0xc85bcbd9_a797_4e3f_945d_d5a0d121aa10);
const XUSB_INTERFACE: GUID = GUID::from_u128(0xec87f1e3_c13b_4100_b5f7_8b84d54260cb);
const DESCRIPTOR: [u8; 143] = [
    0x05, 0x01, 0x09, 0x05, 0xa1, 0x01, 0xa1, 0x00, 0x09, 0x30, 0x09, 0x31, 0x15, 0x00, 0x26, 0xff,
    0xff, 0x35, 0x00, 0x46, 0xff, 0xff, 0x95, 0x02, 0x75, 0x10, 0x81, 0x02, 0xc0, 0xa1, 0x00, 0x09,
    0x33, 0x09, 0x34, 0x15, 0x00, 0x26, 0xff, 0xff, 0x35, 0x00, 0x46, 0xff, 0xff, 0x95, 0x02, 0x75,
    0x10, 0x81, 0x02, 0xc0, 0xa1, 0x00, 0x09, 0x32, 0x15, 0x00, 0x26, 0xff, 0xff, 0x35, 0x00, 0x46,
    0xff, 0xff, 0x95, 0x01, 0x75, 0x10, 0x81, 0x02, 0xc0, 0xa1, 0x00, 0x09, 0x40, 0x09, 0x41, 0x15,
    0x00, 0x26, 0xff, 0xff, 0x35, 0x00, 0x46, 0xff, 0xff, 0x95, 0x02, 0x75, 0x10, 0x81, 0x02, 0xc0,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x0a, 0x95, 0x0a, 0x75, 0x01, 0x81, 0x02, 0x05, 0x01, 0x09, 0x39,
    0x15, 0x01, 0x25, 0x08, 0x35, 0x00, 0x46, 0x3b, 0x10, 0x66, 0x0e, 0x00, 0x75, 0x04, 0x95, 0x01,
    0x81, 0x42, 0x75, 0x02, 0x95, 0x01, 0x81, 0x03, 0x75, 0x08, 0x95, 0x02, 0x81, 0x03, 0xc0,
];

impl Key {
    fn owned(&self) -> Result<bool> {
        Ok(self.get("RustClientOwner")? == Some((REG_SZ, utf16_bytes(OWNER))))
    }

    fn companion_id(&self) -> Result<Option<String>> {
        let Some((kind, bytes)) = self.get("CompanionInstanceId")? else {
            return Ok(None);
        };
        if kind != REG_SZ || bytes.len() % 2 != 0 || !bytes.ends_with(&[0, 0]) {
            return Err(io::Error::other("invalid recorded companion identity"));
        }
        let chars: Vec<_> = bytes[..bytes.len() - 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        let id = String::from_utf16(&chars).map_err(io::Error::other)?;
        if id.is_empty() || id.contains('\0') {
            return Err(io::Error::other("empty recorded companion identity"));
        }
        Ok(Some(id))
    }
}

fn configuration() -> BTreeMap<String, (u32, Vec<u8>)> {
    let mut values = BTreeMap::new();
    for (name, text) in [
        ("RustClientOwner", OWNER),
        ("ProductString", NAME),
        ("DeviceDescription", NAME),
    ] {
        values.insert(name.into(), (REG_SZ, utf16_bytes(text)));
    }
    for (name, value) in [
        ("FunctionMode", 1u32),
        ("VendorId", 0x045e),
        ("ProductId", 0x028e),
        ("VersionNumber", 0x0100),
        ("Bluetooth", 0),
        ("InputReportByteLength", 18),
        ("XusbCompanion", 1),
    ] {
        values.insert(name.into(), (REG_DWORD, value.to_le_bytes().to_vec()));
    }
    // The descriptor declares no report ID; the length is 18 bytes.
    let report_id = [&[0], &18u32.to_le_bytes()[..], &DESCRIPTOR].concat();
    // An empty table: format 4 header with no answers (FeatureStubTable.EmptyBlob).
    let feature_answers = [&16u32.to_le_bytes()[..], &4u32.to_le_bytes(), &[0; 8]].concat();
    for (name, bytes) in [
        ("ReportDescriptor", DESCRIPTOR.to_vec()),
        ("InputReportId", report_id),
        ("FeatureAnswers", feature_answers),
        ("CachedInputReportIds", Vec::new()),
        ("XusbAnswers", xusb_answers()),
    ] {
        values.insert(name.into(), (REG_BINARY, bytes));
    }
    values
}

fn identity_entry() -> BTreeMap<String, (u32, Vec<u8>)> {
    BTreeMap::from([(
        "ControllerIndex".into(),
        (REG_DWORD, 0u32.to_le_bytes().to_vec()),
    )])
}

/// The configuration a client built for HIDMaestro v1.12.0 left behind.
fn legacy_configuration() -> BTreeMap<String, (u32, Vec<u8>)> {
    let mut values = configuration();
    for name in [
        "XusbCompanion",
        "InputReportId",
        "FeatureAnswers",
        "CachedInputReportIds",
        "XusbAnswers",
    ] {
        values.remove(name);
    }
    values.insert("DeviceInstanceId".into(), (REG_SZ, utf16_bytes(ROOT_ID)));
    values
}

/// The XUSB companion's IOCTL answers for a wired Xbox 360 pad on index 0.
///
/// HIDMaestro v2.0.0 profiles/models/xusb-companion.json with its defaults
/// (gamepad subtype, voice and PMD flags, wired full battery) and 045E:028E
/// substituted, laid out as XusbAnswers.Build: a header of length, format 4
/// and count, 12-byte entries of IOCTL, minimum output, mode, arena offset
/// and size, then the arena.
fn xusb_answers() -> Vec<u8> {
    const EXACT: u16 = 0;
    const UP_TO: u16 = 1;
    let mut information_ex = [0u8; 64];
    information_ex[..12].copy_from_slice(&[3, 1, 1, 1, 0, 0, 0, 0, 0x5e, 0x04, 0x8e, 0x02]);
    let answers: [(u32, u16, u16, &[u8]); 5] = [
        (
            0x8000_6000,
            0,
            EXACT,
            &[3, 1, 1, 0, 0, 0, 0, 0, 0x5e, 0x04, 0x8e, 0x02],
        ),
        (
            0x8000_e004,
            0,
            EXACT,
            &[
                3, 1, 0, 1, 0xff, 0xf7, 0xff, 0xff, 0xc0, 0xff, 0xc0, 0xff, 0xc0, 0xff, 0xc0, 0xff,
                0xff, 0xff, 0xff, 0xff, 0, 0, 0xff, 0xff,
            ],
        ),
        (
            0x8000_e004,
            36,
            EXACT,
            &[
                3, 1, 1, 1, 0x0c, 0, 0x5e, 0x04, 0x8e, 0x02, 0x10, 0x01, 0, 0xfa, 0x34, 0x22, 0xff,
                0xf7, 0xff, 0xff, 0xc0, 0xff, 0xc0, 0xff, 0xc0, 0xff, 0xc0, 0xff, 0xff, 0xff, 0xff,
                0xff, 0, 0, 0xff, 0xff,
            ],
        ),
        (0x8000_e018, 0, EXACT, &[0, 0, 1, 3]),
        (0x8000_e3fc, 0, UP_TO, &information_ex),
    ];
    let arena_start = 12 + 12 * answers.len();
    let length = arena_start + answers.iter().map(|a| a.3.len()).sum::<usize>();
    let mut blob = Vec::with_capacity(length);
    for value in [length as u32, 4, answers.len() as u32] {
        blob.extend_from_slice(&value.to_le_bytes());
    }
    let mut offset = 0;
    for (code, min_output, mode, data) in answers {
        blob.extend_from_slice(&code.to_le_bytes());
        for value in [min_output, mode, offset, data.len() as u16] {
            blob.extend_from_slice(&value.to_le_bytes());
        }
        offset += data.len() as u16;
    }
    for (.., data) in answers {
        blob.extend_from_slice(data);
    }
    blob
}

fn transport_retained() -> Result<bool> {
    // XInput caches file handles; observing removal releases this process's cache.
    sys::poll_xinput();
    for name in [
        "Input",
        "Output",
        "InputAck",
        "InputEvent",
        "CompanionInputEvent",
        "OutputEvent",
        "InputAckEvent",
        "RemoveEvent",
        "RemovedEvent",
        "Version",
    ] {
        let name = format!("Global\\HIDMaestro{name}0");
        let open = if name.ends_with("Event0") {
            Event::open(&name, EVENT_MODIFY_STATE)?.is_some()
        } else {
            Mapping::open(&name)?.is_some()
        };
        if open {
            return Ok(true);
        }
    }
    Ok(false)
}

fn present(id: &str) -> bool {
    DevNode::locate(id, CM_LOCATE_DEVNODE_NORMAL).is_ok()
}

fn absent(id: &str) -> bool {
    DevNode::locate(id, CM_LOCATE_DEVNODE_PHANTOM).err() == Some(CR_NO_SUCH_DEVNODE)
}

fn wait_for(mut ready: impl FnMut() -> bool, what: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ready() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, what.to_owned()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn companion_ready(id: &str) -> bool {
    DevNode::locate(id, 0).is_ok_and(DevNode::started) && interface(&XUSB_INTERFACE, id).is_some()
}

fn verify_bound(id: &str, expected_inf: &std::path::Path) -> Result<()> {
    let set = DeviceSet::new()?;
    let data = set.open(id)?;
    let (_, buffer) = data.property(SPDRP_DRIVER)?;
    let path = String::from_utf16(
        &buffer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .take_while(|c| *c != 0)
            .collect::<Vec<_>>(),
    )
    .map_err(io::Error::other)?;
    let key = Key::open(&format!(r"SYSTEM\CurrentControlSet\Control\Class\{path}"))?
        .ok_or_else(|| io::Error::other("bound driver key is missing"))?;
    let expected = utf16_bytes(&expected_inf.file_name().unwrap().to_string_lossy());
    if key.get("InfPath")? != Some((REG_SZ, expected)) {
        return Err(io::Error::other(format!(
            "{id} bound to an unexpected driver package"
        )));
    }
    Ok(())
}

fn remove_root(transport: Option<&Transport>) -> Result<()> {
    remove_node(ROOT_ID, HARDWARE, transport)
}

fn remove_node(id: &str, hardware_ids: &str, transport: Option<&Transport>) -> Result<()> {
    let set = DeviceSet::new()?;
    let data = match set.open(id) {
        Ok(d) => d,
        Err(e) if absent(id) && e.raw_os_error() == Some(0xe000020b_u32 as i32) => {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let (kind, hardware) = data.property(SPDRP_HARDWAREID)?;
    if kind != REG_MULTI_SZ || hardware != utf16_bytes(hardware_ids) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root identity is not owned by this client",
        ));
    }
    let mut children = Vec::new();
    let mut next = data.node().child();
    while let Ok(child) = next {
        let id = child
            .id()
            .map_err(|rc| io::Error::other(format!("read child identity: {rc:#x}")))?;
        children.push(id);
        next = child.sibling();
    }
    if let Err(rc) = next
        && rc != CR_NO_SUCH_DEVNODE
    {
        return Err(io::Error::other(format!(
            "enumerate owned children: {rc:#x}"
        )));
    }
    if let Some(transport) = transport
        && present(id)
    {
        // Watchers close their handles on a removal query. When a holder
        // refuses, DIF_REMOVE would leave the HID child's record without its
        // driver; the driver instead fails the device as an unplug does.
        let removed = data.node().query_and_remove();
        #[cfg(test)]
        tests::QUERY_REMOVED.set(Some(removed));
        if !removed {
            let _ejected = transport.eject();
            #[cfg(test)]
            tests::EJECTED.set(_ejected);
        }
    }
    for child in children {
        if !absent(&child) {
            // An ejected device's children can leave between the check and the open.
            match set.open(&child) {
                Ok(data) => data.call_class_installer(DIF_REMOVE)?,
                Err(_) if absent(&child) => {}
                Err(e) => return Err(e),
            }
        }
        wait_for(|| absent(&child), "owned child removal")?;
    }
    data.call_class_installer(DIF_REMOVE)?;
    wait_for(|| absent(id), "device removal")
}

fn elevated() -> Result<()> {
    if !sys::elevated()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run the client as administrator",
        ));
    }
    Ok(())
}

fn recover() -> Result<bool> {
    let journal = Key::open(JOURNAL)?;
    let recorded = if let Some(key) = &journal {
        if !key.owned()? {
            return Err(io::Error::other("foreign recovery journal"));
        }
        let id = key.companion_id()?;
        let mut expected =
            BTreeMap::from([("RustClientOwner".into(), (REG_SZ, utf16_bytes(OWNER)))]);
        if let Some(id) = &id {
            expected.insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
        }
        if key.snapshot()? != expected {
            return Err(io::Error::other("recovery journal was modified"));
        }
        id
    } else {
        None
    };
    let identity = Key::open(IDENTITY)?;
    if let Some(key) = &identity {
        if journal.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "identity entry has no ownership record",
            ));
        }
        if key.snapshot()? != identity_entry() {
            return Err(io::Error::other(
                "identity entry was modified; preserving it",
            ));
        }
    }
    if let Some(key) = Key::open(CONFIG)? {
        if !key.owned()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Controller0 belongs to another client",
            ));
        }
        if !recoverable(&key.snapshot()?, recorded.as_deref()) {
            return Err(io::Error::other(
                "configuration was modified; preserving it",
            ));
        }
        drop(key);
        if recorded.as_deref().is_some_and(present) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "XUSB instance still has an owner",
            ));
        }
        remove_root(None)?;
        if let Some(id) = &recorded {
            remove_node(id, SWD_HARDWARE, None)?;
        }
        Key::delete_tree(CONFIG)?;
    }
    if let Some(key) = &journal {
        if recorded.as_deref().is_some_and(present) {
            return Err(io::Error::other("recorded companion is still present"));
        }
        remove_root(None)?;
        if let Some(id) = &recorded {
            remove_node(id, SWD_HARDWARE, None)?;
            key.delete_value("CompanionInstanceId")?;
        }
    }
    if identity.is_some() {
        drop(identity);
        Key::delete_tree(IDENTITY)?;
    }
    if !absent(ROOT_ID) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "root device has no ownership record",
        ));
    }
    Ok(journal.is_some())
}

/// Creation records the companion in the journal before the configuration, so a
/// configuration without it is an interrupted creation rather than a foreign edit.
fn recoverable(config: &BTreeMap<String, (u32, Vec<u8>)>, recorded: Option<&str>) -> bool {
    [configuration(), legacy_configuration()]
        .into_iter()
        .any(|expected| {
            let Some(id) = recorded else {
                return *config == expected;
            };
            let mut with_id = expected.clone();
            with_id.insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
            *config == with_id || *config == expected
        })
}

fn driver_inf(xusb: bool) -> Result<std::path::PathBuf> {
    let directory = std::path::PathBuf::from(
        std::env::var_os("SystemRoot").ok_or_else(|| io::Error::other("SystemRoot is missing"))?,
    )
    .join("INF");
    for entry in std::fs::read_dir(directory)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
        if !name.starts_with("oem") || !name.ends_with(".inf") {
            continue;
        }
        // Another vendor's locked or broken INF says nothing about these packages.
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let content = if bytes.starts_with(&[0xff, 0xfe]) {
            String::from_utf16_lossy(
                &bytes[2..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let compact = content.to_lowercase().replace([' ', '\t', '\r'], "");
        let binary = if xusb {
            "hmxinput.dll"
        } else {
            "hidmaestro.dll"
        };
        if compact.contains("driverver=10/19/2026,2.0.0.2201")
            && compact.contains(binary)
            && compact.contains("hidmaestro")
        {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "install HIDMaestro v2.0.0 driver packages first",
    ))
}

fn create_companion() -> Result<SoftwareDevice> {
    SoftwareDevice::create(&Description {
        enumerator: "HIDMAESTRO",
        parent: r"HTREE\ROOT\0",
        instance: TOKEN,
        hardware_ids: SWD_HARDWARE,
        compatible_ids: "USB\\MS_COMP_XUSB10\0USB\\Class_FF&SubClass_5D&Prot_01\0USB\\Class_FF&SubClass_5D\0USB\\Class_FF\0",
        container: CONTAINER,
        description: NAME,
    })
}

pub(crate) struct Backend {
    companion: Option<SoftwareDevice>,
    root: bool,
    config: bool,
    identity: bool,
    transport: Option<Transport>,
    lease: Option<OwnedHandle>,
    expected: BTreeMap<String, (u32, Vec<u8>)>,
    companion_id: Option<String>,
    journal: bool,
}

impl Backend {
    pub fn create() -> Result<Self> {
        elevated()?;
        let inf = driver_inf(false)?;
        let companion_inf = driver_inf(true)?;
        let transport = Transport::create_with(identity_tag(TOKEN), recover)?;
        let mut this = Self {
            companion: None,
            root: false,
            config: false,
            identity: false,
            transport: Some(transport),
            lease: None,
            expected: BTreeMap::new(),
            companion_id: None,
            journal: false,
        };
        let setup = (|| {
            if DevNode::locate(ROOT_ID, CM_LOCATE_DEVNODE_PHANTOM).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "root device already exists without ownership record",
                ));
            }
            let key = Key::create(CONFIG)?;
            this.config = true;
            for (name, (kind, bytes)) in configuration() {
                key.set(&name, kind, &bytes)?;
                this.expected.insert(name, (kind, bytes));
            }
            drop(key);
            let journal = match Key::open(JOURNAL)? {
                Some(key) => key,
                None => Key::create(JOURNAL)?,
            };
            this.journal = true;
            journal.text("RustClientOwner", OWNER)?;
            drop(journal);
            let identity = Key::create(IDENTITY)?;
            this.identity = true;
            for (name, (kind, bytes)) in identity_entry() {
                identity.set(&name, kind, &bytes)?;
            }
            drop(identity);
            this.submit(&State::default())?;
            this.create_root(&inf)
                .map_err(|e| io::Error::new(e.kind(), format!("HID setup: {e}")))?;
            #[cfg(test)]
            if tests::FAIL_AFTER_HID.get() {
                return Err(io::Error::other("injected failure after HID registration"));
            }
            this.companion = Some(
                create_companion()
                    .map_err(|e| io::Error::new(e.kind(), format!("XUSB setup: {e}")))?,
            );
            let id = this.companion.as_ref().unwrap().id();
            this.companion_id = Some(id.to_owned());
            Key::open(JOURNAL)?
                .ok_or_else(|| io::Error::other("recovery journal disappeared"))?
                .text("CompanionInstanceId", id)?;
            Key::open(CONFIG)?
                .ok_or_else(|| io::Error::other("configuration disappeared"))?
                .text("CompanionInstanceId", id)?;
            this.expected
                .insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
            let transport = this
                .transport
                .as_ref()
                .ok_or_else(|| io::Error::other("controller is closed"))?;
            // A companion that failed its start names the value it could not read.
            let started = wait_for(|| companion_ready(id), "XUSB interface start");
            transport.check_companion()?;
            started?;
            verify_bound(id, &companion_inf)?;
            verify_bound(ROOT_ID, &inf)?;
            Ok(())
        })();
        if let Err(error) = setup {
            if let Err(cleanup) = this.cleanup() {
                return Err(io::Error::other(format!(
                    "setup: {error}; rollback: {cleanup}"
                )));
            }
            return Err(error);
        }
        Ok(this)
    }

    fn create_root(&mut self, inf: &std::path::Path) -> Result<()> {
        let set = DeviceSet::new()?;
        let mut data = set.create(ROOT_ID, &HID_CLASS, NAME)?;
        for (property, value) in [
            (SPDRP_HARDWAREID, HARDWARE),
            (
                SPDRP_COMPATIBLEIDS,
                "USB\\MS_COMP_XUSB10\0USB\\Class_FF&SubClass_5D&Prot_01\0",
            ),
            (SPDRP_UPPERFILTERS, "xinputhid\0"),
        ] {
            data.set_property(property, &utf16_bytes(value))?;
        }
        data.call_class_installer(DIF_REGISTERDEVICE)?;
        self.root = true;
        let parameters = Key::create(&format!(
            r"SYSTEM\CurrentControlSet\Enum\{ROOT_ID}\Device Parameters"
        ));
        match parameters {
            Ok(key) => key.dword("ControllerIndex", 0)?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Key::open(&format!(
                r"SYSTEM\CurrentControlSet\Enum\{ROOT_ID}\Device Parameters"
            ))?
            .ok_or(e)?
            .dword("ControllerIndex", 0)?,
            Err(e) => return Err(e),
        }
        if data.install(inf)? {
            return Err(io::Error::other(
                "Windows requires a restart to start the HID device",
            ));
        }
        let started = wait_for(
            || data.node().child().is_ok_and(DevNode::started),
            "HID child start",
        );
        // The driver writes its half at add, before HID class creates the child.
        self.transport
            .as_ref()
            .ok_or_else(|| io::Error::other("controller is closed"))?
            .check_driver()?;
        started
    }

    pub fn submit(&mut self, state: &State) -> Result<()> {
        let frame = report::encode(state)?;
        self.transport
            .as_mut()
            .ok_or_else(|| io::Error::other("controller is closed"))?
            .publish(&frame)
    }
    pub fn take_writer(&mut self) -> Result<super::Writer> {
        self.transport
            .as_mut()
            .ok_or_else(|| io::Error::other("controller is closed"))?
            .take_writer()
    }
    fn cleanup(&mut self) -> Result<()> {
        let mut error = if let Some(transport) = self.transport.as_mut() {
            transport.neutral().err()
        } else {
            None
        };
        drop(self.companion.take());
        if let Some(id) = self.companion_id.as_deref() {
            if let Err(e) = wait_for(|| !present(id), "XUSB removal") {
                error.get_or_insert(e);
            }
            if !present(id)
                && let Err(e) = remove_node(id, SWD_HARDWARE, None)
            {
                error.get_or_insert(e);
            }
        }
        if self.root {
            match remove_root(self.transport.as_ref()) {
                Ok(()) => self.root = false,
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        let companion_gone = self.companion_id.as_deref().is_none_or(absent);
        if !self.root
            && companion_gone
            && let Some(transport) = self.transport.take()
        {
            self.lease = Some(transport.release());
        }
        let retained = if self.lease.is_some() {
            match transport_retained() {
                Ok(retained) => retained,
                Err(e) => {
                    error.get_or_insert(e);
                    true
                }
            }
        } else {
            false
        };
        if self.identity && !self.root && companion_gone && error.is_none() {
            let result = (|| {
                if let Some(key) = Key::open(IDENTITY)? {
                    if key.snapshot()? != identity_entry() {
                        return Err(io::Error::other("identity entry changed; preserving it"));
                    }
                    drop(key);
                    Key::delete_tree(IDENTITY)?;
                }
                Ok(())
            })();
            match result {
                Ok(()) => self.identity = false,
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        if self.config && !self.root && companion_gone && error.is_none() {
            let result = (|| {
                if let Some(key) = Key::open(CONFIG)? {
                    if key.snapshot()? != self.expected {
                        return Err(io::Error::other(
                            "configuration ownership changed; preserving it",
                        ));
                    }
                    drop(key);
                    Key::delete_tree(CONFIG)?;
                }
                Ok(())
            })();
            match result {
                Ok(()) => self.config = false,
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        if self.journal && !self.config && !self.identity && !self.root && companion_gone {
            let result = (|| {
                let Some(key) = Key::open(JOURNAL)? else {
                    return Ok(false);
                };
                let recorded = key.companion_id()?;
                // Setup may fail before recording its companion, never with another one.
                if !key.owned()? || recorded.is_some() && recorded != self.companion_id {
                    return Err(io::Error::other("journal ownership changed; preserving it"));
                }
                drop(key);
                if !retained {
                    Key::delete_tree(JOURNAL)?;
                }
                Ok(true)
            })();
            match result {
                Ok(true) => self.journal = false,
                Ok(false) => {}
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        if !self.config && !self.identity && !self.journal && !self.root && companion_gone {
            self.lease.take();
        }
        if let Some(e) = error { Err(e) } else { Ok(()) }
    }
    pub fn close(mut self) -> Result<()> {
        self.cleanup()
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        if self.transport.is_some()
            || self.lease.is_some()
            || self.root
            || self.config
            || self.identity
            || self.journal
        {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static FAIL_AFTER_HID: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static EJECTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static QUERY_REMOVED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    fn hid_child_interface() -> Vec<u16> {
        let guid = GUID::from_u128(0x4d1e55b2_f16f_11cf_88cb_001111000030);
        let child = DevNode::locate(ROOT_ID, 0).unwrap().child().unwrap();
        interface(&guid, &child.id().unwrap()).expect("HID child has no interface")
    }

    #[test]
    #[ignore = "explicit elevated test removes a HID device another handle holds open"]
    fn close_ejects_a_held_hid_child() {
        let controller = Backend::create().unwrap();
        // A handle with no read pending and no PnP notification refuses the
        // removal query, as Steam's does with PlayStation pads.
        let held = sys::open_device(&hid_child_interface()).unwrap();
        // The holder lets go only once the parent has left the device tree,
        // which a removal query cannot achieve while the handle is open.
        let holder = std::thread::spawn(move || {
            let begin = Instant::now();
            while present(ROOT_ID) && begin.elapsed() < Duration::from_secs(40) {
                std::thread::sleep(Duration::from_millis(50));
            }
            drop(held);
            begin.elapsed()
        });
        EJECTED.set(false);
        QUERY_REMOVED.set(None);
        let begin = Instant::now();
        let closed = controller.close();
        let took = begin.elapsed();
        let held_for = holder.join().unwrap();
        println!(
            "query removed: {:?}; ejected: {}; close: {closed:?} in {took:?}; handle held {held_for:?}",
            QUERY_REMOVED.get(),
            EJECTED.get()
        );
        assert_eq!(
            QUERY_REMOVED.get(),
            Some(false),
            "the holder did not refuse"
        );
        assert!(
            EJECTED.get(),
            "the driver did not answer the removal request"
        );
        closed.unwrap();
        assert!(!present(ROOT_ID));
        // The removal left the identity whole: a new HID child starts on it.
        let again = Backend::create().unwrap();
        hid_child_interface();
        again.close().unwrap();
    }

    #[test]
    fn devnodes_carry_the_identity_token() {
        assert_eq!(ROOT_ID.rsplit('\\').next(), Some(TOKEN));
        assert_eq!(SWD_ID.rsplit('\\').next(), Some(TOKEN));
        assert!(IDENTITY.ends_with(&format!(r"\{TOKEN}")));
    }

    #[test]
    fn xusb_answers_parse_as_companion_loads_them() {
        let blob = xusb_answers();
        let word = |at: usize| u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
        let half = |at: usize| u16::from_le_bytes([blob[at], blob[at + 1]]) as usize;
        assert_eq!(word(0) as usize, blob.len());
        assert!(blob.len() <= 512);
        assert_eq!(word(4), 4);
        let count = word(8) as usize;
        assert!(count <= 8);
        let arena = 12 + 12 * count;
        let mut answers = Vec::new();
        for entry in (12..arena).step_by(12) {
            let (mode, offset, size) = (half(entry + 6), half(entry + 8), half(entry + 10));
            assert!(mode <= 1 && size <= 64 && arena + offset + size <= blob.len());
            answers.push((
                word(entry),
                half(entry + 4),
                &blob[arena + offset..][..size],
            ));
        }
        let capabilities = answers
            .iter()
            .find(|a| a.0 == 0x8000_e004 && a.1 == 36)
            .unwrap()
            .2;
        assert_eq!(capabilities.len(), 36);
        assert_eq!(capabilities[3], 1);
        assert_eq!(&capabilities[4..10], &[0x0c, 0, 0x5e, 0x04, 0x8e, 0x02]);
        assert_eq!(capabilities[12], 0);
        let battery = answers.iter().find(|a| a.0 == 0x8000_e018).unwrap().2;
        assert_eq!(battery, &[0, 0, 1, 3]);
    }

    #[test]
    fn contract_values_match_driver_limits() {
        let config = configuration();
        assert!(!config.contains_key("DeviceInstanceId"));
        let (kind, report_id) = &config["InputReportId"];
        assert_eq!(*kind, REG_BINARY);
        assert_eq!(report_id.len(), 5 + DESCRIPTOR.len());
        assert_eq!(&report_id[..5], &[0, 18, 0, 0, 0]);
        let (_, features) = &config["FeatureAnswers"];
        assert_eq!(features.len(), 16);
        assert_eq!(&features[..8], &[16, 0, 0, 0, 4, 0, 0, 0]);
        assert_eq!(config["CachedInputReportIds"], (REG_BINARY, Vec::new()));
    }

    #[test]
    fn legacy_configuration_is_recoverable() {
        let id = r"SWD\HIDMAESTRO\HM_RUST_CLIENT_0";
        let mut legacy = legacy_configuration();
        assert!(recoverable(&legacy, None));
        legacy.insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
        assert!(recoverable(&legacy, Some(id)));
        let mut mixed = configuration();
        mixed.insert("DeviceInstanceId".into(), (REG_SZ, utf16_bytes(ROOT_ID)));
        assert!(!recoverable(&mixed, None));
    }

    #[test]
    fn interrupted_companion_record_is_recoverable() {
        let id = r"SWD\HIDMAESTRO\HM_RUST_CLIENT_0";
        let bare = configuration();
        let mut recorded = bare.clone();
        recorded.insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
        assert!(recoverable(&bare, None));
        assert!(recoverable(&recorded, Some(id)));
        assert!(recoverable(&bare, Some(id)));
        assert!(!recoverable(&recorded, None));
        assert!(!recoverable(&recorded, Some("other")));
        let mut foreign = bare;
        foreign.insert("ProductId".into(), (REG_DWORD, 1u32.to_le_bytes().to_vec()));
        assert!(!recoverable(&foreign, Some(id)));
    }

    #[test]
    #[ignore = "explicit elevated test retains a mapping across controller sessions"]
    fn retained_transport_is_reused_after_close() {
        let mut backend = Backend::create().unwrap();
        let held = Mapping::open("Global\\HIDMaestroInput0").unwrap().unwrap();
        backend.cleanup().unwrap();
        assert!(backend.transport.is_none());
        assert!(Key::open(CONFIG).unwrap().is_none());
        assert!(Key::open(JOURNAL).unwrap().is_some());
        let next = Backend::create().unwrap();
        drop(backend);
        assert!(Backend::create().is_err());
        next.close().unwrap();
        drop(held);
        Backend::create().unwrap().close().unwrap();
    }

    #[test]
    #[ignore = "explicit elevated test removes devices with an external XInput client"]
    fn close_with_external_xinput_client() {
        use std::os::windows::io::AsHandle;
        use windows_sys::Win32::System::Threading::SYNCHRONIZATION_SYNCHRONIZE;
        let name = format!("Local\\HIDMaestroObserver{}", std::process::id());
        if let Ok(parent) = std::env::var("HIDMAESTRO_OBSERVER_PARENT") {
            let event = Event::open(
                &format!("Local\\HIDMaestroObserver{parent}"),
                EVENT_MODIFY_STATE,
            )
            .unwrap()
            .unwrap();
            let resume = Event::open(
                &format!("Local\\HIDMaestroObserver{parent}Resume"),
                SYNCHRONIZATION_SYNCHRONIZE,
            )
            .unwrap()
            .unwrap();
            let id = std::env::var("HIDMAESTRO_OBSERVER_DEVICE").unwrap();
            let path = interface(&XUSB_INTERFACE, &id).unwrap();
            let old = sys::open_device(&path).unwrap();
            let mut bytes = [0u8; 29];
            sys::ioctl(old.as_handle(), 0x8000e00c, &[], &mut bytes).unwrap();
            assert_eq!(u16::from_le_bytes([bytes[11], bytes[12]]), 0x1000);
            sys::poll_xinput();
            event.set().unwrap();
            assert!(resume.wait(30_000).unwrap());
            for code in [0x8000e00c, 0x8000a010] {
                let input = bytes;
                assert!(
                    sys::ioctl(old.as_handle(), code, &input, &mut bytes).is_err(),
                    "removed XUSB handle still accepts IOCTL {code:#x}"
                );
            }
            drop(old);
            wait_for(
                || (0..4).any(|slot| sys::xinput_buttons(slot) == Some(0x2000)),
                "recreated controller B press",
            )
            .unwrap();
            return;
        }
        for _ in 0..3 {
            let (ready, _) = Event::create(&name, None, true).unwrap();
            let (resume, _) = Event::create(&format!("{name}Resume"), None, true).unwrap();
            let mut controller = Backend::create().unwrap();
            controller
                .submit(&State {
                    buttons: crate::Buttons::A,
                    ..State::default()
                })
                .unwrap();
            let mut observer = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows::device::tests::close_with_external_xinput_client",
                    "--ignored",
                    "--nocapture",
                ])
                .env("HIDMAESTRO_OBSERVER_PARENT", std::process::id().to_string())
                .env(
                    "HIDMAESTRO_OBSERVER_DEVICE",
                    controller.companion_id.as_ref().unwrap(),
                )
                .spawn()
                .unwrap();
            let result = (|| -> Result<()> {
                if !ready.wait(5000)? {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "external observer startup",
                    ));
                }
                controller.close()?;
                let mut recreated = Backend::create()?;
                recreated.submit(&State {
                    buttons: crate::Buttons::B,
                    ..State::default()
                })?;
                resume.set()?;
                if !sys::wait(observer.as_handle(), 20_000)? {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "external observer checks",
                    ));
                }
                if !observer.wait()?.success() {
                    return Err(io::Error::other("external observer failed"));
                }
                recreated.close()
            })();
            let _ = observer.kill();
            let _ = observer.wait();
            result.unwrap();
        }
    }

    #[test]
    #[ignore = "explicit elevated test creates and removes HID/XUSB devices"]
    fn lifecycle_rollback_and_recreate() {
        FAIL_AFTER_HID.set(true);
        let failed = Backend::create();
        FAIL_AFTER_HID.set(false);
        assert!(failed.is_err());
        assert!(!present(ROOT_ID));
        assert!(Key::open(CONFIG).unwrap().is_none());
        let controller = Backend::create().unwrap();
        assert!(present(ROOT_ID));
        sys::poll_xinput();
        assert!(Backend::create().is_err());
        controller.close().unwrap();
        assert!(!present(ROOT_ID));
        assert!(DevNode::locate(SWD_ID, CM_LOCATE_DEVNODE_PHANTOM).is_err());
        drop(Backend::create().unwrap());
        assert!(!present(ROOT_ID));
    }

    #[test]
    #[ignore = "explicit elevated test temporarily reserves Controller0"]
    fn foreign_configuration_is_preserved() {
        assert!(Key::open(CONFIG).unwrap().is_none());
        let key = Key::create(CONFIG).unwrap();
        key.text("ForeignSentinel", "keep me").unwrap();
        let result = Backend::create();
        let sentinel = key.get("ForeignSentinel").unwrap();
        drop(key);
        Key::delete_tree(CONFIG).unwrap();
        assert!(result.is_err());
        assert_eq!(sentinel, Some((REG_SZ, utf16_bytes("keep me"))));
        assert!(!present(ROOT_ID));
    }

    #[test]
    #[ignore = "explicit elevated test changes this client's configuration"]
    fn changed_configuration_is_preserved_on_close() {
        let controller = Backend::create().unwrap();
        let key = Key::open(CONFIG).unwrap().unwrap();
        key.text("OtherProgram", "preserve").unwrap();
        let result = controller.close();
        let preserved = key.get("OtherProgram").unwrap();
        drop(key);
        Key::delete_tree(CONFIG).unwrap();
        assert!(result.is_err());
        assert_eq!(preserved, Some((REG_SZ, utf16_bytes("preserve"))));
        assert!(!present(ROOT_ID));
    }

    #[test]
    #[ignore = "explicit elevated test recovers this client's crash residue"]
    fn recover_owned_root_after_lost_process_handles() {
        let mut old = Backend::create().unwrap();
        old.companion.take();
        wait_for(|| !present(SWD_ID), "XUSB close").unwrap();
        old.transport.take();
        old.root = false;
        old.config = false;
        old.identity = false;
        old.journal = false;
        drop(old);
        let recovered = Backend::create();
        if recovered.is_err() {
            remove_root(None).unwrap();
            Key::delete_tree(CONFIG).unwrap();
        }
        assert!(recovered.is_ok(), "{:#?}", recovered.err());
    }

    #[test]
    #[ignore = "explicit elevated recovery test preserves an altered companion ID"]
    fn modified_companion_record_is_preserved() {
        let mut old = Backend::create().unwrap();
        let id = old.companion.as_ref().unwrap().id().to_owned();
        old.companion.take();
        wait_for(|| !present(&id), "XUSB close").unwrap();
        old.transport.take();
        old.root = false;
        old.config = false;
        old.identity = false;
        old.journal = false;
        drop(old);
        let key = Key::open(CONFIG).unwrap().unwrap();
        key.dword("CompanionInstanceId", 123).unwrap();
        let result = Backend::create();
        let preserved = key.get("CompanionInstanceId");
        drop(result);
        if let Some(key) = Key::open(CONFIG).unwrap() {
            key.text("CompanionInstanceId", &id).unwrap();
        }
        drop(Backend::create().unwrap());
        assert_eq!(
            preserved.unwrap(),
            Some((REG_DWORD, 123u32.to_le_bytes().to_vec()))
        );
    }
}
