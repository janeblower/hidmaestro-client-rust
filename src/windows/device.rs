use super::{Handle, check, transport::Transport, wide};
use crate::{Result, State, report};
use std::{
    collections::BTreeMap,
    io,
    mem::size_of,
    ptr,
    sync::mpsc,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Devices::{DeviceAndDriverInstallation::*, Enumeration::Pnp::*},
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, INVALID_HANDLE_VALUE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::{
            Registry::*,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
    core::GUID,
};

const CONFIG: &str = r"SOFTWARE\HIDMaestro\Controller0";
const JOURNAL: &str = r"SOFTWARE\HIDMaestroRustClient\Controller0";
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

fn status(code: u32) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

struct Key(HKEY);
impl Key {
    fn snapshot(&self) -> Result<BTreeMap<String, (u32, Vec<u8>)>> {
        let mut subkeys = 0;
        status(unsafe {
            RegQueryInfoKeyW(
                self.0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                &mut subkeys,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })?;
        if subkeys != 0 {
            return Err(io::Error::other(
                "configuration has unexpected subkeys; preserving it",
            ));
        }
        let mut values = BTreeMap::new();
        for index in 0.. {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            let rc = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc == windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS {
                break;
            }
            status(rc)?;
            let name = String::from_utf16(&name[..len as usize]).map_err(io::Error::other)?;
            values.insert(
                name.clone(),
                self.get(&name)?
                    .ok_or_else(|| io::Error::other("configuration changed during read"))?,
            );
        }
        Ok(values)
    }
    fn open(path: &str) -> Result<Option<Self>> {
        let mut key = ptr::null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(path).as_ptr(),
                0,
                KEY_READ | KEY_WRITE,
                &mut key,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        status(rc)?;
        Ok(Some(Self(key)))
    }
    fn create(path: &str) -> Result<Self> {
        let mut key = ptr::null_mut();
        let mut disposition = 0;
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(path).as_ptr(),
                0,
                ptr::null(),
                0,
                KEY_READ | KEY_WRITE,
                ptr::null(),
                &mut key,
                &mut disposition,
            )
        };
        status(rc)?;
        let key = Self(key);
        if disposition != REG_CREATED_NEW_KEY {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                path.to_owned(),
            ));
        }
        Ok(key)
    }
    fn set(&self, name: &str, kind: u32, bytes: &[u8]) -> Result<()> {
        status(unsafe {
            RegSetValueExW(
                self.0,
                wide(name).as_ptr(),
                0,
                kind,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        })
    }
    fn text(&self, name: &str, value: &str) -> Result<()> {
        self.set(name, REG_SZ, &utf16_bytes(value))
    }
    fn dword(&self, name: &str, value: u32) -> Result<()> {
        self.set(name, REG_DWORD, &value.to_le_bytes())
    }
    fn get(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
        let mut size = 0;
        let mut kind = 0;
        let rc = unsafe {
            RegQueryValueExW(
                self.0,
                wide(name).as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        status(rc)?;
        let mut bytes = vec![0; size as usize];
        status(unsafe {
            RegQueryValueExW(
                self.0,
                wide(name).as_ptr(),
                ptr::null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        })?;
        bytes.truncate(size as usize);
        Ok(Some((kind, bytes)))
    }
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
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn utf16_bytes(value: &str) -> Vec<u8> {
    wide(value).into_iter().flat_map(u16::to_le_bytes).collect()
}

fn configuration() -> BTreeMap<String, (u32, Vec<u8>)> {
    let mut values = BTreeMap::new();
    for (name, text) in [
        ("RustClientOwner", OWNER),
        ("DeviceInstanceId", ROOT_ID),
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
    ] {
        values.insert(name.into(), (REG_DWORD, value.to_le_bytes().to_vec()));
    }
    values.insert("ReportDescriptor".into(), (REG_BINARY, DESCRIPTOR.to_vec()));
    values
}

fn transport_retained() -> Result<bool> {
    // XInput caches file handles; observing removal releases this process's cache.
    for slot in 0..4 {
        let mut state = windows_sys::Win32::UI::Input::XboxController::XINPUT_STATE::default();
        unsafe {
            windows_sys::Win32::UI::Input::XboxController::XInputGetState(slot, &mut state);
        }
    }
    for name in [
        "Input",
        "Output",
        "InputAck",
        "InputEvent",
        "CompanionInputEvent",
        "OutputEvent",
        "InputAckEvent",
    ] {
        let is_event = name.ends_with("Event");
        let name = wide(&format!("Global\\HIDMaestro{name}0"));
        let handle = unsafe {
            if is_event {
                windows_sys::Win32::System::Threading::OpenEventW(
                    windows_sys::Win32::System::Threading::EVENT_MODIFY_STATE,
                    0,
                    name.as_ptr(),
                )
            } else {
                windows_sys::Win32::System::Memory::OpenFileMappingW(
                    windows_sys::Win32::System::Memory::FILE_MAP_READ,
                    0,
                    name.as_ptr(),
                )
            }
        };
        if !handle.is_null() {
            drop(Handle::new(handle)?);
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32) {
            return Err(error);
        }
    }
    Ok(false)
}

struct DeviceSet(HDEVINFO);
impl DeviceSet {
    fn new() -> Result<Self> {
        let h = unsafe { SetupDiCreateDeviceInfoList(ptr::null(), ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE as isize {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(h))
        }
    }
    fn open(&self, id: &str) -> Result<SP_DEVINFO_DATA> {
        let mut data = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        check(unsafe {
            SetupDiOpenDeviceInfoW(self.0, wide(id).as_ptr(), ptr::null_mut(), 0, &mut data)
        })?;
        Ok(data)
    }
}
impl Drop for DeviceSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

fn present(id: &str) -> bool {
    let mut node = 0;
    unsafe {
        CM_Locate_DevNodeW(&mut node, wide(id).as_ptr(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS
    }
}

fn absent(id: &str) -> bool {
    let mut node = 0;
    unsafe {
        CM_Locate_DevNodeW(&mut node, wide(id).as_ptr(), CM_LOCATE_DEVNODE_PHANTOM)
            == CR_NO_SUCH_DEVNODE
    }
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
    let mut node = 0;
    let mut state = 0;
    let mut problem = 0;
    let mut interface = [0u16; 4096];
    let guid = GUID::from_u128(0xec87f1e3_c13b_4100_b5f7_8b84d54260cb);
    unsafe {
        CM_Locate_DevNodeW(&mut node, wide(id).as_ptr(), 0) == CR_SUCCESS
            && CM_Get_DevNode_Status(&mut state, &mut problem, node, 0) == CR_SUCCESS
            && state & DN_STARTED != 0
            && problem == 0
            && CM_Get_Device_Interface_ListW(
                &guid,
                wide(id).as_ptr(),
                interface.as_mut_ptr(),
                interface.len() as u32,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            ) == CR_SUCCESS
            && interface[0] != 0
    }
}

fn verify_bound(id: &str, expected_inf: &std::path::Path) -> Result<()> {
    let set = DeviceSet::new()?;
    let data = set.open(id)?;
    let mut buffer = [0u8; 1024];
    let mut size = 0;
    let mut kind = 0;
    check(unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set.0,
            &data,
            SPDRP_DRIVER,
            &mut kind,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut size,
        )
    })?;
    let path = String::from_utf16(
        &buffer[..size as usize]
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

fn remove_root() -> Result<()> {
    remove_node(ROOT_ID, HARDWARE)
}

fn remove_node(id: &str, hardware_ids: &str) -> Result<()> {
    let set = DeviceSet::new()?;
    let data = match set.open(id) {
        Ok(d) => d,
        Err(e) if absent(id) && e.raw_os_error() == Some(0xe000020b_u32 as i32) => {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut hardware = [0u8; 1024];
    let mut len = 0;
    let mut kind = 0;
    check(unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set.0,
            &data,
            SPDRP_HARDWAREID,
            &mut kind,
            hardware.as_mut_ptr(),
            hardware.len() as u32,
            &mut len,
        )
    })?;
    let expected = utf16_bytes(hardware_ids);
    if kind != REG_MULTI_SZ || hardware[..len as usize] != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root identity is not owned by this client",
        ));
    }
    let mut children = Vec::new();
    let mut child = 0;
    let mut rc = unsafe { CM_Get_Child(&mut child, data.DevInst, 0) };
    while rc == CR_SUCCESS {
        let mut id = [0u16; 4096];
        let result = unsafe { CM_Get_Device_IDW(child, id.as_mut_ptr(), id.len() as u32, 0) };
        if result != CR_SUCCESS {
            return Err(io::Error::other(format!(
                "read child identity: {result:#x}"
            )));
        }
        let end = id.iter().position(|&c| c == 0).unwrap_or(id.len());
        children.push(String::from_utf16(&id[..end]).map_err(io::Error::other)?);
        let mut sibling = 0;
        rc = unsafe { CM_Get_Sibling(&mut sibling, child, 0) };
        child = sibling;
    }
    if rc != CR_NO_SUCH_DEVNODE {
        return Err(io::Error::other(format!(
            "enumerate owned children: {rc:#x}"
        )));
    }
    for child in children {
        if !absent(&child) {
            let data = set.open(&child)?;
            check(unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set.0, &data) })?;
        }
        wait_for(|| absent(&child), "owned child removal")?;
    }
    check(unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set.0, &data) })?;
    wait_for(|| absent(id), "device removal")
}

fn elevated() -> Result<()> {
    let mut token = ptr::null_mut();
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    let token = Handle::new(token)?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    check(unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    })?;
    if elevation.TokenIsElevated == 0 {
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
        remove_root()?;
        if let Some(id) = &recorded {
            remove_node(id, SWD_HARDWARE)?;
        }
        status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(CONFIG).as_ptr()) })?;
    }
    if let Some(key) = &journal {
        if recorded.as_deref().is_some_and(present) {
            return Err(io::Error::other("recorded companion is still present"));
        }
        remove_root()?;
        if let Some(id) = &recorded {
            remove_node(id, SWD_HARDWARE)?;
            status(unsafe { RegDeleteValueW(key.0, wide("CompanionInstanceId").as_ptr()) })?;
        }
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
    let expected = configuration();
    let Some(id) = recorded else {
        return *config == expected;
    };
    let mut with_id = expected.clone();
    with_id.insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
    *config == with_id || *config == expected
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
        if compact.contains("driverver=10/13/2026,1.12.0.2302")
            && compact.contains(binary)
            && compact.contains("hidmaestro")
        {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "install HIDMaestro v1.12.0 driver packages first",
    ))
}

struct Callback {
    sender: mpsc::Sender<(i32, String)>,
}
struct SoftwareDevice {
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

fn create_companion() -> Result<SoftwareDevice> {
    let instance = wide("HM_RUST_CLIENT_0");
    let hardware = wide(SWD_HARDWARE);
    let compatible = wide(
        "USB\\MS_COMP_XUSB10\0USB\\Class_FF&SubClass_5D&Prot_01\0USB\\Class_FF&SubClass_5D\0USB\\Class_FF\0",
    );
    let description = wide(NAME);
    let info = SW_DEVICE_CREATE_INFO {
        cbSize: size_of::<SW_DEVICE_CREATE_INFO>() as u32,
        pszInstanceId: instance.as_ptr(),
        pszzHardwareIds: hardware.as_ptr(),
        pszzCompatibleIds: compatible.as_ptr(),
        pContainerId: &CONTAINER,
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
            wide("HIDMAESTRO").as_ptr(),
            wide(r"HTREE\ROOT\0").as_ptr(),
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

pub(crate) struct Backend {
    companion: Option<SoftwareDevice>,
    root: bool,
    config: bool,
    transport: Option<Transport>,
    lease: Option<Handle>,
    expected: BTreeMap<String, (u32, Vec<u8>)>,
    companion_id: Option<String>,
    journal: bool,
}

impl Backend {
    pub fn create() -> Result<Self> {
        Self::create_inner(false)
    }
    fn create_inner(fail_after_hid: bool) -> Result<Self> {
        elevated()?;
        let inf = driver_inf(false)?;
        let companion_inf = driver_inf(true)?;
        let transport = Transport::create_with(recover)?;
        let mut this = Self {
            companion: None,
            root: false,
            config: false,
            transport: Some(transport),
            lease: None,
            expected: BTreeMap::new(),
            companion_id: None,
            journal: false,
        };
        let setup = (|| {
            let mut phantom = 0;
            if unsafe {
                CM_Locate_DevNodeW(
                    &mut phantom,
                    wide(ROOT_ID).as_ptr(),
                    CM_LOCATE_DEVNODE_PHANTOM,
                )
            } == CR_SUCCESS
            {
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
            this.submit(&State::default())?;
            this.create_root(&inf)
                .map_err(|e| io::Error::new(e.kind(), format!("HID setup: {e}")))?;
            if fail_after_hid {
                return Err(io::Error::other("injected failure after HID registration"));
            }
            this.companion = Some(
                create_companion()
                    .map_err(|e| io::Error::new(e.kind(), format!("XUSB setup: {e}")))?,
            );
            let id = &this.companion.as_ref().unwrap().id;
            this.companion_id = Some(id.clone());
            Key::open(JOURNAL)?
                .ok_or_else(|| io::Error::other("recovery journal disappeared"))?
                .text("CompanionInstanceId", id)?;
            Key::open(CONFIG)?
                .ok_or_else(|| io::Error::other("configuration disappeared"))?
                .text("CompanionInstanceId", id)?;
            this.expected
                .insert("CompanionInstanceId".into(), (REG_SZ, utf16_bytes(id)));
            wait_for(|| companion_ready(id), "XUSB interface start")?;
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
        let mut data = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        check(unsafe {
            SetupDiCreateDeviceInfoW(
                set.0,
                wide(ROOT_ID).as_ptr(),
                &HID_CLASS,
                wide(NAME).as_ptr(),
                ptr::null_mut(),
                0,
                &mut data,
            )
        })?;
        for (property, value) in [
            (SPDRP_HARDWAREID, HARDWARE),
            (
                SPDRP_COMPATIBLEIDS,
                "USB\\MS_COMP_XUSB10\0USB\\Class_FF&SubClass_5D&Prot_01\0",
            ),
            (SPDRP_UPPERFILTERS, "xinputhid\0"),
        ] {
            let bytes = utf16_bytes(value);
            check(unsafe {
                SetupDiSetDeviceRegistryPropertyW(
                    set.0,
                    &mut data,
                    property,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                )
            })?;
        }
        check(unsafe { SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set.0, &data) })?;
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
        let mut params = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        check(unsafe { SetupDiGetDeviceInstallParamsW(set.0, &data, &mut params) })?;
        params.Flags |= DI_ENUMSINGLEINF | DI_QUIETINSTALL;
        let path = wide(&inf.to_string_lossy());
        if path.len() > params.DriverPath.len() {
            return Err(io::Error::other("INF path is too long"));
        }
        params.DriverPath[..path.len()].copy_from_slice(&path);
        check(unsafe { SetupDiSetDeviceInstallParamsW(set.0, &data, &params) })?;
        check(unsafe { SetupDiBuildDriverInfoList(set.0, &mut data, SPDIT_COMPATDRIVER) })?;
        let mut driver = SP_DRVINFO_DATA_V2_W {
            cbSize: size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
            ..Default::default()
        };
        check(unsafe { SetupDiEnumDriverInfoW(set.0, &data, SPDIT_COMPATDRIVER, 0, &mut driver) })?;
        let mut reboot = 0;
        let rc = unsafe { DiInstallDevice(ptr::null_mut(), set.0, &data, &driver, 0, &mut reboot) };
        unsafe {
            SetupDiDestroyDriverInfoList(set.0, &data, SPDIT_COMPATDRIVER);
        }
        check(rc)?;
        if reboot != 0 {
            return Err(io::Error::other(
                "Windows requires a restart to start the HID device",
            ));
        }
        wait_for(
            || {
                let mut child = 0;
                let mut state = 0;
                let mut problem = 0;
                unsafe {
                    CM_Get_Child(&mut child, data.DevInst, 0) == CR_SUCCESS
                        && CM_Get_DevNode_Status(&mut state, &mut problem, child, 0) == CR_SUCCESS
                        && problem == 0
                        && state & DN_STARTED != 0
                }
            },
            "HID child start",
        )
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
                && let Err(e) = remove_node(id, SWD_HARDWARE)
            {
                error.get_or_insert(e);
            }
        }
        if self.root {
            match remove_root() {
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
        if self.config && !self.root && companion_gone && error.is_none() {
            let result = (|| {
                if let Some(key) = Key::open(CONFIG)? {
                    if key.snapshot()? != self.expected {
                        return Err(io::Error::other(
                            "configuration ownership changed; preserving it",
                        ));
                    }
                    drop(key);
                    status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(CONFIG).as_ptr()) })?;
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
        if self.journal && !self.config && !self.root && companion_gone {
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
                    status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(JOURNAL).as_ptr()) })?;
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
        if !self.config && !self.journal && !self.root && companion_gone {
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
            || self.journal
        {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use windows_sys::Win32::System::Memory::*;
        let mut backend = Backend::create().unwrap();
        let held = Handle::new(unsafe {
            OpenFileMappingW(FILE_MAP_READ, 0, wide("Global\\HIDMaestroInput0").as_ptr())
        })
        .unwrap();
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
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::*,
            System::IO::DeviceIoControl,
        };
        let name = format!("Local\\HIDMaestroObserver{}", std::process::id());
        if let Ok(parent) = std::env::var("HIDMAESTRO_OBSERVER_PARENT") {
            let event = Handle::new(unsafe {
                OpenEventW(
                    EVENT_MODIFY_STATE,
                    0,
                    wide(&format!("Local\\HIDMaestroObserver{parent}")).as_ptr(),
                )
            })
            .unwrap();
            let resume = Handle::new(unsafe {
                OpenEventW(
                    SYNCHRONIZATION_SYNCHRONIZE,
                    0,
                    wide(&format!("Local\\HIDMaestroObserver{parent}Resume")).as_ptr(),
                )
            })
            .unwrap();
            let id = std::env::var("HIDMAESTRO_OBSERVER_DEVICE").unwrap();
            let guid = GUID::from_u128(0xec87f1e3_c13b_4100_b5f7_8b84d54260cb);
            let mut path = [0u16; 4096];
            assert_eq!(
                unsafe {
                    CM_Get_Device_Interface_ListW(
                        &guid,
                        wide(&id).as_ptr(),
                        path.as_mut_ptr(),
                        path.len() as u32,
                        CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
                    )
                },
                CR_SUCCESS
            );
            assert_ne!(path[0], 0);
            let old = Handle::new(unsafe {
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
            .unwrap();
            let mut bytes = [0u8; 29];
            let mut returned = 0;
            check(unsafe {
                DeviceIoControl(
                    old.0,
                    0x8000e00c,
                    ptr::null(),
                    0,
                    bytes.as_mut_ptr().cast(),
                    bytes.len() as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            })
            .unwrap();
            assert_eq!(u16::from_le_bytes([bytes[11], bytes[12]]), 0x1000);
            for slot in 0..4 {
                let mut state =
                    windows_sys::Win32::UI::Input::XboxController::XINPUT_STATE::default();
                unsafe {
                    windows_sys::Win32::UI::Input::XboxController::XInputGetState(slot, &mut state);
                }
            }
            unsafe {
                SetEvent(event.0);
            }
            assert_eq!(unsafe { WaitForSingleObject(resume.0, 30_000) }, 0);
            for code in [0x8000e00c, 0x8000a010] {
                assert_eq!(
                    unsafe {
                        DeviceIoControl(
                            old.0,
                            code,
                            bytes.as_ptr().cast(),
                            bytes.len() as u32,
                            bytes.as_mut_ptr().cast(),
                            bytes.len() as u32,
                            &mut returned,
                            ptr::null_mut(),
                        )
                    },
                    0,
                    "removed XUSB handle still accepts IOCTL {code:#x}"
                );
            }
            drop(old);
            wait_for(
                || {
                    (0..4).any(|slot| {
                        let mut state =
                            windows_sys::Win32::UI::Input::XboxController::XINPUT_STATE::default();
                        (unsafe {
                            windows_sys::Win32::UI::Input::XboxController::XInputGetState(
                                slot, &mut state,
                            )
                        }) == 0
                            && state.Gamepad.wButtons == 0x2000
                    })
                },
                "recreated controller B press",
            )
            .unwrap();
            return;
        }
        for _ in 0..3 {
            let ready =
                Handle::new(unsafe { CreateEventW(ptr::null(), 1, 0, wide(&name).as_ptr()) })
                    .unwrap();
            let resume = Handle::new(unsafe {
                CreateEventW(ptr::null(), 1, 0, wide(&format!("{name}Resume")).as_ptr())
            })
            .unwrap();
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
                if unsafe { WaitForSingleObject(ready.0, 5000) } != 0 {
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
                check(unsafe { SetEvent(resume.0) })?;
                if unsafe { WaitForSingleObject(observer.as_raw_handle(), 20_000) } != 0 {
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
        assert!(Backend::create_inner(true).is_err());
        assert!(!present(ROOT_ID));
        assert!(Key::open(CONFIG).unwrap().is_none());
        let controller = Backend::create_inner(false).unwrap();
        assert!(present(ROOT_ID));
        for slot in 0..4 {
            let mut state = windows_sys::Win32::UI::Input::XboxController::XINPUT_STATE::default();
            unsafe {
                windows_sys::Win32::UI::Input::XboxController::XInputGetState(slot, &mut state);
            }
        }
        assert!(Backend::create_inner(false).is_err());
        controller.close().unwrap();
        assert!(!present(ROOT_ID));
        let mut phantom = 0;
        assert_ne!(
            unsafe {
                CM_Locate_DevNodeW(
                    &mut phantom,
                    wide(SWD_ID).as_ptr(),
                    CM_LOCATE_DEVNODE_PHANTOM,
                )
            },
            CR_SUCCESS
        );
        drop(Backend::create_inner(false).unwrap());
        assert!(!present(ROOT_ID));
    }

    #[test]
    fn late_callback_keeps_context_alive() {
        let (tx, rx) = std::sync::mpsc::channel();
        let context = Box::new(Callback { sender: tx });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(1))
                .is_err()
        );
        unsafe {
            created(
                std::ptr::null_mut(),
                0,
                (&*context as *const Callback).cast(),
                std::ptr::null(),
            );
        }
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap().0, 0);
    }

    #[test]
    fn callback_preserves_actual_instance_id() {
        let (tx, rx) = std::sync::mpsc::channel::<(i32, String)>();
        let context = Box::new(Callback { sender: tx });
        let id = wide(r"SWD\HIDMAESTRO\decorated-instance");
        unsafe {
            created(
                std::ptr::null_mut(),
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

    #[test]
    #[ignore = "explicit elevated test temporarily reserves Controller0"]
    fn foreign_configuration_is_preserved() {
        assert!(Key::open(CONFIG).unwrap().is_none());
        let key = Key::create(CONFIG).unwrap();
        key.text("ForeignSentinel", "keep me").unwrap();
        let result = Backend::create();
        let sentinel = key.get("ForeignSentinel").unwrap();
        drop(key);
        status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(CONFIG).as_ptr()) }).unwrap();
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
        status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(CONFIG).as_ptr()) }).unwrap();
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
        old.journal = false;
        drop(old);
        let recovered = Backend::create();
        if recovered.is_err() {
            remove_root().unwrap();
            status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(CONFIG).as_ptr()) }).unwrap();
        }
        assert!(recovered.is_ok(), "{:#?}", recovered.err());
    }

    #[test]
    #[ignore = "explicit elevated recovery test preserves an altered companion ID"]
    fn modified_companion_record_is_preserved() {
        let mut old = Backend::create().unwrap();
        let id = old.companion.as_ref().unwrap().id.clone();
        old.companion.take();
        wait_for(|| !present(&id), "XUSB close").unwrap();
        old.transport.take();
        old.root = false;
        old.config = false;
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
