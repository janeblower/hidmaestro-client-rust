use super::{status, utf16_bytes, wide};
use crate::Result;
use std::{collections::BTreeMap, io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS},
    System::Registry::*,
};

/// A read-write key under HKEY_LOCAL_MACHINE.
pub struct Key(HKEY);
impl Key {
    pub fn open(path: &str) -> Result<Option<Self>> {
        let mut key = ptr::null_mut();
        // SAFETY: the path outlives the call; key receives a handle that Key closes.
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

    /// Creates a new key, failing with `AlreadyExists` if it was already there.
    pub fn create(path: &str) -> Result<Self> {
        let mut key = ptr::null_mut();
        let mut disposition = 0;
        // SAFETY: the path outlives the call; key receives a handle that Key closes.
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

    /// Deletes the key at path and everything below it.
    pub fn delete_tree(path: &str) -> Result<()> {
        // SAFETY: the path outlives the call.
        status(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(path).as_ptr()) })
    }

    /// Reads every value, failing if the key has subkeys.
    pub fn snapshot(&self) -> Result<BTreeMap<String, (u32, Vec<u8>)>> {
        let mut subkeys = 0;
        // SAFETY: the key is open; only the subkey count is requested.
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
            // SAFETY: name holds len UTF-16 units, which the call reads back into len.
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
            if rc == ERROR_NO_MORE_ITEMS {
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

    pub fn set(&self, name: &str, kind: u32, bytes: &[u8]) -> Result<()> {
        // SAFETY: name and bytes outlive the call, which reads bytes.len() bytes.
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

    pub fn text(&self, name: &str, value: &str) -> Result<()> {
        self.set(name, REG_SZ, &utf16_bytes(value))
    }

    pub fn dword(&self, name: &str, value: u32) -> Result<()> {
        self.set(name, REG_DWORD, &value.to_le_bytes())
    }

    pub fn get(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
        let mut size = 0;
        let mut kind = 0;
        // SAFETY: the name outlives the call; a null buffer asks only for the size.
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
        // SAFETY: the buffer holds size bytes, which the call reads back into size.
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

    pub fn delete_value(&self, name: &str) -> Result<()> {
        // SAFETY: the name outlives the call.
        status(unsafe { RegDeleteValueW(self.0, wide(name).as_ptr()) })
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Key owns the open key and closes it only here.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
