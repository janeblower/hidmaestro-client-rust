use super::wide;
use std::ptr;
use windows_sys::{Win32::Devices::DeviceAndDriverInstallation::*, core::GUID};

/// A device node; failures carry the raw CONFIGRET.
#[derive(Clone, Copy)]
pub struct DevNode(pub(super) u32);
impl DevNode {
    pub fn locate(id: &str, flags: u32) -> Result<Self, CONFIGRET> {
        let mut node = 0;
        // SAFETY: the ID outlives the call.
        match unsafe { CM_Locate_DevNodeW(&mut node, wide(id).as_ptr(), flags) } {
            CR_SUCCESS => Ok(Self(node)),
            rc => Err(rc),
        }
    }

    /// The node's status and problem flags.
    pub fn status(self) -> Result<(u32, u32), CONFIGRET> {
        let (mut state, mut problem) = (0, 0);
        // SAFETY: both outputs are writable u32s.
        match unsafe { CM_Get_DevNode_Status(&mut state, &mut problem, self.0, 0) } {
            CR_SUCCESS => Ok((state, problem)),
            rc => Err(rc),
        }
    }

    /// Whether the node has started without a problem.
    pub fn started(self) -> bool {
        self.status()
            .is_ok_and(|(state, problem)| problem == 0 && state & DN_STARTED != 0)
    }

    pub fn child(self) -> Result<Self, CONFIGRET> {
        let mut child = 0;
        // SAFETY: child is a writable u32.
        match unsafe { CM_Get_Child(&mut child, self.0, 0) } {
            CR_SUCCESS => Ok(Self(child)),
            rc => Err(rc),
        }
    }

    pub fn sibling(self) -> Result<Self, CONFIGRET> {
        let mut sibling = 0;
        // SAFETY: sibling is a writable u32.
        match unsafe { CM_Get_Sibling(&mut sibling, self.0, 0) } {
            CR_SUCCESS => Ok(Self(sibling)),
            rc => Err(rc),
        }
    }

    pub fn id(self) -> Result<String, CONFIGRET> {
        let mut id = [0u16; 4096];
        // SAFETY: the buffer holds the length passed.
        match unsafe { CM_Get_Device_IDW(self.0, id.as_mut_ptr(), id.len() as u32, 0) } {
            CR_SUCCESS => {
                let end = id.iter().position(|&c| c == 0).unwrap_or(id.len());
                // An identity that is not UTF-16 cannot name a device of ours.
                String::from_utf16(&id[..end]).map_err(|_| CR_INVALID_DATA)
            }
            rc => Err(rc),
        }
    }

    /// Asks the holders of the subtree to let go and removes it; false if refused.
    pub fn query_and_remove(self) -> bool {
        // SAFETY: no veto outputs are requested.
        let rc = unsafe {
            CM_Query_And_Remove_SubTreeW(
                self.0,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                CM_REMOVE_UI_NOT_OK | CM_REMOVE_NO_RESTART,
            )
        };
        rc == CR_SUCCESS
    }
}

/// The first present interface of a class on a device, with its NUL.
pub fn interface(class: &GUID, id: &str) -> Option<Vec<u16>> {
    let mut list = vec![0u16; 4096];
    // SAFETY: the ID outlives the call, and the buffer holds the length passed.
    let rc = unsafe {
        CM_Get_Device_Interface_ListW(
            class,
            wide(id).as_ptr(),
            list.as_mut_ptr(),
            list.len() as u32,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
    };
    let end = list.iter().position(|&c| c == 0)?;
    if rc != CR_SUCCESS || end == 0 {
        return None;
    }
    list.truncate(end + 1);
    Some(list)
}
