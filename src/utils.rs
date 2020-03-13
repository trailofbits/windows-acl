//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use libc;
use std::ffi::OsStr;
use std::iter::once;
use std::mem;
use std::ops::Drop;
use std::os::windows::ffi::OsStrExt;
use widestring::WideString;
use winapi::shared::minwindef::{BYTE, DWORD, FALSE, HLOCAL, PDWORD};
use winapi::shared::ntdef::{HANDLE, LPCWSTR, LPWSTR, NULL, WCHAR};
use winapi::shared::sddl::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS};

#[allow(unused_imports)]
use winapi::um::accctrl::{
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
    SE_SERVICE,
};
use winapi::um::aclapi::{GetNamedSecurityInfoW, SetNamedSecurityInfoW};
use winapi::um::errhandlingapi::{GetLastError, SetLastError};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, CopySid, GetLengthSid};
use winapi::um::winbase::{GetUserNameW, LocalFree, LookupAccountNameW, LookupPrivilegeValueW};
use winapi::um::winnt::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PACL, PSECURITY_DESCRIPTOR, PSID, PTOKEN_PRIVILEGES,
    SACL_SECURITY_INFORMATION, SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};

/// Converts a raw SID into a SID string representation.
///
/// # Arguments
/// * `sid` - A pointer to a raw SID buffer. In native Windows, this is would be a `PSID` type.
///
/// # Errors
/// On error, a Windows error code is returned with the `Err` type.
pub fn sid_to_string(sid: PSID) -> Result<String, DWORD> {
    let mut raw_string_sid: LPWSTR = NULL as LPWSTR;
    if unsafe { ConvertSidToStringSidW(sid, &mut raw_string_sid) } == 0
        || raw_string_sid == (NULL as LPWSTR)
    {
        return Err(unsafe { GetLastError() });
    }

    let raw_string_sid_len = unsafe { libc::wcslen(raw_string_sid) };
    let sid_string = unsafe { WideString::from_ptr(raw_string_sid, raw_string_sid_len) };

    unsafe { LocalFree(raw_string_sid as HLOCAL) };

    Ok(sid_string.to_string_lossy())
}

/// Resolves a system username (either in the format of "user" or "DOMAIN\user") into a raw SID. The raw SID
/// is represented by a `Vec<u8>` object.
///
/// # Arguments
/// * `name` - The user name to be resolved into a raw SID.
/// * `system` - An optional string denoting the scope of the user name (such as a machine or domain name). If not required, use `None`.
///
/// # Errors
/// On error, a Windows error code is returned with the `Err` type.
///
/// **Note**: If the error code is 0, `GetLastError()` returned `ERROR_INSUFFICIENT_BUFFER` after invoking `LookupAccountNameW` or
///         the `sid_size` is 0.
pub fn name_to_sid(name: &str, system: Option<&str>) -> Result<Vec<BYTE>, DWORD> {
    let raw_name: Vec<u16> = OsStr::new(name).encode_wide().chain(once(0)).collect();
    let raw_system: Option<Vec<u16>> =
        system.map(|name| OsStr::new(name).encode_wide().chain(once(0)).collect());
    let system_ptr: LPCWSTR = match raw_system {
        Some(sys_name) => sys_name.as_ptr(),
        None => NULL as LPCWSTR,
    };
    let mut sid_size: DWORD = 0;
    let mut sid_type: SID_NAME_USE = 0 as SID_NAME_USE;

    let mut name_size: DWORD = 0;

    if unsafe {
        LookupAccountNameW(
            system_ptr,
            raw_name.as_ptr() as LPCWSTR,
            NULL as PSID,
            &mut sid_size,
            NULL as LPWSTR,
            &mut name_size,
            &mut sid_type,
        )
    } != 0
    {
        return Err(unsafe { GetLastError() });
    }

    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(0);
    }

    if sid_size == 0 {
        return Err(0);
    }

    let mut sid: Vec<BYTE> = Vec::with_capacity(sid_size as usize);
    let mut name: Vec<BYTE> = Vec::with_capacity((name_size as usize) * mem::size_of::<WCHAR>());

    if unsafe {
        LookupAccountNameW(
            system_ptr,
            raw_name.as_ptr() as LPCWSTR,
            sid.as_mut_ptr() as PSID,
            &mut sid_size,
            name.as_mut_ptr() as LPWSTR,
            &mut name_size,
            &mut sid_type,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }

    Ok(sid)
}

/// Converts a string representation of a SID into a raw SID. The returned raw SID is contained in a `Vec<u8>` object.
///
/// # Arguments
/// * `string_sid` - The SID to converted into raw form as a string.
///
/// # Errors
/// On error, a Windows error code is wrapped in an `Err` type.
pub fn string_to_sid(string_sid: &str) -> Result<Vec<BYTE>, DWORD> {
    let mut sid: PSID = NULL as PSID;
    let raw_string_sid: Vec<u16> = OsStr::new(string_sid)
        .encode_wide()
        .chain(once(0))
        .collect();

    if unsafe { ConvertStringSidToSidW(raw_string_sid.as_ptr(), &mut sid) } == 0 {
        return Err(unsafe { GetLastError() });
    }

    let size = unsafe { GetLengthSid(sid) };
    let mut sid_buf: Vec<BYTE> = Vec::with_capacity(size as usize);

    if unsafe { CopySid(size, sid_buf.as_mut_ptr() as PSID, sid) } == 0 {
        return Err(unsafe { GetLastError() });
    }

    Ok(sid_buf)
}

/// Retrieves the user name of the current user.
pub fn current_user() -> Option<String> {
    let mut username_size: DWORD = 0 as DWORD;

    if unsafe { GetUserNameW(NULL as LPWSTR, &mut username_size) } != 0 {
        return None;
    }

    let mut username: Vec<u16> = Vec::with_capacity(username_size as usize);
    if unsafe { GetUserNameW(username.as_mut_ptr() as LPWSTR, &mut username_size) } == 0 {
        return None;
    }

    let name = unsafe { WideString::from_ptr(username.as_ptr(), (username_size - 1) as usize) };

    Some(name.to_string_lossy())
}

fn set_privilege(name: &str, is_enabled: bool) -> Result<bool, DWORD> {
    let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
    let wPrivilegeName: Vec<u16> = OsStr::new(name).encode_wide().chain(once(0)).collect();

    if unsafe {
        LookupPrivilegeValueW(
            NULL as LPCWSTR,
            wPrivilegeName.as_ptr(),
            &mut tkp.Privileges[0].Luid,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }

    tkp.PrivilegeCount = 1;

    if is_enabled {
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tkp.Privileges[0].Attributes = 0;
    }

    let mut hToken: HANDLE = INVALID_HANDLE_VALUE;
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut hToken,
        )
    } == 0
    {
        return Err(unsafe { GetLastError() });
    }

    let status = unsafe {
        AdjustTokenPrivileges(
            hToken,
            FALSE,
            &mut tkp,
            0,
            NULL as PTOKEN_PRIVILEGES,
            NULL as PDWORD,
        )
    };
    let code = unsafe { GetLastError() };
    unsafe { CloseHandle(hToken) };

    if code == ERROR_NOT_ALL_ASSIGNED {
        return Err(code);
    }

    if status == 0 {
        return Err(code);
    }

    Ok(is_enabled)
}

#[derive(Debug)]
struct SystemPrivilege {
    name: Option<String>,
}

impl SystemPrivilege {
    fn acquire(name: &str) -> Result<SystemPrivilege, DWORD> {
        set_privilege(name, true).map(|_| SystemPrivilege {
            name: Some(name.to_owned()),
        })
    }

    fn release(&mut self) -> bool {
        let mut status = true;
        if let Some(ref name) = self.name {
            status = set_privilege(name, false).is_ok();
        }

        self.name = None;
        status
    }
}

impl Drop for SystemPrivilege {
    fn drop(&mut self) {
        self.release();
    }
}

/// This structure manages a Windows `SECURITY_DESCRIPTOR` object.
#[derive(Debug)]
pub struct SecurityDescriptor {
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,

    /// Pointer to the discretionary access control list in the security descriptor
    pub pDacl: PACL,

    /// Pointer to the system access control list in the security descriptor
    pub pSacl: PACL,

    psidOwner: PSID,
    psidGroup: PSID,
}

impl SecurityDescriptor {
    /// Returns a `SecurityDescriptor` object for the specified named object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the named object path.
    /// * `obj_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `get_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type
    pub fn from_path(
        path: &str,
        obj_type: SE_OBJECT_TYPE,
        get_sacl: bool,
    ) -> Result<SecurityDescriptor, DWORD> {
        let wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();

        let mut obj = SecurityDescriptor::default();
        let mut flags =
            DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;

        let privilege: Option<SystemPrivilege>;

        if get_sacl {
            privilege = SystemPrivilege::acquire("SeSecurityPrivilege").ok();
            if privilege.is_none() {
                return Err(unsafe { GetLastError() });
            }

            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        let ret = unsafe {
            GetNamedSecurityInfoW(
                wPath.as_ptr(),
                obj_type,
                flags,
                &mut obj.psidOwner,
                &mut obj.psidGroup,
                &mut obj.pDacl,
                &mut obj.pSacl,
                &mut obj.pSecurityDescriptor,
            )
        };
        if ret != ERROR_SUCCESS {
            unsafe { SetLastError(ret) };
            return Err(ret);
        }

        if !get_sacl {
            obj.pSacl = NULL as PACL;
        }

        Ok(obj)
    }

    fn default() -> SecurityDescriptor {
        SecurityDescriptor {
            pSecurityDescriptor: NULL,
            pDacl: NULL as PACL,
            pSacl: NULL as PACL,
            psidOwner: NULL,
            psidGroup: NULL,
        }
    }

    /// Commits a provided discretionary and/or system access control list to the specified named object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the named object path.
    /// * `obj_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `dacl` - An optional
    /// * `sacl` - An optional
    ///
    /// # Remarks
    /// This function does not update the `pSacl` or `pDacl` field in the `SecurityDescriptor` object. The `ACL` object tends
    /// to completely reload the `SecurityDescriptor` object after a reload to ensure consistency.
    ///
    /// # Errors
    /// On error, `false` is returned.
    pub fn apply(
        &mut self,
        path: &str,
        obj_type: SE_OBJECT_TYPE,
        dacl: Option<PACL>,
        sacl: Option<PACL>,
    ) -> bool {
        let mut wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let dacl_ptr = dacl.unwrap_or(NULL as PACL);
        let sacl_ptr = sacl.unwrap_or(NULL as PACL);

        let mut flags = 0;
        if dacl_ptr != (NULL as PACL) {
            flags |= DACL_SECURITY_INFORMATION;
        }

        let privilege: Option<SystemPrivilege>;

        if sacl_ptr != (NULL as PACL) {
            privilege = SystemPrivilege::acquire("SeSecurityPrivilege").ok();
            if privilege.is_none() {
                return false;
            }

            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        let ret = unsafe {
            SetNamedSecurityInfoW(
                wPath.as_mut_ptr(),
                obj_type,
                flags,
                NULL as PSID,
                NULL as PSID,
                dacl_ptr,
                sacl_ptr,
            )
        };
        if ret != ERROR_SUCCESS {
            unsafe { SetLastError(ret) };
            return false;
        }

        true
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if self.pSecurityDescriptor != NULL {
            unsafe { LocalFree(self.pSecurityDescriptor) };
        }
    }
}
