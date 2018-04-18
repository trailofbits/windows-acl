#![allow(non_snake_case)]

use libc;
use std::ffi::OsStr;
use std::iter::once;
use std::mem;
use std::ops::Drop;
use std::os::windows::ffi::OsStrExt;
use widestring::WideString;
use winapi::shared::minwindef::{
    DWORD, FALSE, HLOCAL, PDWORD
};
use winapi::shared::ntdef::{
    LPCWSTR, LPWSTR, HANDLE, NULL
};
use winapi::shared::sddl::{
    ConvertSidToStringSidW
};
use winapi::shared::winerror::{
    ERROR_NOT_ALL_ASSIGNED,
    ERROR_SUCCESS
};
use winapi::um::accctrl::{
  SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
  SE_SERVICE
};
use winapi::um::aclapi::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{
    CloseHandle, INVALID_HANDLE_VALUE
};
use winapi::um::minwinbase::LPTR;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, OpenProcessToken
};
use winapi::um::securitybaseapi::{
    AdjustTokenPrivileges, InitializeAcl, InitializeSecurityDescriptor
};
use winapi::um::winbase::{
    LocalAlloc, LocalFree, LookupPrivilegeValueW
};
use winapi::um::winnt::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES,
    OWNER_SECURITY_INFORMATION, PACL, PSECURITY_DESCRIPTOR, PSID, PTOKEN_PRIVILEGES,
    SECURITY_DESCRIPTOR_MIN_LENGTH, SACL_SECURITY_INFORMATION, SE_PRIVILEGE_ENABLED,
    SECURITY_DESCRIPTOR_REVISION, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY
};

pub fn sid_to_string(sid: PSID) -> Result<String, DWORD> {
    let mut raw_string_sid: LPWSTR = NULL as LPWSTR;
    if unsafe { ConvertSidToStringSidW(sid, &mut raw_string_sid) } == 0 ||
        raw_string_sid == (NULL as LPWSTR) {
        return Err(unsafe { GetLastError() });
    }

    let raw_string_sid_len = unsafe { libc::wcslen(raw_string_sid) };
    let sid_string = unsafe { WideString::from_ptr(raw_string_sid, raw_string_sid_len)};

    unsafe { LocalFree(raw_string_sid as HLOCAL) };

    Ok(sid_string.to_string_lossy())
}

fn set_privilege(name: &str, is_enabled: bool) -> Result<bool, DWORD> {
    let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
    let wPrivilegeName: Vec<u16> = OsStr::new(name).encode_wide().chain(once(0)).collect();

    if unsafe {
        LookupPrivilegeValueW(NULL as LPCWSTR, wPrivilegeName.as_ptr(), &mut tkp.Privileges[0].Luid)
    } == 0 {
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
        OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                         &mut hToken)
       } == 0 {
        return Err(unsafe { GetLastError() });
    }

    let status = unsafe {
        AdjustTokenPrivileges(hToken,
                              FALSE,
                              &mut tkp,
                              0,
                              NULL as PTOKEN_PRIVILEGES,
                              NULL as PDWORD)
    };
    let code = unsafe { GetLastError() };
    unsafe { CloseHandle(hToken) };

    if code == ERROR_NOT_ALL_ASSIGNED {
        println!("not all assigned");
        return Err(code);
    }

    if status == 0 {
        return Err(code);
    }

    Ok(is_enabled)
}

struct SystemPrivilege {
    name: Option<String>
}

impl SystemPrivilege {
    fn acquire(name: &str) -> Result<SystemPrivilege, DWORD> {
        set_privilege(name, true).map(|_| SystemPrivilege { name: Some(name.to_owned()) })
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

pub struct SecurityDescriptor {
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    pub pDacl: PACL,
    pub pSacl: PACL,
    psidOwner: PSID,
    psidGroup: PSID,
    privilege: Option<SystemPrivilege>
}

impl SecurityDescriptor {
    pub fn from_path(path: &str, obj_type: SE_OBJECT_TYPE, get_sacl: bool)
        -> Result<SecurityDescriptor, DWORD> {
        let mut ret: DWORD = 0;
        let wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();

        let mut obj = SecurityDescriptor::default();
        let mut flags = DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            OWNER_SECURITY_INFORMATION;

        if get_sacl {
            obj.privilege = match SystemPrivilege::acquire("SeSecurityPrivilege") {
                Ok(p) => Some(p),
                Err(c) => return Err(c)
            };

            flags |= SACL_SECURITY_INFORMATION;
        }

        ret = unsafe {
            GetNamedSecurityInfoW(
                wPath.as_ptr(),
                obj_type,
                flags,
                &mut obj.psidOwner,
                &mut obj.psidGroup,
                &mut obj.pDacl,
                &mut obj.pSacl,
                &mut obj.pSecurityDescriptor
            )
        };
        if ret != ERROR_SUCCESS {
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
            privilege: None
        }
    }

    pub fn new() -> Result<SecurityDescriptor, DWORD> {
        let pSecurityDescriptor: PSECURITY_DESCRIPTOR = unsafe {
            LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH)
        };
        if pSecurityDescriptor == NULL {
            return Err(unsafe { GetLastError() });
        }

        if unsafe {
            InitializeSecurityDescriptor(pSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)
           } == 0 {
            unsafe {
                LocalFree(pSecurityDescriptor)
            };
            return Err(unsafe { GetLastError() });
        }

        Ok(SecurityDescriptor::default())
    }

    // TODO(andy): We need a commit/apply function which bakes the security descriptor into
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if self.pSecurityDescriptor != NULL {
            unsafe {
                LocalFree(self.pSecurityDescriptor)
            };
        }
    }
}