#![allow(non_snake_case)]

use field_offset::*;
use std::mem;
use utils::SecurityDescriptor;
use winapi::shared::minwindef::{
    BYTE, DWORD, LPVOID, WORD
};
use winapi::shared::ntdef::{
    NULL
};
use winapi::um::accctrl::{
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
    SE_SERVICE
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::securitybaseapi::{
    CopySid, EqualSid, GetAce, GetLengthSid, IsValidSid,
};
use winapi::um::winnt::{
    ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE,
    ACCESS_DENIED_OBJECT_ACE_TYPE, ACCESS_MASK, PACE_HEADER, PACL, PSID, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE_TYPE
};

pub struct ACLEntry {
    entry_type: BYTE,
    size: WORD,
    flags: BYTE,
    mask: ACCESS_MASK,
    sid: Option<Vec<u16>>
}

pub struct ACL {
    descriptor: Option<SecurityDescriptor>,
    path: String
}

macro_rules! process_entry {
    ($entry: ident, $ptr: ident => $cls: path) => {
        {
            let entry_ptr: *mut $cls = $ptr as *mut $cls;
            let sid_offset = offset_of!($cls => SidStart);
            let pSid: PSID = sid_offset.apply_ptr_mut(entry_ptr) as PSID;

            if unsafe { IsValidSid(pSid) } != 0 {
                let size = unsafe { GetLengthSid(pSid) };
                let mut sid: Vec<u16> = Vec::with_capacity(size as usize);

                if unsafe { CopySid(size, sid.as_mut_ptr() as PSID, pSid) } != 0 {
                    $entry.sid = Some(sid);
                    $entry.entry_type = unsafe { (*$ptr).AceType };
                    $entry.size = unsafe { (*$ptr).AceSize };
                    $entry.flags = unsafe { (*$ptr).AceFlags };
                    $entry.mask = unsafe { (*entry_ptr).Mask};
                }
            }
        }
    };
}

trait EntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool;
}

fn enumerate_acl_entries<T: EntryCallback>(pAcl: PACL, callback: &mut T) {
    let mut hdr: PACE_HEADER = NULL as PACE_HEADER;
    let ace_count = unsafe { (*pAcl).AceCount };

    for i in 0..ace_count {
        if unsafe { GetAce(pAcl, i as DWORD, mem::transmute::<&mut PACE_HEADER, *mut LPVOID>(&mut hdr)) } == 0 {
            break
        }

        let mut entry = ACLEntry {
            entry_type: 0,
            size: 0,
            flags: 0,
            mask: 0,
            sid: None
        };

        match unsafe { (*hdr).AceType } {
            ACCESS_ALLOWED_ACE_TYPE => process_entry!(entry, hdr => ACCESS_ALLOWED_ACE),
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE => process_entry!(entry, hdr => ACCESS_ALLOWED_CALLBACK_ACE),
            ACCESS_ALLOWED_OBJECT_ACE_TYPE => process_entry!(entry, hdr => ACCESS_ALLOWED_OBJECT_ACE),
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => process_entry!(entry, hdr => ACCESS_ALLOWED_CALLBACK_OBJECT_ACE),
            ACCESS_DENIED_ACE_TYPE => process_entry!(entry, hdr => ACCESS_DENIED_ACE),
            ACCESS_DENIED_CALLBACK_ACE_TYPE => process_entry!(entry, hdr => ACCESS_DENIED_CALLBACK_ACE),
            ACCESS_DENIED_OBJECT_ACE_TYPE => process_entry!(entry, hdr => ACCESS_DENIED_OBJECT_ACE),
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => process_entry!(entry, hdr => ACCESS_DENIED_CALLBACK_OBJECT_ACE),
            SYSTEM_AUDIT_ACE_TYPE => process_entry!(entry, hdr => SYSTEM_AUDIT_ACE),
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE => process_entry!(entry, hdr => SYSTEM_AUDIT_CALLBACK_ACE),
            SYSTEM_AUDIT_OBJECT_ACE_TYPE => process_entry!(entry, hdr => SYSTEM_AUDIT_OBJECT_ACE),
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => process_entry!(entry, hdr => SYSTEM_AUDIT_CALLBACK_OBJECT_ACE),
            _ => {}
        }

        if !callback.on_entry(hdr, entry) {
            break
        }
    }
}

struct GetEntryCallback {
    entries: Vec<ACLEntry>,
    target: PSID
}

impl EntryCallback for GetEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID
        };

        if pSid != NULL && (unsafe { EqualSid(self.target, pSid) } != 0) {
            self.entries.push(entry);
        }

        true
    }
}

impl ACL {
    pub fn from_path(path: &str, object_type: SE_OBJECT_TYPE, get_sacl: bool) -> Result<ACL, DWORD> {
        Ok(ACL {
            descriptor: match SecurityDescriptor::from_path(path, object_type, get_sacl) {
                Ok(s) => Some(s),
                Err(e) => return Err(e)
            },
            path: path.to_owned()
        })
    }

    pub fn from_file_path(path: &str, get_sacl: bool) -> Result<ACL, DWORD> {
        ACL::from_path(path, SE_FILE_OBJECT, get_sacl)
    }

    pub fn from_object_path(path: &str, get_sacl: bool) -> Result<ACL, DWORD> {
        ACL::from_path(path, SE_KERNEL_OBJECT, get_sacl)
    }

    pub fn from_registry_path(path: &str, is_wow6432key: bool, get_sacl: bool) -> Result<ACL, DWORD> {
        if is_wow6432key {
            ACL::from_path(path, SE_REGISTRY_WOW64_32KEY, get_sacl)
        } else {
            ACL::from_path(path, SE_REGISTRY_KEY, get_sacl)
        }
    }

    pub fn get_entries_by_sid(&self, sid: PSID) -> Result<Vec<ACLEntry>, DWORD> {
        let mut callback = GetEntryCallback {
            target: sid,
            entries: Vec::new()
        };

        match self.descriptor {
            Some(ref descriptor) => {
                let pDacl = descriptor.pDacl;

                enumerate_acl_entries(pDacl, &mut callback)
            },
            None => return Err(0)
        }

        Ok(callback.entries)
    }

    pub fn get_audit_entries_by_sid(&self, sid: PSID) -> result<Vec<ACLEntry>, DWORD> {

    }

    // pub fn add_entry() {}
    // pub fn add_audit_entry() {}

}

impl Drop for ACL {
    fn drop(&mut self) {

    }
}