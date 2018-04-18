#![allow(non_snake_case)]

use field_offset::*;
use std::fmt;
use std::mem;
use utils::{
    SecurityDescriptor, sid_to_string,
};
use winapi::shared::minwindef::{
    BYTE, DWORD, LPVOID, WORD,
};
use winapi::shared::ntdef::NULL;
use winapi::um::accctrl::{
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
    SE_SERVICE,
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
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
};
use winapi::um::winnt::{
    CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERIT_ONLY_ACE, INHERITED_ACE, NO_PROPAGATE_INHERIT_ACE,
    OBJECT_INHERIT_ACE, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
};
use winapi::um::winnt::{
    DELETE, GENERIC_READ, GENERIC_WRITE, GENERIC_ALL, GENERIC_EXECUTE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    MAXIMUM_ALLOWED, SYNCHRONIZE, FILE_WRITE_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_DELETE_CHILD, FILE_EXECUTE,
    FILE_WRITE_EA, FILE_READ_EA, FILE_APPEND_DATA, FILE_WRITE_DATA, FILE_READ_DATA, STANDARD_RIGHTS_ALL,
    SPECIFIC_RIGHTS_ALL, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ALL_ACCESS
};

#[derive(Clone,Copy,PartialEq)]
pub enum AceType {
    Unknown = 0,
    AccessAllow = 1,
    AccessAllowCallback,
    AccessAllowObject,
    AccessAllowCallbackObject,
    AccessDeny = 5,
    AccessDenyCallback,
    AccessDenyObject,
    AccessDenyCallbackObject,
    SystemAudit = 9,
    SystemAuditCallback,
    SystemAuditObject,
    SystemAuditCallbackObject,
    SystemMandatoryLabel = 13,
    SystemResourceAttribute,
}

pub struct ACLEntry {
    entry_type: AceType,
    size: WORD,
    flags: BYTE,
    mask: ACCESS_MASK,
    sid: Option<Vec<u16>>,
}

pub struct ACL {
    descriptor: Option<SecurityDescriptor>,
    path: String,
    include_sacl: bool,
}

impl fmt::Display for AceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let entry_type = match *self {
            AceType::Unknown => "Unknown",
            AceType::AccessAllow => "AccessAllow",
            AceType::AccessAllowCallback => "AccessAllowCallback",
            AceType::AccessAllowObject => "AccessAllowObject",
            AceType::AccessAllowCallbackObject => "AccessAllowCallbackObject",
            AceType::AccessDeny => "AccessDeny",
            AceType::AccessDenyCallback => "AccessDenyCallback",
            AceType::AccessDenyObject => "AccessDenyObject",
            AceType::AccessDenyCallbackObject => "AccessDenyCallbackObject",
            AceType::SystemAudit => "SystemAudit",
            AceType::SystemAuditCallback => "SystemAuditCallback",
            AceType::SystemAuditObject => "SystemAuditObject",
            AceType::SystemAuditCallbackObject => "SystemAuditCallbackObject",
            AceType::SystemMandatoryLabel => "SystemMandatoryLabel",
            AceType::SystemResourceAttribute => "SystemResourceAttribute"
        };
        write!(f, "{}", entry_type)
    }
}

impl fmt::Display for ACLEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sid_string = match self.sid {
            Some(ref sid) => {
                sid_to_string((*sid).as_ptr() as PSID).unwrap_or_else(
                    |code| "BadFormat".to_string()
                )
            },
            None => "None".to_string()
        };
        let mut flags: String = String::new();
        let defined_flags = [
            (CONTAINER_INHERIT_ACE, "ContainerInheritAce"),
            (FAILED_ACCESS_ACE_FLAG, "FailedAccessAce"),
            (INHERIT_ONLY_ACE, "InheritOnlyAce"),
            (INHERITED_ACE, "InheritedAce"),
            (NO_PROPAGATE_INHERIT_ACE, "NoPropagateInheritAce"),
            (OBJECT_INHERIT_ACE, "ObjectInheritAce"),
            (SUCCESSFUL_ACCESS_ACE_FLAG, "SuccessfulAccessAce")
        ];

        for &(flag, desc) in &defined_flags {
            if (self.flags & flag) > 0 {
                if flags.len() > 0 {
                    flags += "|"
                }
                flags += desc;
            }
        }

        let mut masks: String = String::new();
        if self.entry_type == AceType::SystemMandatoryLabel {
            let defined_masks = [
                (SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, "NoExecUp"),
                (SYSTEM_MANDATORY_LABEL_NO_READ_UP, "NoReadUp"),
                (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "NoWriteUp")];
            for &(mask, desc) in &defined_masks {
                if (self.mask & mask) > 0 {
                    if masks.len() > 0 {
                        masks += "|";
                    }
                    masks += desc;
                }
            }
        } else {
            // TODO(andy): Only works for files...
            let defined_std_rights = [
                (DELETE, "Delete"),
                (GENERIC_READ, "GenericRead"),
                (GENERIC_WRITE, "GenericWrite"),
                (GENERIC_ALL, "GenericAll"),
                (GENERIC_EXECUTE, "GenericExec"),
                (READ_CONTROL, "ReadControl"),
                (WRITE_DAC, "WriteDac"),
                (WRITE_OWNER, "WriteOwner"),
                (MAXIMUM_ALLOWED, "MaxAllowed"),
                (SYNCHRONIZE, "Synchronize")];
            let defined_specific_rights = [
                (FILE_WRITE_ATTRIBUTES, "FileWriteAttr"),
                (FILE_READ_ATTRIBUTES, "FileReadAttr"),
                (FILE_DELETE_CHILD, "FileDeleteChild"),
                (FILE_EXECUTE, "FileExecuteOrTraverse"),
                (FILE_WRITE_EA, "FileWriteEa"),
                (FILE_READ_EA, "FileReadEa"),
                (FILE_APPEND_DATA, "FileAppendDataOrAddSubDir"),
                (FILE_WRITE_DATA, "FileWriteDataOrAddFile"),
                (FILE_READ_DATA, "FileReadDataOrListDir")
            ];
            if (self.mask & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL {
                masks += "StandardRightsAll";
            } else {
                for &(mask, desc) in &defined_std_rights {
                    if (self.mask & mask) > 0 {
                        if masks.len() > 0 {
                            masks += "|";
                        }
                        masks += desc;
                    }
                }
            }

            if (self.mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS {
                if masks.len() > 0 {
                    masks += "|";
                }
                masks += "FileAllAccess";
            } else {
                for &(mask, desc) in &defined_specific_rights {
                    if (self.mask & mask) > 0 {
                        if masks.len() > 0 {
                            masks += "|";
                        }
                        masks += desc;
                    }
                }
            }
        }

        write!(f, "Type={}\n  Flags={}\n  RawMask={:X}\n  Mask={}\n  Sid={}\n", self.entry_type, flags, self.mask, masks, sid_string)
    }
}

macro_rules! process_entry {
    ($entry: ident, $typ: path, $ptr: ident => $cls: path) => {
        {
            let entry_ptr: *mut $cls = $ptr as *mut $cls;
            let sid_offset = offset_of!($cls => SidStart);
            let pSid: PSID = sid_offset.apply_ptr_mut(entry_ptr) as PSID;

            if unsafe { IsValidSid(pSid) } != 0 {
                let size = unsafe { GetLengthSid(pSid) };
                let mut sid: Vec<u16> = Vec::with_capacity(size as usize);

                if unsafe { CopySid(size, sid.as_mut_ptr() as PSID, pSid) } != 0 {
                    $entry.sid = Some(sid);
                    $entry.entry_type = $typ;
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

fn enumerate_acl_entries<T: EntryCallback>(pAcl: PACL, callback: &mut T) -> bool {
    let mut hdr: PACE_HEADER = NULL as PACE_HEADER;
    let ace_count = unsafe { (*pAcl).AceCount };

    for i in 0..ace_count {
        if unsafe { GetAce(pAcl, i as DWORD, mem::transmute::<&mut PACE_HEADER, *mut LPVOID>(&mut hdr)) } == 0 {
            return false;
        }

        let mut entry = ACLEntry {
            entry_type: AceType::Unknown,
            size: 0,
            flags: 0,
            mask: 0,
            sid: None,
        };

        match unsafe { (*hdr).AceType } {
            ACCESS_ALLOWED_ACE_TYPE => process_entry!(entry,
                                                      AceType::AccessAllow,
                                                      hdr => ACCESS_ALLOWED_ACE),
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE => process_entry!(entry,
                                                               AceType::AccessAllowCallback,
                                                               hdr => ACCESS_ALLOWED_CALLBACK_ACE),
            ACCESS_ALLOWED_OBJECT_ACE_TYPE => process_entry!(entry,
                                                             AceType::AccessAllowObject,
                                                             hdr => ACCESS_ALLOWED_OBJECT_ACE),
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => process_entry!(entry,
                                                                      AceType::AccessAllowCallbackObject,
                                                                      hdr => ACCESS_ALLOWED_CALLBACK_OBJECT_ACE),
            ACCESS_DENIED_ACE_TYPE => process_entry!(entry,
                                                     AceType::AccessDeny,
                                                     hdr => ACCESS_DENIED_ACE),
            ACCESS_DENIED_CALLBACK_ACE_TYPE => process_entry!(entry,
                                                              AceType::AccessDenyCallback,
                                                              hdr => ACCESS_DENIED_CALLBACK_ACE),
            ACCESS_DENIED_OBJECT_ACE_TYPE => process_entry!(entry,
                                                            AceType::AccessDenyObject,
                                                            hdr => ACCESS_DENIED_OBJECT_ACE),
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => process_entry!(entry,
                                                                     AceType::AccessDenyCallbackObject,
                                                                     hdr => ACCESS_DENIED_CALLBACK_OBJECT_ACE),
            SYSTEM_AUDIT_ACE_TYPE => process_entry!(entry,
                                                    AceType::SystemAudit,
                                                    hdr => SYSTEM_AUDIT_ACE),
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE => process_entry!(entry,
                                                             AceType::SystemAuditCallback,
                                                             hdr => SYSTEM_AUDIT_CALLBACK_ACE),
            SYSTEM_AUDIT_OBJECT_ACE_TYPE => process_entry!(entry,
                                                           AceType::SystemAuditObject,
                                                           hdr => SYSTEM_AUDIT_OBJECT_ACE),
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => process_entry!(entry,
                                                                    AceType::SystemAuditCallbackObject,
                                                                    hdr => SYSTEM_AUDIT_CALLBACK_OBJECT_ACE),
            SYSTEM_MANDATORY_LABEL_ACE_TYPE => process_entry!(entry,
                                                              AceType::SystemMandatoryLabel,
                                                              hdr => SYSTEM_MANDATORY_LABEL_ACE),
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => process_entry!(entry,
                                                                 AceType::SystemResourceAttribute,
                                                                 hdr => SYSTEM_RESOURCE_ATTRIBUTE_ACE),
            _ => {}
        }

        if !callback.on_entry(hdr, entry) {
            break;
        }
    }

    true
}

struct GetEntryCallback {
    entries: Vec<ACLEntry>,
    target: PSID,
    target_type: Option<AceType>,
}

struct AllEntryCallback {
    entries: Vec<ACLEntry>
}

struct AddEntryCallback {}

struct RemoveEntryCallback {
    target: PSID,
    target_type: Option<AceType>,
}

impl EntryCallback for GetEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID
        };

        if pSid != NULL && (unsafe { EqualSid(self.target, pSid) } != 0) {
            if let Some(ref t) = self.target_type {
                if entry.entry_type != *t {
                    return true;
                }
            }

            self.entries.push(entry);
        }

        true
    }
}

impl EntryCallback for AllEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        self.entries.push(entry);

        true
    }
}

impl EntryCallback for AddEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        // TODO(andy):

        false
    }
}

impl EntryCallback for RemoveEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID
        };

        if let Some(ref t) = self.target_type {
            if entry.entry_type != *t {
                // TODO(andy):
            }
        }

        false
    }
}

impl ACL {
    pub fn from_path(path: &str, object_type: SE_OBJECT_TYPE, get_sacl: bool) -> Result<ACL, DWORD> {
        Ok(ACL {
            descriptor: match SecurityDescriptor::from_path(path, object_type, get_sacl) {
                Ok(s) => Some(s),
                Err(e) => return Err(e)
            },
            path: path.to_owned(),
            include_sacl: get_sacl,
        })
    }

    // TODO(andy): Simple constructor APIs
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

    pub fn all(&self) -> Result<Vec<ACLEntry>, DWORD> {
        let mut callback = AllEntryCallback {
            entries: Vec::new()
        };

        if let Some(ref descriptor) = self.descriptor {
            let pDacl = descriptor.pDacl;

            if pDacl != (NULL as PACL) && !enumerate_acl_entries(pDacl, &mut callback) {
                return Err(unsafe { GetLastError() });
            }

            let pSacl = descriptor.pSacl;

            if pSacl != (NULL as PACL) && !enumerate_acl_entries(pSacl, &mut callback) {
                return Err(unsafe { GetLastError() });
            }
        }

        Ok(callback.entries)
    }

    pub fn get(&self, sid: PSID, entry_type: Option<AceType>) -> Result<Vec<ACLEntry>, DWORD> {
        let mut callback = GetEntryCallback {
            target: sid,
            target_type: entry_type,
            entries: Vec::new(),
        };

        if let Some(ref descriptor) = self.descriptor {
            let pDacl = descriptor.pDacl;

            if pDacl != (NULL as PACL) && !enumerate_acl_entries(pDacl, &mut callback) {
                return Err(unsafe { GetLastError() });
            }

            let pSacl = descriptor.pSacl;

            if pSacl != (NULL as PACL) && !enumerate_acl_entries(pSacl, &mut callback) {
                return Err(unsafe { GetLastError() });
            }
        }

        Ok(callback.entries)
    }

    // TODO(andy): For initial version, we do not support object, conditional ACEs

    pub fn add_entry(&mut self, sid: PSID, entry_type: AceType, flags: DWORD, mask: DWORD) {
        // TODO(andy): Create new ACL

        // TODO(andy): Create SecurityDescriptor
        // TODO(andy): Add ACL to SecurityDescriptor
        // TODO(andy): Commit SecurityDescriptor
        // TODO(andy): open new SecurityDescriptor
    }

    pub fn remove_entry(&mut self, sid: PSID, entry_type: AceType, flags: Option<DWORD>) -> Result<DWORD, DWORD> {
        // TODO(andy): Create new ACL

        //
        Err(0)
    }

    // NOTE(andy): Simple API
    pub fn allow(&mut self, sid: PSID, inheritable: bool, mask: DWORD) {
        // TODO(andy): inheritable -> flags
        let mut flags: DWORD = 0;
        self.add_entry(sid, AceType::AccessAllow, flags, mask)
    }

    pub fn deny(&mut self, sid: PSID, inheritable: bool, mask: DWORD) {
        // TODO(andy): inheritable -> flags
        let mut flags: DWORD = 0;
        self.add_entry(sid, AceType::AccessDeny, flags, mask)
    }

    pub fn audit(&mut self, sid: PSID, inheritable: bool, mask: DWORD, audit_success: bool, audit_fails: bool) {
        // TODO(andy): create flags based off inheritable, audit_{success, failure}
        let mut flags: DWORD = 0;
        self.add_entry(sid, AceType::SystemAudit, flags, mask)
    }

    pub fn integrity_level(&mut self, label_sid: PSID, inheritable: bool, policy: DWORD) {
        let mut flags: DWORD = 0;
        self.add_entry(label_sid, AceType::SystemMandatoryLabel, flags, policy)
    }

    pub fn remove(&mut self, sid: PSID, entry_type: AceType, inheritable: Option<bool>) -> Result<DWORD, DWORD> {
        let mut flags: Option<DWORD> = None;
        if let Some(inherit) = inheritable {
            if inherit {} else {}
        }

        self.remove_entry(sid, entry_type, flags)
    }
}

impl Drop for ACL {
    fn drop(&mut self) {}
}