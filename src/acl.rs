#![allow(non_snake_case)]

use field_offset::*;
use std::fmt;
use std::mem;
use utils::SecurityDescriptor;
use winapi::shared::minwindef::{
    BYTE, DWORD, LPVOID, WORD,
};
use winapi::shared::ntdef::NULL;
use winapi::um::accctrl::{
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
    SE_SERVICE, SE_UNKNOWN_OBJECT_TYPE, SE_PRINTER, SE_LMSHARE, SE_DS_OBJECT, SE_DS_OBJECT_ALL,
    SE_PROVIDER_DEFINED_OBJECT, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::securitybaseapi::{
    AddAce, CopySid, EqualSid, GetAce, GetAclInformation, GetLengthSid, IsValidAcl, IsValidSid,
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
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, MAXDWORD, ACL_REVISION, AclSizeInformation, ACL_SIZE_INFORMATION,
};

#[derive(Clone, Copy, PartialEq)]
pub enum ObjectType {
    Unknown = 0,
    FileObject,
    ServiceObject,
    PrinterObject,
    RegistryKey,
    LmShare,
    KernelObject,
    WindowObject,
    DsObject,
    DsObjectAll,
    ProviderDefinedObject,
    WmiGuidObject,
    RegistryWow6432Key,
}

impl From<ObjectType> for SE_OBJECT_TYPE {
    fn from(obj_type: ObjectType) -> Self {
        match obj_type {
            ObjectType::FileObject => SE_FILE_OBJECT,
            ObjectType::ServiceObject => SE_SERVICE,
            ObjectType::PrinterObject => SE_PRINTER,
            ObjectType::RegistryKey => SE_REGISTRY_KEY,
            ObjectType::LmShare => SE_LMSHARE,
            ObjectType::KernelObject => SE_KERNEL_OBJECT,
            ObjectType::WindowObject => SE_WINDOW_OBJECT,
            ObjectType::DsObject => SE_DS_OBJECT,
            ObjectType::DsObjectAll => SE_DS_OBJECT_ALL,
            ObjectType::ProviderDefinedObject => SE_PROVIDER_DEFINED_OBJECT,
            ObjectType::WmiGuidObject => SE_WMIGUID_OBJECT,
            ObjectType::RegistryWow6432Key => SE_REGISTRY_WOW64_32KEY,
            _ => SE_UNKNOWN_OBJECT_TYPE
        }
    }
}

impl From<SE_OBJECT_TYPE> for ObjectType {
    fn from(obj_type: SE_OBJECT_TYPE) -> Self {
        match obj_type {
            SE_FILE_OBJECT => ObjectType::FileObject,
            SE_SERVICE => ObjectType::ServiceObject,
            SE_PRINTER => ObjectType::PrinterObject,
            SE_REGISTRY_KEY => ObjectType::RegistryKey,
            SE_LMSHARE => ObjectType::LmShare,
            SE_KERNEL_OBJECT => ObjectType::KernelObject,
            SE_WINDOW_OBJECT => ObjectType::WindowObject,
            SE_DS_OBJECT => ObjectType::DsObject,
            SE_DS_OBJECT_ALL => ObjectType::DsObjectAll,
            SE_PROVIDER_DEFINED_OBJECT => ObjectType::ProviderDefinedObject,
            SE_WMIGUID_OBJECT => ObjectType::WmiGuidObject,
            SE_REGISTRY_WOW64_32KEY => ObjectType::RegistryWow6432Key,
            _ => ObjectType::Unknown
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
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
    pub index: u16,
    pub entry_type: AceType,
    pub entry_size: DWORD,
    pub size: WORD,
    pub flags: BYTE,
    pub mask: ACCESS_MASK,
    pub sid: Option<Vec<u16>>,
}

pub struct ACL {
    descriptor: Option<SecurityDescriptor>,
    path: String,
    include_sacl: bool,
    object_type: ObjectType,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let obj_type = match *self {
            ObjectType::Unknown => "Unknown",
            ObjectType::FileObject => "FileObject",
            ObjectType::ServiceObject => "ServiceObject",
            ObjectType::PrinterObject => "PrinterObject",
            ObjectType::RegistryKey => "RegistryKey",
            ObjectType::LmShare => "LmShare",
            ObjectType::KernelObject => "KernelObject",
            ObjectType::WindowObject => "WindowObject",
            ObjectType::DsObject => "DsObject",
            ObjectType::DsObjectAll => "DsObjectAll",
            ObjectType::ProviderDefinedObject => "ProviderDefinedObject",
            ObjectType::WmiGuidObject => "WmiGuidObject",
            ObjectType::RegistryWow6432Key => "RegistryWow6432Key"
        };
        write!(f, "{}", obj_type)
    }
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
                    // NOTE(andy): This calculation needs double checking but should be correct...
                    $entry.entry_size = (mem::size_of::<$cls>() as DWORD) -
                                        (mem::size_of::<DWORD>() as DWORD) +
                                        unsafe { GetLengthSid(sid.as_ptr() as PSID) };
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

fn acl_size(acl: PACL) -> Option<DWORD> {
    let mut si: ACL_SIZE_INFORMATION = unsafe { mem::zeroed::<ACL_SIZE_INFORMATION>() };

    if acl == (NULL as PACL) || unsafe { IsValidAcl(acl) } == 0 {
        return None;
    }

    if unsafe {
        GetAclInformation(acl,
                          mem::transmute::<&mut ACL_SIZE_INFORMATION, LPVOID>(&mut si),
                          mem::size_of::<ACL_SIZE_INFORMATION>() as DWORD,
                          AclSizeInformation)
    } == 0 {
        return None;
    }

    Some(si.AclBytesInUse)
}

fn acl_entry_size(entry_type: AceType) -> Option<DWORD> {
    match entry_type {
        AceType::AccessAllow => Some(mem::size_of::<ACCESS_ALLOWED_ACE>() as DWORD),
        AceType::AccessAllowCallback => Some(mem::size_of::<ACCESS_ALLOWED_CALLBACK_ACE>() as DWORD),
        AceType::AccessAllowObject => Some(mem::size_of::<ACCESS_ALLOWED_OBJECT_ACE>() as DWORD),
        AceType::AccessAllowCallbackObject => Some(mem::size_of::<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE>() as DWORD),
        AceType::AccessDeny => Some(mem::size_of::<ACCESS_DENIED_ACE>() as DWORD),
        AceType::AccessDenyCallback => Some(mem::size_of::<ACCESS_DENIED_CALLBACK_ACE>() as DWORD),
        AceType::AccessDenyObject => Some(mem::size_of::<ACCESS_DENIED_OBJECT_ACE>() as DWORD),
        AceType::AccessDenyCallbackObject => Some(mem::size_of::<ACCESS_DENIED_CALLBACK_OBJECT_ACE> as DWORD),
        AceType::SystemAudit => Some(mem::size_of::<SYSTEM_AUDIT_ACE>() as DWORD),
        AceType::SystemAuditCallback => Some(mem::size_of::<SYSTEM_AUDIT_CALLBACK_ACE>() as DWORD),
        AceType::SystemAuditObject => Some(mem::size_of::<SYSTEM_AUDIT_OBJECT_ACE>() as DWORD),
        AceType::SystemAuditCallbackObject => Some(mem::size_of::<SYSTEM_AUDIT_CALLBACK_OBJECT_ACE>() as DWORD),
        AceType::SystemMandatoryLabel => Some(mem::size_of::<SYSTEM_MANDATORY_LABEL_ACE>() as DWORD),
        AceType::SystemResourceAttribute => Some(mem::size_of::<SYSTEM_RESOURCE_ATTRIBUTE_ACE>() as DWORD),
        _ => None
    }
}

fn enumerate_acl_entries<T: EntryCallback>(pAcl: PACL, callback: &mut T) -> bool {
    if pAcl == (NULL as PACL) {
        return false;
    }

    let mut hdr: PACE_HEADER = NULL as PACE_HEADER;
    let ace_count = unsafe { (*pAcl).AceCount };

    for i in 0..ace_count {
        if unsafe { GetAce(pAcl, i as DWORD, mem::transmute::<&mut PACE_HEADER, *mut LPVOID>(&mut hdr)) } == 0 {
            return false;
        }

        let mut entry = ACLEntry {
            index: i,
            entry_type: AceType::Unknown,
            entry_size: 0,
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

struct AddEntryCallback {
    new_acl: Vec<BYTE>
}

struct RemoveEntryCallback {
    removed: usize,
    new_acl: Vec<BYTE>,
    target: PSID,
    target_type: Option<AceType>,
    flags: Option<BYTE>,
}

impl EntryCallback for GetEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID
        };

        if pSid == NULL {
            return false;
        }

        if unsafe { EqualSid(self.target, pSid) } != 0 {
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

impl AddEntryCallback {
    fn new(old_acl: PACL, sid: PSID, entry_type: AceType, flags: BYTE, mask: DWORD) -> Option<AddEntryCallback> {
        let mut new_acl_size = acl_size(old_acl)? as usize;
        new_acl_size += acl_entry_size(entry_type)? as usize;
        new_acl_size += unsafe { GetLengthSid(sid) as usize } - mem::size_of::<DWORD>();

        Some(AddEntryCallback {
            new_acl: Vec::with_capacity(new_acl_size)
        })
    }
}

impl EntryCallback for AddEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        // TODO(andy):

        false
    }
}

impl RemoveEntryCallback {
    fn new(old_acl: PACL, target: PSID, target_type: Option<AceType>, flags: Option<BYTE>) -> Option<RemoveEntryCallback> {
        let new_acl_size = acl_size(old_acl)? as usize;

        Some(RemoveEntryCallback {
            removed: 0,
            target,
            target_type,
            flags,
            new_acl: Vec::with_capacity(new_acl_size),
        })
    }
}

impl EntryCallback for RemoveEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID
        };

        if pSid == NULL {
            return false;
        }

        if unsafe { EqualSid(self.target, pSid) } != 0 {
            if let Some(ref t) = self.target_type {
                if entry.entry_type == *t {
                    if let Some(mask) = self.flags {
                        if (entry.flags & mask) == mask {
                            // NOTE(andy) sid, entry_type, and flag mask all match, remove it!
                            self.removed += 1;
                            return true;
                        }
                    } else {
                        // NOTE(andy): We don't have a flags mask to search for so since the entry_type and sid match
                        //             this is an item we want to remove
                        self.removed += 1;
                        return true;
                    }
                }
            } else {
                // NOTE(andy): No target type means all entries with matching sid are removed
                self.removed += 1;
                return true;
            }
        }

        if unsafe {
            AddAce(self.new_acl.as_mut_ptr() as PACL,
                   ACL_REVISION as DWORD,
                   MAXDWORD,
                   hdr as LPVOID,
                   (*hdr).AceSize as DWORD)
        } == 0 {
            return false;
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
            path: path.to_owned(),
            include_sacl: get_sacl,
            object_type: object_type.into(),
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

    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }

    pub fn all(&self) -> Result<Vec<ACLEntry>, DWORD> {
        let mut callback = AllEntryCallback {
            entries: Vec::new()
        };

        if let Some(ref descriptor) = self.descriptor {
            for acl in [descriptor.pDacl, descriptor.pSacl].iter() {
                if *acl != (NULL as PACL) && !enumerate_acl_entries(*acl, &mut callback) {
                    return Err(unsafe { GetLastError() });
                }
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
            for acl in [descriptor.pDacl, descriptor.pSacl].iter() {
                if *acl != (NULL as PACL) && !enumerate_acl_entries(*acl, &mut callback) {
                    return Err(unsafe { GetLastError() });
                }
            }
        }

        Ok(callback.entries)
    }

    // TODO(andy): For initial version, we do not support object, conditional ACEs

    pub fn add_entry(&mut self, sid: PSID, entry_type: AceType, flags: BYTE, mask: DWORD) {
        // TODO(andy): Depending on entry_type, create the appropriate callback

        // TODO(andy): Create SecurityDescriptor
        // TODO(andy): Add ACL to SecurityDescriptor
        // TODO(andy): Apply SecurityDescriptor to self.path

        // TODO(andy): Replace current SecurityDescriptor with a new one opened with from_path
    }

    pub fn remove_entry(&mut self, sid: PSID, entry_type: Option<AceType>, flags: Option<BYTE>) -> Result<usize, DWORD> {
        let mut removed_entries = 0;

        if let Some(ref descriptor) = self.descriptor {
            let mut dacl_callback = match RemoveEntryCallback::new(descriptor.pDacl, sid, entry_type, flags) {
                Some(obj) => obj,
                None => return Err(unsafe { GetLastError() })
            };

            if !enumerate_acl_entries(descriptor.pDacl, &mut dacl_callback) {
                return Err(unsafe { GetLastError() });
            }
            removed_entries = dacl_callback.removed;

            let mut sacl_callback = match RemoveEntryCallback::new(descriptor.pSacl, sid, entry_type, flags) {
                Some(obj) => obj,
                None => return Err(unsafe { GetLastError() })
            };

            if !enumerate_acl_entries(descriptor.pSacl, &mut sacl_callback) {
                return Err(unsafe { GetLastError() });
            }
            removed_entries += sacl_callback.removed;

            // TODO(andy): Create SecurityDescriptor
            // TODO(andy): Add DACL to SecurityDescriptor if appropriate
            // TODO(andy): Add SACL to SecurityDescriptor if appropriate
            // TODO(andy): Apply SecurityDescriptor to self.path

            // TODO(andy): Replace current SecurityDescriptor with a new one opened with from_path
        }

        Ok(removed_entries)
    }

    // NOTE(andy): Simple API
    pub fn allow(&mut self, sid: PSID, inheritable: bool, mask: DWORD) {
        // TODO(andy): inheritable -> flags
        let mut flags: BYTE = 0;
        self.add_entry(sid, AceType::AccessAllow, flags, mask)
    }

    pub fn deny(&mut self, sid: PSID, inheritable: bool, mask: DWORD) {
        // TODO(andy): inheritable -> flags
        let mut flags: BYTE = 0;
        self.add_entry(sid, AceType::AccessDeny, flags, mask)
    }

    pub fn audit(&mut self, sid: PSID, inheritable: bool, mask: DWORD, audit_success: bool, audit_fails: bool) {
        // TODO(andy): create flags based off inheritable, audit_{success, failure}
        let mut flags: BYTE = 0;
        self.add_entry(sid, AceType::SystemAudit, flags, mask)
    }

    pub fn integrity_level(&mut self, label_sid: PSID, inheritable: bool, policy: DWORD) {
        let mut flags: BYTE = 0;
        self.add_entry(label_sid, AceType::SystemMandatoryLabel, flags, policy)
    }

    pub fn remove(&mut self, sid: PSID, entry_type: Option<AceType>, inheritable: Option<bool>) -> Result<usize, DWORD> {
        let mut flags: Option<BYTE> = None;
        if let Some(inherit) = inheritable {
            if inherit {} else {}
        }

        self.remove_entry(sid, entry_type, flags)
    }
}

impl Drop for ACL {
    fn drop(&mut self) {}
}