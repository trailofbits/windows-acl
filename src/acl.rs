//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

#[allow(unused_imports)]
use field_offset::*;

use std::fmt;
use std::mem;
use utils::{sid_to_string, SecurityDescriptor};
use winapi::shared::minwindef::{BYTE, DWORD, FALSE, LPVOID, WORD};
use winapi::shared::ntdef::NULL;
use winapi::um::accctrl::{
    SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
    SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_SERVICE,
    SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::securitybaseapi::{
    AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, AddAuditAccessAceEx, AddMandatoryAce,
    CopySid, EqualSid, GetAce, GetAclInformation, GetLengthSid, InitializeAcl, IsValidAcl,
    IsValidSid,
};
use winapi::um::winnt::{
    AclSizeInformation, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE,
    ACCESS_DENIED_OBJECT_ACE_TYPE, ACCESS_MASK, ACL as _ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION,
    CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERITED_ACE, MAXDWORD, OBJECT_INHERIT_ACE,
    PACE_HEADER, PACL, PSID, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
};

/// This enum is almost a direct mapping with the values described in
/// [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type)
#[derive(Clone, Copy, Debug, PartialEq)]
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
            _ => SE_UNKNOWN_OBJECT_TYPE,
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
            _ => ObjectType::Unknown,
        }
    }
}

/// This enum is a almost direct mapping with the values described under `AceType` in
/// [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
#[derive(Clone, Copy, Debug, PartialEq)]
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

/// `ACLEntry` represents a single access control entry in an access control list
pub struct ACLEntry {
    /// The index of the current entry in the raw access control list
    pub index: u16,

    /// The entry's type
    pub entry_type: AceType,

    /// The calculated size of the current access control entry
    pub entry_size: DWORD,

    /// See `AceSize` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub size: WORD,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: BYTE,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub mask: ACCESS_MASK,

    /// The target entity's raw SID
    pub sid: Option<Vec<u16>>,

    /// The target entity's SID in string representation
    pub string_sid: String,
}

/// `ACL` represents the access control list (discretionary or oth discretionary/system) for a named object
#[derive(Debug)]
pub struct ACL {
    descriptor: Option<SecurityDescriptor>,
    path: String,
    include_sacl: bool,
    object_type: ObjectType,
}

#[allow(dead_code)]
impl ACLEntry {
    /// Returns an `ACLEntry` object with default values.
    pub fn new() -> ACLEntry {
        ACLEntry {
            index: 0,
            entry_type: AceType::Unknown,
            entry_size: 0,
            size: 0,
            flags: 0,
            mask: 0,
            sid: None,
            string_sid: "".to_string(),
        }
    }
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
            ObjectType::RegistryWow6432Key => "RegistryWow6432Key",
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
            AceType::SystemResourceAttribute => "SystemResourceAttribute",
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
                    $entry.string_sid = sid_to_string(sid.as_ptr() as PSID).unwrap_or("".to_string());
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
        GetAclInformation(
            acl,
            mem::transmute::<&mut ACL_SIZE_INFORMATION, LPVOID>(&mut si),
            mem::size_of::<ACL_SIZE_INFORMATION>() as DWORD,
            AclSizeInformation,
        )
    } == 0
    {
        return None;
    }

    Some(si.AclBytesInUse)
}

fn acl_entry_size(entry_type: AceType) -> Option<DWORD> {
    match entry_type {
        AceType::AccessAllow => Some(mem::size_of::<ACCESS_ALLOWED_ACE>() as DWORD),
        AceType::AccessAllowCallback => {
            Some(mem::size_of::<ACCESS_ALLOWED_CALLBACK_ACE>() as DWORD)
        }
        AceType::AccessAllowObject => Some(mem::size_of::<ACCESS_ALLOWED_OBJECT_ACE>() as DWORD),
        AceType::AccessAllowCallbackObject => {
            Some(mem::size_of::<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE>() as DWORD)
        }
        AceType::AccessDeny => Some(mem::size_of::<ACCESS_DENIED_ACE>() as DWORD),
        AceType::AccessDenyCallback => Some(mem::size_of::<ACCESS_DENIED_CALLBACK_ACE>() as DWORD),
        AceType::AccessDenyObject => Some(mem::size_of::<ACCESS_DENIED_OBJECT_ACE>() as DWORD),
        AceType::AccessDenyCallbackObject => {
            Some(mem::size_of::<ACCESS_DENIED_CALLBACK_OBJECT_ACE> as DWORD)
        }
        AceType::SystemAudit => Some(mem::size_of::<SYSTEM_AUDIT_ACE>() as DWORD),
        AceType::SystemAuditCallback => Some(mem::size_of::<SYSTEM_AUDIT_CALLBACK_ACE>() as DWORD),
        AceType::SystemAuditObject => Some(mem::size_of::<SYSTEM_AUDIT_OBJECT_ACE>() as DWORD),
        AceType::SystemAuditCallbackObject => {
            Some(mem::size_of::<SYSTEM_AUDIT_CALLBACK_OBJECT_ACE>() as DWORD)
        }
        AceType::SystemMandatoryLabel => {
            Some(mem::size_of::<SYSTEM_MANDATORY_LABEL_ACE>() as DWORD)
        }
        AceType::SystemResourceAttribute => {
            Some(mem::size_of::<SYSTEM_RESOURCE_ATTRIBUTE_ACE>() as DWORD)
        }
        _ => None,
    }
}

fn enumerate_acl_entries<T: EntryCallback>(pAcl: PACL, callback: &mut T) -> bool {
    if pAcl == (NULL as PACL) {
        return false;
    }

    let mut hdr: PACE_HEADER = NULL as PACE_HEADER;
    let ace_count = unsafe { (*pAcl).AceCount };

    for i in 0..ace_count {
        if unsafe {
            GetAce(
                pAcl,
                i as DWORD,
                mem::transmute::<&mut PACE_HEADER, *mut LPVOID>(&mut hdr),
            )
        } == 0
        {
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
            string_sid: String::from(""),
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
    entries: Vec<ACLEntry>,
}

struct AddEntryCallback {
    new_acl: Vec<BYTE>,
    entry_sid: PSID,
    entry_type: AceType,
    entry_flags: BYTE,
    entry_mask: DWORD,
    already_added: bool,
}

struct RemoveEntryCallback {
    removed: usize,
    new_acl: Vec<BYTE>,
    target: PSID,
    target_type: Option<AceType>,
    flags: Option<BYTE>,
}

impl EntryCallback for GetEntryCallback {
    fn on_entry(&mut self, _hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID,
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
    fn on_entry(&mut self, _hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        self.entries.push(entry);
        true
    }
}

impl AddEntryCallback {
    fn new(
        old_acl: PACL,
        sid: PSID,
        entry_type: AceType,
        flags: BYTE,
        mask: DWORD,
    ) -> Option<AddEntryCallback> {
        let mut new_acl_size =
            acl_size(old_acl).unwrap_or(mem::size_of::<_ACL>() as DWORD) as usize;
        new_acl_size += acl_entry_size(entry_type)? as usize;
        new_acl_size += unsafe { GetLengthSid(sid) as usize } - mem::size_of::<DWORD>();

        let mut obj = AddEntryCallback {
            new_acl: Vec::with_capacity(new_acl_size),
            entry_sid: sid,
            entry_type,
            entry_flags: flags,
            entry_mask: mask,
            already_added: false,
        };

        if unsafe {
            InitializeAcl(
                obj.new_acl.as_mut_ptr() as PACL,
                new_acl_size as DWORD,
                ACL_REVISION_DS as DWORD,
            )
        } == 0
        {
            return None;
        }

        Some(obj)
    }

    fn insert_entry(&mut self) -> bool {
        let status = match self.entry_type {
            AceType::AccessAllow => unsafe {
                AddAccessAllowedAceEx(
                    self.new_acl.as_mut_ptr() as PACL,
                    ACL_REVISION_DS as DWORD,
                    self.entry_flags as DWORD,
                    self.entry_mask,
                    self.entry_sid,
                )
            },
            AceType::AccessDeny => unsafe {
                AddAccessDeniedAceEx(
                    self.new_acl.as_mut_ptr() as PACL,
                    ACL_REVISION_DS as DWORD,
                    self.entry_flags as DWORD,
                    self.entry_mask,
                    self.entry_sid,
                )
            },
            AceType::SystemAudit => unsafe {
                AddAuditAccessAceEx(
                    self.new_acl.as_mut_ptr() as PACL,
                    ACL_REVISION_DS as DWORD,
                    self.entry_flags as DWORD,
                    self.entry_mask,
                    self.entry_sid,
                    FALSE,
                    FALSE,
                )
            },
            AceType::SystemMandatoryLabel => unsafe {
                AddMandatoryAce(
                    self.new_acl.as_mut_ptr() as PACL,
                    ACL_REVISION_DS as DWORD,
                    self.entry_flags as DWORD,
                    self.entry_mask,
                    self.entry_sid,
                )
            },
            _ => 0,
        };

        status != 0
    }
}

impl EntryCallback for AddEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        // NOTE(andy): Our assumption here is that the access control list are in the proper order
        //             See https://msdn.microsoft.com/en-us/library/windows/desktop/aa379298(v=vs.85).aspx

        if !self.already_added {
            if (entry.flags & INHERITED_ACE) == 0 {
                if let Some(sid) = entry.sid {
                    if entry.entry_type == self.entry_type
                        && unsafe { EqualSid(sid.as_ptr() as PSID, self.entry_sid) } != 0
                    {
                        // NOTE(andy): We found an entry that matches the type and sid of the one we were going
                        //             to add (uninherited). Instead of adding the old one and the new one, we
                        //             replace the old entry with the new entry.
                        if !self.insert_entry() {
                            return false;
                        }
                        self.already_added = true;

                        // NOTE(andy): Since we are replacing the matching entry, return true and exit the current
                        //             entry handler
                        return true;
                    }
                }

                if entry.entry_type == AceType::AccessAllow
                    && self.entry_type == AceType::AccessDeny
                {
                    // NOTE(andy): Assuming proper ordering, we just hit an uninherited access allowed ACE while
                    //             trying to add an access deny ACE. This implies that we just reached the end of
                    //             the deny ACEs. We should add the deny ACE here.
                    if !self.insert_entry() {
                        return false;
                    }
                    self.already_added = true;
                }
            } else {
                // NOTE(andy): Assuming proper ordering, our enumeration hit an inherited ACE while trying
                //             to add an access allowed, access denied, audit, or mandatory label ACE. This
                //             implies that we reached the end of the explicit ACEs. It is a good place to
                //             add access allowed, access denied, audit, or mandatory label ACE.
                if !self.insert_entry() {
                    return false;
                }
                self.already_added = true;
            }
        }

        if unsafe {
            AddAce(
                self.new_acl.as_mut_ptr() as PACL,
                ACL_REVISION_DS as DWORD,
                MAXDWORD,
                hdr as LPVOID,
                (*hdr).AceSize as DWORD,
            )
        } == 0
        {
            return false;
        }

        true
    }
}

impl RemoveEntryCallback {
    fn new(
        old_acl: PACL,
        target: PSID,
        target_type: Option<AceType>,
        flags: Option<BYTE>,
    ) -> Option<RemoveEntryCallback> {
        let new_acl_size = acl_size(old_acl)? as usize;

        let mut obj = RemoveEntryCallback {
            removed: 0,
            target,
            target_type,
            flags,
            new_acl: Vec::with_capacity(new_acl_size),
        };

        if unsafe {
            InitializeAcl(
                obj.new_acl.as_mut_ptr() as PACL,
                new_acl_size as DWORD,
                ACL_REVISION_DS as DWORD,
            )
        } == 0
        {
            return None;
        }

        Some(obj)
    }
}

impl EntryCallback for RemoveEntryCallback {
    fn on_entry(&mut self, hdr: PACE_HEADER, entry: ACLEntry) -> bool {
        let pSid: PSID = match entry.sid {
            Some(ref sid) => sid.as_ptr() as PSID,
            None => NULL as PSID,
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
                if let Some(mask) = self.flags {
                    if (entry.flags & mask) == mask {
                        // NOTE(andy) sid and flag mask all match, remove it!
                        self.removed += 1;
                        return true;
                    }
                } else {
                    // NOTE(andy): We don't have a flags mask to search for so since the sid matches
                    //             this is an item we want to remove
                    self.removed += 1;
                    return true;
                }
            }
        }

        if unsafe {
            AddAce(
                self.new_acl.as_mut_ptr() as PACL,
                ACL_REVISION_DS as DWORD,
                MAXDWORD,
                hdr as LPVOID,
                (*hdr).AceSize as DWORD,
            )
        } == 0
        {
            return false;
        }

        true
    }
}

impl ACL {
    /// Creates an `ACL` object from a specified named object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the named object path.
    /// * `object_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `get_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// For file, kernel object, and registry paths, it is better to use the simpler `from_file_path`,
    /// `from_object_path`, and `from_registry_path` APIs.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_path(
        path: &str,
        object_type: SE_OBJECT_TYPE,
        get_sacl: bool,
    ) -> Result<ACL, DWORD> {
        Ok(ACL {
            descriptor: match SecurityDescriptor::from_path(path, object_type, get_sacl) {
                Ok(s) => Some(s),
                Err(e) => return Err(e),
            },
            path: path.to_owned(),
            include_sacl: get_sacl,
            object_type: object_type.into(),
        })
    }

    /// Creates an `ACL` object from a specified file path.
    ///
    /// # Arguments
    /// * `path` - A string containing the file path.
    /// * `get_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_file_path(path: &str, get_sacl: bool) -> Result<ACL, DWORD> {
        ACL::from_path(path, SE_FILE_OBJECT, get_sacl)
    }

    /// Creates an `ACL` object from a specified kernel object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the kernel object path.
    /// * `get_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_object_path(path: &str, get_sacl: bool) -> Result<ACL, DWORD> {
        ACL::from_path(path, SE_KERNEL_OBJECT, get_sacl)
    }

    /// Creates an `ACL` object from a specified registry path.
    ///
    /// # Arguments
    /// * `path` - A string containing the registry path.
    /// * `get_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_registry_path(
        path: &str,
        is_wow6432key: bool,
        get_sacl: bool,
    ) -> Result<ACL, DWORD> {
        if is_wow6432key {
            ACL::from_path(path, SE_REGISTRY_WOW64_32KEY, get_sacl)
        } else {
            ACL::from_path(path, SE_REGISTRY_KEY, get_sacl)
        }
    }

    /// Returns the `ObjectType` of the target named object path as specified during the creation of the `ACL` object
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }

    /// Returns a `Vec<ACLEntry>` of access control list entries for the specified named object path.
    pub fn all(&self) -> Result<Vec<ACLEntry>, DWORD> {
        let mut callback = AllEntryCallback {
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

    /// Retrieves a list of access control entries matching the target SID entity and optionally, a access control entry type.
    ///
    /// # Arguments
    /// * `sid` - The raw SID of the target entity.
    /// * `entry_type` - The access control entry type or `None`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
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

    /// Update the current named object path's security descriptor. Returns a boolean denoting the status of the reload operation.
    ///
    /// # Remarks
    /// This is invoked automatically after any add/remove entry operation.
    pub fn reload(&mut self) -> bool {
        self.descriptor =
            SecurityDescriptor::from_path(&self.path, self.object_type().into(), self.include_sacl)
                .ok();

        self.descriptor.is_some()
    }

    /// Adds a custom entry into the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `entry_type` - The entry's type. Currently, only `AccessAllow`, `AccessDeny`, `SystemAudit`, and `SystemMandatoryLabel` are supported.
    /// * `flags` - See [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header) documentation.
    /// * `mask` - The permissions allotted for the target entity.
    ///
    /// # Remarks
    /// We only support (for now) adding access allow, access deny, system audit, and system mandatory label entries. After adding the entry,
    /// the security descriptor is automatically reloaded to reflect changes.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn add_entry(
        &mut self,
        sid: PSID,
        entry_type: AceType,
        flags: BYTE,
        mask: DWORD,
    ) -> Result<bool, DWORD> {
        let object_type = self.object_type();
        if let Some(ref mut descriptor) = self.descriptor {
            let mut is_dacl = false;
            let acl: PACL = match entry_type {
                AceType::AccessAllow | AceType::AccessDeny => {
                    is_dacl = true;
                    descriptor.pDacl
                }
                AceType::SystemAudit | AceType::SystemMandatoryLabel => descriptor.pSacl,
                _ => {
                    return Err(0);
                }
            };

            let mut add_callback = match AddEntryCallback::new(acl, sid, entry_type, flags, mask) {
                Some(obj) => obj,
                None => {
                    return Err(unsafe { GetLastError() });
                }
            };

            if acl != (NULL as PACL) && !enumerate_acl_entries(acl, &mut add_callback) {
                return Err(unsafe { GetLastError() });
            }

            // NOTE(andy): After enumerating the ACL, we still did not add our ACL, at this point, add it to the end
            if !add_callback.already_added && !add_callback.insert_entry() {
                return Err(unsafe { GetLastError() });
            }
            add_callback.already_added = true;

            let new_acl = add_callback.new_acl.as_ptr() as PACL;

            let status: bool;
            if is_dacl {
                status = descriptor.apply(&self.path, object_type.into(), Some(new_acl), None);
            } else {
                status = descriptor.apply(&self.path, object_type.into(), None, Some(new_acl));
            }

            if !status {
                return Err(unsafe { GetLastError() });
            }
        }

        if !self.reload() {
            return Err(unsafe { GetLastError() });
        }

        Ok(true)
    }

    /// Removes access control list entries that match the specified parameters.
    ///
    /// # Arguments
    /// * `sid` - The target entry's raw SID.
    /// * `entry_type` - The entry's type.
    /// * `flags` - See [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header) documentation.
    ///
    /// # Remarks
    /// After removing the entry, the security descriptor is reloaded automatically to reflect changes.
    ///
    /// # Errors
    /// On error, a Windows error code wrapped in a `Err` type.
    pub fn remove_entry(
        &mut self,
        sid: PSID,
        entry_type: Option<AceType>,
        flags: Option<BYTE>,
    ) -> Result<usize, DWORD> {
        let mut removed_entries = 0;
        let object_type = self.object_type().into();

        if let Some(ref mut descriptor) = self.descriptor {
            let dacl_result: Option<RemoveEntryCallback> = if descriptor.pDacl != (NULL as PACL)
            {
                RemoveEntryCallback::new(descriptor.pDacl, sid, entry_type, flags)
            } else {
                None
            };

            if let Some(mut dacl_callback) = dacl_result {
                if !enumerate_acl_entries(descriptor.pDacl, &mut dacl_callback) {
                    return Err(unsafe { GetLastError() });
                }
                removed_entries += dacl_callback.removed;

                if !descriptor.apply(
                    &self.path,
                    object_type,
                    Some(dacl_callback.new_acl.as_ptr() as PACL),
                    None,
                ) {
                    return Err(unsafe { GetLastError() });
                }
            }

            let sacl_result: Option<RemoveEntryCallback> = if descriptor.pSacl != (NULL as PACL)
            {
                RemoveEntryCallback::new(descriptor.pSacl, sid, entry_type, flags)
            } else {
                None
            };

            if let Some(mut sacl_callback) = sacl_result {
                if !enumerate_acl_entries(descriptor.pSacl, &mut sacl_callback) {
                    return Err(unsafe { GetLastError() });
                }
                removed_entries += sacl_callback.removed;

                if !descriptor.apply(
                    &self.path,
                    object_type,
                    None,
                    Some(sacl_callback.new_acl.as_ptr() as PACL),
                ) {
                    return Err(unsafe { GetLastError() });
                }
            }
        }

        if !self.reload() {
            return Err(unsafe { GetLastError() });
        }

        Ok(removed_entries)
    }

    /// Adds an access allow entry to the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `mask` - The allowed permissions for the target entity.
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn allow(&mut self, sid: PSID, inheritable: bool, mask: DWORD) -> Result<bool, DWORD> {
        let mut flags: BYTE = 0;

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }
        self.add_entry(sid, AceType::AccessAllow, flags, mask)
    }

    /// Adds an access deny entry to the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `mask` - The denied permissions for the target entity.
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn deny(&mut self, sid: PSID, inheritable: bool, mask: DWORD) -> Result<bool, DWORD> {
        let mut flags: BYTE = 0;

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }
        self.add_entry(sid, AceType::AccessDeny, flags, mask)
    }

    /// Adds a system audit entry to the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `mask` - The permissions to audit.
    /// * `audit_success` - Denotes that success events should be audited.
    /// * `audit_fails` - Denotes that failure events should be audited.
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn audit(
        &mut self,
        sid: PSID,
        inheritable: bool,
        mask: DWORD,
        audit_success: bool,
        audit_fails: bool,
    ) -> Result<bool, DWORD> {
        let mut flags: BYTE = 0;

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }

        if audit_success {
            flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
        }

        if audit_fails {
            flags |= FAILED_ACCESS_ACE_FLAG;
        }

        self.add_entry(sid, AceType::SystemAudit, flags, mask)
    }

    /// Adds a system mandatory level entry to the access control list. This sets the mandatory integrity level for the named object path.
    ///
    /// # Arguments
    /// * `label_sid` - See `pLabelSid` in [AddMandatoryAce](https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-addmandatoryace)
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `policy` - See `MandatoryPolicy` in [AddMandatoryAce](https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-addmandatoryace)
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn integrity_level(
        &mut self,
        label_sid: PSID,
        inheritable: bool,
        policy: DWORD,
    ) -> Result<bool, DWORD> {
        let mut flags: BYTE = 0;

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }
        self.add_entry(label_sid, AceType::SystemMandatoryLabel, flags, policy)
    }

    /// Removes access control list entries that match the specified parameters.
    ///
    /// # Arguments
    /// * `sid` - The target entry's raw SID.
    /// * `entry_type` - The entry's type.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    ///
    /// # Remarks
    /// This is a wrapper over `remove_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn remove(
        &mut self,
        sid: PSID,
        entry_type: Option<AceType>,
        inheritable: Option<bool>,
    ) -> Result<usize, DWORD> {
        let mut flags: Option<BYTE> = None;
        if let Some(inherit) = inheritable {
            if inherit {
                flags = Some(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
            }
        }

        self.remove_entry(sid, entry_type, flags)
    }
}

impl Drop for ACL {
    fn drop(&mut self) {}
}
