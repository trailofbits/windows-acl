#![cfg(windows)]

extern crate clap;
extern crate winapi;
extern crate windows_acl;

use clap::{
    App, Arg,
};
use winapi::um::winnt::{
    CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERIT_ONLY_ACE, INHERITED_ACE, NO_PROPAGATE_INHERIT_ACE,
    OBJECT_INHERIT_ACE, PSID, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};
use winapi::um::winnt::{
    DELETE, GENERIC_READ, GENERIC_WRITE, GENERIC_ALL, GENERIC_EXECUTE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    MAXIMUM_ALLOWED, SYNCHRONIZE, FILE_WRITE_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_DELETE_CHILD, FILE_EXECUTE,
    FILE_WRITE_EA, FILE_READ_EA, FILE_APPEND_DATA, FILE_WRITE_DATA, FILE_READ_DATA, STANDARD_RIGHTS_ALL,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ALL_ACCESS
};
use windows_acl::acl::{
    ACL, ACLEntry, AceType, ObjectType,
};
use windows_acl::helper::{
    sid_to_string
};

fn process_entry(acl: &ACL, ent: &ACLEntry) {
    let sid_string = match ent.sid {
        Some(ref sid) => {
            sid_to_string((*sid).as_ptr() as PSID).unwrap_or_else(
                | _ | "BadFormat".to_string()
            )
        }
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
        if (ent.flags & flag) > 0 {
            if flags.len() > 0 {
                flags += " |\n          ";
            }
            flags += desc;
        }
    }
    if flags.len() == 0 {
        flags += "None";
    }

    let mut masks: String = String::new();
    if ent.entry_type == AceType::SystemMandatoryLabel {
        let defined_masks = [
            (SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, "NoExecUp"),
            (SYSTEM_MANDATORY_LABEL_NO_READ_UP, "NoReadUp"),
            (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "NoWriteUp")];
        for &(mask, desc) in &defined_masks {
            if (ent.mask & mask) > 0 {
                if masks.len() > 0 {
                    masks += " |\n         ";
                }
                masks += desc;
            }
        }
    } else {
        match acl.object_type() {
            ObjectType::FileObject => {
                if (ent.mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS {
                    if masks.len() > 0 {
                        masks += " |\n         ";
                    }
                    masks += "FileAllAccess";
                } else {
                    // NOTE(andy): For files with ACLs set by PowerShell CmdLets, SYNCHRONIZE is usually not set?!

                    if (ent.mask & FILE_GENERIC_READ) == (FILE_GENERIC_READ & !SYNCHRONIZE) {
                        if masks.len() > 0 {
                            masks += " |\n         ";
                        }
                        masks += "FileGenericRead";
                    }

                    if (ent.mask & FILE_GENERIC_WRITE) == (FILE_GENERIC_WRITE & !SYNCHRONIZE) {
                        if masks.len() > 0 {
                            masks += " |\n         ";
                        }
                        masks += "FileGenericWrite";
                    }

                    if (ent.mask & FILE_GENERIC_EXECUTE) == (FILE_GENERIC_EXECUTE & !SYNCHRONIZE) {
                        if masks.len() > 0 {
                            masks += " |\n         ";
                        }
                        masks += "FileGenericExec";
                    }

                    // NOTE(andy): Custom rights that require detailed enumeration
                    if masks.len() == 0 {
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
                        for &(mask, desc) in &defined_specific_rights {
                            if (ent.mask & mask) > 0 {
                                if masks.len() > 0 {
                                    masks += " |\n         ";
                                }
                                masks += desc;
                            }
                        }
                    }
                }
            }
            _ => {
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
                if (ent.mask & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL {
                    masks += "StandardRightsAll";
                } else {
                    for &(mask, desc) in &defined_std_rights {
                        if (ent.mask & mask) > 0 {
                            if masks.len() > 0 {
                                masks += " |\n         ";
                            }
                            masks += desc;
                        }
                    }
                }
            }
        }
    }
    if masks.len() == 0 {
        masks += "None";
    }

    println!("  AccessControlEntry[{}] {{", ent.index);
    println!("    Type={}", ent.entry_type);
    println!("    Flags={}", flags);
    println!("    Sid={}", sid_string);
    println!("    Mask={}", masks);
    println!("    RawMask=0x{:x}", ent.mask);
    println!("  }}");
}

pub fn main() {
    let matches = App::new("Query ACL")
        .about("Enumerates the ACLs on a named object")
        .arg(Arg::with_name("registry")
            .short("r")
            .long("registry")
            .help("Named object is a registry key")
            .takes_value(false))
        .arg(Arg::with_name("path")
            .help("Named object path")
            .required(true)
            .index(1))
        .get_matches();

    let path = matches.value_of("path").unwrap();
    let acl: Option<ACL>;

    if matches.is_present("registry") {
        acl = ACL::from_registry_path(path, false, true).or_else(
            |code| {
                println!("Failed to read ACLs for registry path {}: GLE={}", path, code);
                Err(code)
            }).ok();
    } else {
        acl = ACL::from_file_path(path, true).or_else(
            |code| {
                println!("Failed to read ACLs for file path {}: GLE={}", path, code);
                Err(code)
            }).ok();
    }

    match acl {
        Some(acl) => {
            let entries = acl.all().unwrap_or_else(
                |code| {
                    println!("Failed to enumerate access control entries: GLE={}", code);
                    Vec::new()
                }
            );

            println!("Access control entries for {}", path);
            println!("Named object type: {}", acl.object_type());

            for entry in &entries {
                process_entry(&acl, entry);
            }
        }
        None => {
            println!("ACLs could not be read from specified named object: ");
        }
    }
}