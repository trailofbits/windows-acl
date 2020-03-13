#![cfg(windows)]

use acl::{ACLEntry, AceType, ACL};
use std::env::current_exe;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Once, ONCE_INIT};
use utils::{current_user, name_to_sid, sid_to_string, string_to_sid};
use winapi::shared::winerror::ERROR_NOT_ALL_ASSIGNED;
use winapi::um::winnt::{
    FAILED_ACCESS_ACE_FLAG, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, PSID, SUCCESSFUL_ACCESS_ACE_FLAG, SYNCHRONIZE,
    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};

static START: Once = ONCE_INIT;

fn support_path() -> Option<PathBuf> {
    if let Ok(mut path) = current_exe() {
        for _ in 0..6 {
            path.pop();

            path.push("support");

            if path.exists() {
                path.push("testfiles");
                return Some(path);
            }

            path.pop();
        }
    } else {
        assert!(false, "current_exe failed");
    }

    None
}

fn run_ps_script(file_name: &str) -> bool {
    if let Some(mut path) = support_path() {
        path.pop();
        path.push(file_name);

        if let Some(script_path) = path.to_str() {
            let mut process = match Command::new("PowerShell.exe")
                .args(&["-ExecutionPolicy", "bypass", "-File", script_path])
                .spawn()
            {
                Ok(process) => process,
                _ => {
                    return false;
                }
            };

            match process.wait() {
                Ok(_code) => {
                    return true;
                }
                Err(_code) => {
                    return false;
                }
            }
        }
    }

    false
}

fn string_sid_by_user(user: &str) -> String {
    let user_sid = name_to_sid(user, None).unwrap_or(Vec::new());
    assert_ne!(user_sid.capacity(), 0);

    let user_string_sid = sid_to_string(user_sid.as_ptr() as PSID).unwrap_or(String::from(""));
    assert_ne!(user_string_sid.len(), 0);

    user_string_sid
}

fn current_user_string_sid() -> String {
    let username = current_user().unwrap_or(String::from(""));
    assert_ne!(username.len(), 0);

    string_sid_by_user(&username)
}

#[test]
fn lookupname_unit_test() {
    let world_name = "Everyone";
    let world_string_sid = "S-1-1-0";

    let raw_world_sid = name_to_sid(world_name, None).unwrap_or(Vec::new());
    assert_ne!(raw_world_sid.capacity(), 0);

    let sid_string = sid_to_string(raw_world_sid.as_ptr() as PSID).unwrap_or(String::from(""));
    assert_ne!(sid_string.len(), 0);

    assert_eq!(sid_string, world_string_sid);
}

#[test]
fn sidstring_unit_test() {
    let world_string_sid = "S-1-5-21";

    let sid = string_to_sid(world_string_sid).unwrap_or(Vec::new());
    assert_ne!(sid.capacity(), 0);

    let sid_string = sid_to_string(sid.as_ptr() as PSID).unwrap_or(String::from(""));
    assert_ne!(sid_string.len(), 0);

    assert_eq!(sid_string, world_string_sid);
}

fn acl_entry_exists(entries: &Vec<ACLEntry>, expected: &ACLEntry) -> Option<usize> {
    for i in 0..(entries.len()) {
        let entry = &entries[i];

        if entry.entry_type == expected.entry_type
            && entry.string_sid == expected.string_sid
            && entry.flags == expected.flags
            && entry.mask == expected.mask
        {
            return Some(i);
        }
    }

    None
}

// Make sure we can read DACL entries set by an external tool (PowerShell)
#[test]
fn query_dacl_unit_test() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let guest_sid = string_sid_by_user("Guest");
    let current_user_sid = current_user_string_sid();

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("query_test");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let acl_result = ACL::from_file_path(path, false);
    assert!(acl_result.is_ok());

    let acl = acl_result.unwrap();
    let entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new();
    expected.entry_type = AceType::AccessDeny;
    expected.string_sid = guest_sid;
    expected.flags = 0;
    expected.mask = (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE;

    let deny_idx = match acl_entry_exists(&entries, &expected) {
        Some(i) => i,
        None => {
            println!("Expected AccessDeny entry does not exist!");
            assert!(false);
            return;
        }
    };

    expected.entry_type = AceType::AccessAllow;
    expected.string_sid = current_user_sid;
    expected.flags = 0;

    // NOTE(andy): For ACL entries added by CmdLets on files, SYNCHRONIZE is not set
    expected.mask = FILE_ALL_ACCESS;

    let allow_idx = match acl_entry_exists(&entries, &expected) {
        Some(i) => i,
        None => {
            println!("Expected AccessAllow entry does not exist!");
            assert!(false);
            return;
        }
    };

    assert!(deny_idx < allow_idx);
}

// Make sure we can read SACL entries set by external tools (PowerShell/.NET)
#[test]
fn query_sacl_unit_test() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let world_sid = string_sid_by_user("Everyone");

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("query_sacl_test");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let acl = match ACL::from_file_path(path, true) {
        Ok(obj) => obj,
        Err(code) => {
            assert_eq!(code, ERROR_NOT_ALL_ASSIGNED);
            println!("INFO: Terminating query_sacl_unit_test early because we are not Admin.");
            return;
        }
    };

    let entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new();
    expected.entry_type = AceType::SystemAudit;
    expected.string_sid = world_sid;
    expected.flags = SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG;
    expected.mask = (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !SYNCHRONIZE;

    let allow_idx = match acl_entry_exists(&entries, &expected) {
        Some(i) => i,
        None => {
            println!("Expected SystemAudit entry does not exist!");
            assert!(false);
            return;
        }
    };

    assert!(allow_idx > 0);
}

// Ensure that we can add and remove DACL access allow entries
#[test]
fn add_and_remove_dacl_allow_test() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let current_user = current_user_string_sid();
    let current_user_sid = match string_to_sid(&current_user) {
        Ok(x) => x,
        Err(x) => {
            println!("string_to_sid failed for {}: GLE={}", current_user, x);
            assert_eq!(x, 0);
            return;
        }
    };

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("dacl_allow_file");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    // NOTE(andy): create() opens for write only or creates new if path doesn't exist. Since we know
    //             that the path exists (see line 255), this will attempt to open for write, which
    //             should fail
    assert!(File::create(path).is_err());

    let acl_result = ACL::from_file_path(path, false);
    assert!(acl_result.is_ok());

    let mut acl = acl_result.unwrap();

    match acl.allow(
        current_user_sid.as_ptr() as PSID,
        false,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
    ) {
        Ok(x) => assert!(x),
        Err(x) => {
            println!(
                "ACL.allow failed for adding allow ACE for {} to FILE_GENERIC_READ: GLE={}",
                &current_user, x
            );
            assert!(false);
            return;
        }
    }

    // NOTE(andy): Our explicit allow entry should make this pass now
    assert!(File::create(path).is_ok());

    let mut entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new();
    expected.entry_type = AceType::AccessAllow;
    expected.string_sid = current_user.to_string();
    expected.flags = 0;
    expected.mask = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

    match acl_entry_exists(&entries, &expected) {
        Some(_i) => {}
        None => {
            println!("Expected AccessAllow entry does not exist!");
            assert!(false);
            return;
        }
    };

    match acl.remove(
        current_user_sid.as_ptr() as PSID,
        Some(AceType::AccessAllow),
        Some(false),
    ) {
        Ok(x) => assert_eq!(x, 1),
        Err(x) => {
            println!(
                "ACL.remove failed for removing allow ACE for {} to FILE_GENERIC_READ: GLE={}",
                &current_user, x
            );
            assert!(false);
            return;
        }
    }

    assert!(File::create(path).is_err());

    entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);
    match acl_entry_exists(&entries, &expected) {
        None => {}
        Some(i) => {
            println!("Did not expect to find AccessAllow entry at {}", i);
            assert!(false);
            return;
        }
    }
}

// Ensure we can add and remove DACL access deny entries
#[test]
fn add_and_remove_dacl_deny_test() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let current_user = current_user_string_sid();
    let current_user_sid = match string_to_sid(&current_user) {
        Ok(x) => x,
        Err(x) => {
            println!("string_to_sid failed for {}: GLE={}", current_user, x);
            assert_eq!(x, 0);
            return;
        }
    };

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("dacl_deny_file");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    // NOTE(andy): create() opens for write only or creates new if path doesn't exist. Since we know
    //             that the path exists (see line 313), this will attempt to open for write, which
    //             should fail
    assert!(File::create(path).is_ok());

    let acl_result = ACL::from_file_path(path, false);
    assert!(acl_result.is_ok());

    let mut acl = acl_result.unwrap();
    match acl.deny(current_user_sid.as_ptr() as PSID, false, FILE_GENERIC_WRITE) {
        Ok(x) => assert!(x),
        Err(x) => {
            println!(
                "ACL.deny failed for adding allow ACE for {} to FILE_GENERIC_READ: GLE={}",
                current_user, x
            );
            assert!(false);
            return;
        }
    }

    // NOTE(andy): Since we added a deny entry for WRITE, this should fail
    assert!(File::create(path).is_err());

    let mut entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new();
    expected.entry_type = AceType::AccessDeny;
    expected.string_sid = current_user.to_string();
    expected.flags = 0;
    expected.mask = FILE_GENERIC_WRITE;

    match acl_entry_exists(&entries, &expected) {
        Some(_i) => {}
        None => {
            println!("Expected AccessDeny entry does not exist!");
            assert!(false);
            return;
        }
    }

    match acl.remove(
        current_user_sid.as_ptr() as PSID,
        Some(AceType::AccessDeny),
        Some(false),
    ) {
        Ok(x) => assert_eq!(x, 1),
        Err(x) => {
            println!(
                "ACL.remove failed for removing deny ACE for {} to FILE_GENERIC_READ: GLE={}",
                current_user, x
            );
            assert!(false);
            return;
        }
    }

    assert!(File::open(path).is_ok());

    entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    match acl_entry_exists(&entries, &expected) {
        None => {}
        Some(i) => {
            println!("AccessDeny unexpectedly exists at {}", i);
            assert!(false);
            return;
        }
    }
}

// Ensure we can add and remove a SACL mandatory level entry
#[test]
fn add_remove_sacl_mil() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let low_mil_string_sid = "S-1-16-4096";
    let low_mil_sid = match string_to_sid(&low_mil_string_sid) {
        Ok(x) => x,
        Err(x) => {
            println!("string_to_sid failed for {}: GLE={}", low_mil_string_sid, x);
            assert_eq!(x, 0);
            return;
        }
    };

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("sacl_mil_file");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let acl_result = ACL::from_file_path(path, true);
    assert!(acl_result.is_ok());

    let mut acl = acl_result.unwrap();
    match acl.integrity_level(
        low_mil_sid.as_ptr() as PSID,
        false,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            | SYSTEM_MANDATORY_LABEL_NO_READ_UP
            | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
    ) {
        Ok(x) => assert!(x),
        Err(x) => {
            println!(
                "ACL.integrity_level failed for {}: GLE={}",
                &low_mil_string_sid, x
            );
            assert!(false);
            return;
        }
    }

    let mut entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new();
    expected.entry_type = AceType::SystemMandatoryLabel;
    expected.string_sid = low_mil_string_sid.to_string();
    expected.flags = 0;
    expected.mask = SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
        | SYSTEM_MANDATORY_LABEL_NO_READ_UP
        | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;

    assert!(acl_entry_exists(&entries, &expected).is_some());

    match acl.remove(
        low_mil_sid.as_ptr() as PSID,
        Some(AceType::SystemMandatoryLabel),
        Some(false),
    ) {
        Ok(x) => assert_eq!(x, 1),
        Err(x) => {
            println!(
                "ACL.remove failed for removing mandatory ACE for {}: GLE={}",
                low_mil_string_sid, x
            );
            assert!(false);
            return;
        }
    }

    entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    assert!(acl_entry_exists(&entries, &expected).is_none());
}

// Make sure we can add and remove a SACL audit entry
#[test]
fn add_remove_sacl_audit() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("sacl_audit_file");
    assert!(path_obj.exists());

    let current_user = current_user_string_sid();
    let current_user_sid = match string_to_sid(&current_user) {
        Ok(x) => x,
        Err(x) => {
            println!("string_to_sid failed for {}: GLE={}", current_user, x);
            assert_eq!(x, 0);
            return;
        }
    };

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let acl_result = ACL::from_file_path(path, true);
    assert!(acl_result.is_ok());

    let mut acl = acl_result.unwrap();
    match acl.audit(
        current_user_sid.as_ptr() as PSID,
        false,
        FILE_GENERIC_READ,
        true,
        true,
    ) {
        Ok(x) => assert!(x),
        Err(x) => {
            println!("ACL.audit failed for {}: GLE={}", &current_user, x);
            assert!(false);
            return;
        }
    }

    let mut entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new();
    expected.entry_type = AceType::SystemAudit;
    expected.string_sid = current_user.to_string();
    expected.flags = SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG;
    expected.mask = FILE_GENERIC_READ;

    assert!(acl_entry_exists(&entries, &expected).is_some());

    match acl.remove(
        current_user_sid.as_ptr() as PSID,
        Some(AceType::SystemAudit),
        Some(false),
    ) {
        Ok(x) => assert_eq!(x, 1),
        Err(x) => {
            println!(
                "ACL.remove failed for removing mandatory ACE for {}: GLE={}",
                &current_user, x
            );
            assert!(false);
            return;
        }
    }

    entries = acl.all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    assert!(acl_entry_exists(&entries, &expected).is_none());
}

// Make sure ACL::get and ACL::remove work as we expect
#[test]
fn acl_get_and_remove_test() {
    START.call_once(|| {
        assert!(run_ps_script("setup_acl_test.ps1"));
    });

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("acl_get_and_remove");
    assert!(path_obj.exists());

    let guest = string_sid_by_user("Guest");
    let guest_sid = match string_to_sid(&guest) {
        Ok(x) => x,
        Err(x) => {
            println!("string_to_sid failed for {}: GLE={}", guest, x);
            assert_eq!(x, 0);
            return;
        }
    };

    let world = string_sid_by_user("Everyone");
    let world_sid = string_to_sid(&world).unwrap_or(Vec::new());
    assert_ne!(world_sid.capacity(), 0);

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let acl_result = ACL::from_file_path(path, true);
    assert!(acl_result.is_ok());

    let mut acl = acl_result.unwrap();

    let mut results = acl
        .get(world_sid.as_ptr() as PSID, None)
        .unwrap_or_else(|_x| {
            assert!(false);
            Vec::new()
        });
    assert_eq!(results.len(), 0);

    results = acl
        .get(guest_sid.as_ptr() as PSID, None)
        .unwrap_or(Vec::new());
    assert_eq!(results.len(), 3);

    results = acl
        .get(guest_sid.as_ptr() as PSID, Some(AceType::AccessAllow))
        .unwrap_or(Vec::new());
    assert_eq!(results.len(), 1);

    results = acl
        .get(guest_sid.as_ptr() as PSID, Some(AceType::AccessDeny))
        .unwrap_or(Vec::new());
    assert_eq!(results.len(), 1);

    results = acl
        .get(guest_sid.as_ptr() as PSID, Some(AceType::SystemAudit))
        .unwrap_or(Vec::new());
    assert_eq!(results.len(), 1);

    let mut removed = acl
        .remove(guest_sid.as_ptr() as PSID, Some(AceType::AccessDeny), None)
        .unwrap_or(0);
    assert_eq!(removed, 1);

    results = acl
        .get(guest_sid.as_ptr() as PSID, None)
        .unwrap_or(Vec::new());
    assert_eq!(results.len(), 2);

    removed = acl
        .remove(guest_sid.as_ptr() as PSID, None, None)
        .unwrap_or(0);
    assert_eq!(removed, 2);
}
