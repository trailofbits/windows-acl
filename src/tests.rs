#![cfg(windows)]

use acl::{
    ACL, AceType
};
use std::env::current_exe;
use std::path::PathBuf;
use std::process::Command;
use utils::{
    name_to_sid, sid_to_string, string_to_sid, current_user
};
use winapi::um::winnt::{
    PSID, INHERITED_ACE, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS, SYNCHRONIZE
};

fn support_path() -> Option<PathBuf> {
    if let Ok(mut path) = current_exe() {
         for _ in 0..4 {
             path.pop();
         }
        path.push("support");
        return Some(path);
    } else {
        assert!(false, "current_exe failed");
    }

    None
}
fn run_ps_script(file_name: &str) -> bool {
    if let Some(mut path) = support_path() {
        path.push(file_name);

        if let Some(script_path) = path.to_str() {
            let mut process = match Command::new("PowerShell.exe")
                .args(&["-ExecutionPolicy", "bypass", "-File", script_path])
                .spawn() {
                Ok(process) => process,
                _ => { return false; }
            };
            if let Ok(_code) = process.wait() {
                return true;
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

#[test]
fn query_dacl_unit_test() {
    assert!(run_ps_script("setup_query_dacl_test.ps1"));

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

    let deny_entry = &entries[0];
    let allow_entry = &entries[1];

    assert_eq!(deny_entry.entry_type, AceType::AccessDeny);
    assert_eq!(deny_entry.string_sid, guest_sid);
    assert_eq!(deny_entry.flags & INHERITED_ACE, 0);

    // NOTE(andy): For ACL entries added by CmdLets on files, SYNCHRONIZE is not set
    assert_eq!(deny_entry.mask, (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE);

    assert_eq!(allow_entry.entry_type, AceType::AccessAllow);
    assert_eq!(allow_entry.string_sid, current_user_sid);
    assert_eq!(allow_entry.flags & INHERITED_ACE, 0);

    // NOTE(andy): For ACL entries added by CmdLets on files, SYNCHRONIZE is not set
    assert_eq!(allow_entry.mask, FILE_ALL_ACCESS);
}

#[test]
fn query_sacl_unit_test() {
    assert!(run_ps_script("setup_query_sacl_test.ps1"));

    let world_sid = string_sid_by_user("Everyone");

    let mut path_obj = support_path().unwrap_or(PathBuf::new());
    path_obj.push("query_test");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let acl_result = ACL::from_file_path(path, true);
    println!("result = {:?}", acl_result);
}