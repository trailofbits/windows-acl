use std::env::current_exe;
use std::process::Command;
use utils::{
    name_to_sid, sid_to_string, string_to_sid
};
use winapi::um::winnt::{
    PSID
};

fn run_ps_script(file_name: &str) -> bool {
    if let Ok(mut path) = current_exe() {
        for _ in 0..4 {
            path.pop();
        }
        path.push("support");
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

#[test]
fn lookupname_unit_test() {
    let raw_sid = match name_to_sid("Everyone", None) {
        Ok(rs) => sid_to_string(rs.as_ptr() as PSID).unwrap_or("Unknown".to_string()),
        Err(code) => {
            println!("GLE={}", code);
            return;
        }
    };

    println!("raw_sid for {} => {}", "Everyone", raw_sid);
}

#[test]
fn sidstring_unit_test() {
    let world_string_sid = "S-1-1-0";

    let sid = string_to_sid(world_string_sid).unwrap_or(Vec::new());
    assert_ne!(sid.capacity(), 0);

    let sid_string = sid_to_string(sid.as_ptr() as PSID).unwrap_or(String::from(""));
    assert_ne!(sid_string.len(), 0);

    assert_eq!(sid_string, world_string_sid);
}

#[test]
fn query_unit_test() {
    assert!(run_ps_script("setup_query_test.ps1"));
}