use std::env::current_exe;
use std::process::Command;

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
fn query_unit_test() {
    assert!(run_ps_script("setup_query_test.ps1"));
}