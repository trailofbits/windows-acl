# windows-acl

[![Build Status](https://img.shields.io/github/workflow/status/trailofbits/windows-acl/CI/master)](https://github.com/trailofbits/windows-acl/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/windows-acl)](https://crates.io/crates/windows-acl)

Rust library to simplify Windows ACL operations.

## Using windows-acl
First, add the following line to the dependencies section of the project’s `Cargo.toml` file.

```
winapi = “0.3.5”
windows-acl = “0.3.0”
```

In the main Rust source code file, add the _windows-acl_ external crate and import the symbols as follows:

```rust
extern crate winapi;
extern crate windows_acl;

use winapi::um::winnt::{
    PSID, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE, FILE_GENERIC_WRITE,
    FILE_ALL_ACCESS, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
    SYSTEM_MANDATORY_LABEL_NO_READ_UP, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
};
use windows_acl::acl::ACL;
```

**NOTE:** Altering system ACL entries require either Administrator privileges or the ability to acquire the `SeSecurityPrivilege` privilege.

### Adding a mandatory integrity label

```rust
    let high_integrity_level_sid = string_to_sid("S-1-16-12288").unwrap();

    let mut acl = ACL::from_file_path("C:\\Users\\andy\\work\\high_il", true).unwrap();

    // Set high_il to be a high integrity level directory
    match acl.integrity_level(
                high_integrity_level_sid.as_ptr() as PSID,
                true,
                SYSTEM_MANDATORY_LABEL_NO_WRITE_UP |
                    SYSTEM_MANDATORY_LABEL_NO_READ_UP |
                    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
            ) {
        Ok(status) => {
            if !status {
                println!("We had an internal issue trying to add high integrity level to high_il");
            }
        },
        Err(code) => {
            println!("Failed to add high integrity level to high_il: error={}", code);
        }
    }
```

### Adding an audit entry

```rust
    let world_sid = string_to_sid("S-1-1-0").unwrap();

    let mut acl = ACL::from_file_path("C:\\Users\\andy\\work\\sensitive_files", true).unwrap();

    // Audit every file operation in sensitive_files from anyone in the Everyone group
    match acl.audit(
                world_sid.as_ptr() as PSID,
                true,
                FILE_ALL_ACCESS,
                true,
                true
            ) {
        Ok(status) => {
            if !status {
                println!("We had an internal issue trying to add audit entry to sensitive_files");
            }
        },
        Err(code) => {
            println!("Failed to add audit entry to sensitive_files: error={}", code);
        }
    }
```

### Denying guest access to a directory

```rust
    let guests = string_to_sid("S-1-5-32-546").unwrap();

    let mut acl = ACL::from_file_path("C:\\Users\\andy\\work\\sensitive_files", false).unwrap();

    // Guests cannot read anything in this directory. However, they can still drop files there
    match acl.deny(guests.as_ptr() as PSID, true, FILE_GENERIC_READ) {
        Ok(status) => {
            if !status {
                println!("We had an internal issue trying to add a deny entry to sensitive_files");
            }
        },
        Err(code) => {
            println!("Failed to add deny entry: error={}", code);
        }
    }
```

### Removing entries

```rust
    let world_sid = string_to_sid("S-1-1-0").unwrap();

    let mut acl = ACL::from_file_path("C:\\Users\\andy\\work\\sensitive_files", true).unwrap();

    // Remove a SystemAudit entry; remove() can also remove DACL entries as well
    match acl.remove(world_sid.as_ptr() as PSID, Some(AceType::SystemAudit), None) {
        Ok(removed) => {
            println!("Removed {} entries", removed);
        },
        Err(code) => {
            println!("Failed to remove entry: error={}", code);
        }
    }
```

## Example Applications
See `query_acl.rs` in the `example/` directory.

## Unit Tests
The current unit tests expect to be run in a single threaded environment with elevated privileges. By default, Rust executes unit tests with multiple threads. To successfully run tests, the following must be done:

 1. Open an elevated privilege/Administrator Command Prompt or Powershell Terminal.
 2. Set the `RUST_TEST_THREADS` environment variable to 1.
 3. Run `cargo test`
