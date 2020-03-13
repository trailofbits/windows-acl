//! `windows-acl` is a Rust library to simplify Windows ACL operations.

#![cfg(windows)]

extern crate field_offset;
extern crate libc;
extern crate widestring;
extern crate winapi;

pub mod acl;
mod utils;

pub mod helper {
    pub use utils::{current_user, name_to_sid, sid_to_string, string_to_sid};
}

#[cfg(test)]
mod tests;
