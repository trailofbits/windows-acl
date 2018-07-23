//! `windows-acl` is a Rust library to simplify Windows ACL operations.

#![cfg(windows)]

extern crate field_offset;
extern crate libc;
extern crate widestring;
extern crate winapi;

pub mod acl;
mod utils;

pub mod helper {
    pub use utils::{sid_to_string, name_to_sid, string_to_sid, current_user};
}

#[cfg(test)]
mod tests;