//! `windows-acl` is a Rust library to simplify Windows ACL operations.

#![cfg(windows)]

extern crate field_offset;
extern crate libc;
extern crate widestring;
extern crate winapi;

pub mod acl;
pub mod utils;

#[cfg(test)]
mod tests;