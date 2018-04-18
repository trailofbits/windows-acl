#[cfg(windows)]

extern crate field_offset;
extern crate libc;
extern crate widestring;
extern crate winapi;

pub mod acl;
mod utils;

#[cfg(test)]
mod tests;
