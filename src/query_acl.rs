extern crate clap;
extern crate windows_acl;

use clap::{
    App, Arg,
};
use windows_acl::acl::ACL;

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
    let mut acl: Option<ACL> = None;

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
            for entry in &entries {
                println!("{}", entry);
            }
        },
        None => {
            println!("ACLs could not be read from specified named object: ");
        }
    }
}