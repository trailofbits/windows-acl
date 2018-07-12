# windows-acl
Rust library to simplify Windows ACL operations.

## Example Applications
See `example/query_acl.rs`

## Unit Tests
The current unit tests expect to be run in a single threaded environment with elevated privileges. By default, Rust executes unit tests with multiple threads. To successfully run tests, the following must be done:

 1. Open an elevated privilege/Administrator Command Prompt or Powershell Terminal.
 2. Set the `RUST_TEST_THREADS` environment variable to 1.
 3. Run `cargo test`