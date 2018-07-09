# windows-acl

## Unit Tests
Running unit tests requires a specific procedure because the default unit test procedure creates race conditions.

 1. Open an elevated privilege/Administrator Command Prompt or Powershell Terminal.
 2. Set the `RUST_TEST_THREADS` environment variable to 1.
 3. Run `cargo test`