# windows-acl

## Unit Tests
The unit tests need to be run with Administrator privileges. Our unit tests require SeSecurityPrivilege to disable parent inheritance and to set System Access Control Lists. Need to set `RUST_TEST_THREADS=1`