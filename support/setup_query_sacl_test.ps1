$supportPath = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -Parent

$queryPath = Join-Path -Path $supportPath -ChildPath "query_test"
Remove-Item -Recurse -Path $queryPath -ErrorAction SilentlyContinue
$null = New-Item -ItemType directory $queryPath -ErrorAction SilentlyContinue

$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule "Everyone", "Read,Write", "Success,Failure"

$acl = Get-Acl -Path $queryPath
$acl.SetAuditRule($auditRule)
$acl | Set-Acl -Path $queryPath