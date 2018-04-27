$supportPath = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -Parent

$queryPath = Join-Path -Path $supportPath -ChildPath "query_test"
Remove-Item -Recurse -Path $queryPath -ErrorAction SilentlyContinue
$null = New-Item -ItemType directory $queryPath

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$guestRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Guest", "ReadAndExecute", "Deny"
$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "FullControl", "Allow"

$acl = Get-Acl -Path $queryPath
$acl.SetAccessRule($guestRule)
$acl.SetAccessRule($userRule)
$acl | Set-Acl -Path $queryPath