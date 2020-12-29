# Enable security privilege
# Below taken from Set-LHSTokenPrivilege.ps1
$definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

$processHandle = (Get-Process -id $PID).Handle
    
$type = Add-Type $definition -PassThru
$null = $type[0]::EnablePrivilege($processHandle, "SeSecurityPrivilege", $false)
$null = $type[0]::EnablePrivilege($processHandle, "SeTakeOwnershipPrivilege", $false)

# Setup supportPath
$supportPath = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -Parent
$supportPath = Join-Path -Path $supportPath -ChildPath "testfiles"

# Create a new directory at supportPath by removing the old one (if it exists)
Remove-Item -Recurse -Path $supportPath -ErrorAction SilentlyContinue
$null = New-Item -ItemType directory $supportPath -ErrorAction SilentlyContinue

$testDirs = @(
    "query_test",
    "query_sacl_test"
)

$testFiles = @(
    "dacl_deny_file",
    "dacl_deny_handle",
    "dacl_allow_file",
    "dacl_allow_handle",
    "sacl_audit_file",
    "sacl_mil_file",
    "acl_get_and_remove"
)

ForEach ($testDir in $testDirs) {
    $queryPath = Join-Path -Path $supportPath -ChildPath $testDir
    Remove-Item -Recurse -Path $queryPath -ErrorAction SilentlyContinue
    $null = New-Item -ItemType directory $queryPath -ErrorAction SilentlyContinue
}

ForEach ($testFile in $testFiles) {
    $queryPath = Join-Path -Path $supportPath -ChildPath $testFile
    Remove-Item -Recurse -Path $queryPath -ErrorAction SilentlyContinue
    $null = New-Item -ItemType file $queryPath -ErrorAction SilentlyContinue
    Set-Content -Path $queryPath -Value $testFile
}

function ResetDaclEntries {
    # For a given path, remove all the Everyone and current user access control entries
    param(
        [string] $Path 
    )
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $true)
    $acl | Set-Acl -Path $Path

    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "Read", "Allow"
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Administrators", "Read", "Allow"
    $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Everyone", "Read", "Allow"
    $authusersRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Authenticated Users", "Read", "Allow"
    
    $acl = Get-Acl -Path $Path
    $acl.RemoveAccessRuleAll($userRule)
    $acl.RemoveAccessRuleAll($adminRule)
    $acl.RemoveAccessRuleAll($everyoneRule)
    $acl.RemoveAccessRuleAll($authusersRule)
    $acl | Set-Acl -Path $Path    
}

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Setup query_test
$queryPath = Join-Path -Path $supportPath -ChildPath "query_test"

$guestRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Guest", "ReadAndExecute", "Deny"
$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "FullControl", "Allow"

$acl = Get-Acl -Path $queryPath
$acl.SetAccessRule($guestRule)
$acl.SetAccessRule($userRule)
$acl | Set-Acl -Path $queryPath

# Setup query_sacl_test
$queryPath = Join-Path -Path $supportPath -ChildPath "query_sacl_test"

$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule "Everyone", "Read,Write", "Success,Failure"

$acl = Get-Acl -Path $queryPath
$acl.SetAuditRule($auditRule)
$acl | Set-Acl -Path $queryPath

# Setup dacl_deny_file
$queryPath = Join-Path -Path $supportPath -ChildPath "dacl_deny_file"
ResetDaclEntries -Path $queryPath

$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "Read, Write", "Allow"

$acl = Get-Acl -Path $queryPath
$null = $acl.SetAccessRule($userRule)
$acl | Set-Acl -Path $queryPath

# Setup dacl_deny_handle
$queryPath = Join-Path -Path $supportPath -ChildPath "dacl_deny_handle"
ResetDaclEntries -Path $queryPath

$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "Read, Write, ChangePermissions", "Allow"

$acl = Get-Acl -Path $queryPath
$null = $acl.SetAccessRule($userRule)
$acl | Set-Acl -Path $queryPath

# Setup dacl_allow_file
$queryPath = Join-Path -Path $supportPath -ChildPath "dacl_allow_file"
ResetDaclEntries -Path $queryPath

$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "Read", "Allow"

$acl = Get-Acl -Path $queryPath
$null = $acl.SetAccessRule($userRule)
$acl | Set-Acl -Path $queryPath

# Setup dacl_allow_handle
$queryPath = Join-Path -Path $supportPath -ChildPath "dacl_allow_handle"
ResetDaclEntries -Path $queryPath

$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule $currentUser, "Read, ChangePermissions", "Allow"

$acl = Get-Acl -Path $queryPath
$null = $acl.SetAccessRule($userRule)
$acl | Set-Acl -Path $queryPath

# Setup acl_get_and_remove
$queryPath = Join-Path -Path $supportPath -ChildPath "acl_get_and_remove"

$readRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Guest", "Read", "Allow"
$writeRule = New-Object System.Security.AccessControl.FileSystemAccessRule "Guest", "Write", "Deny"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule "Guest", "Read, Write", "Success,Failure"

$acl = Get-Acl -Path $queryPath
$null = $acl.SetAccessRule($writeRule)
$null = $acl.SetAccessRule($readRule)
$null = $acl.SetAuditRule($auditRule)
$acl | Set-Acl -Path $queryPath
