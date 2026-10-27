param([Parameter(Mandatory=$true)][string]$PrivateDirectory)
$ErrorActionPreference = 'Stop'
try {
  if (-not [System.IO.Path]::IsPathRooted($PrivateDirectory)) { throw 'invalid' }
  $item = Get-Item -LiteralPath $PrivateDirectory -Force
  if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'invalid' }
  if (@(Get-ChildItem -LiteralPath $PrivateDirectory -Force).Count -ne 0) { throw 'notempty' }
  $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $allowed = @($user.Value, 'S-1-5-18', 'S-1-5-32-544')
  $ancestorAllowed = @($allowed)
  try { $ancestorAllowed += ([System.Security.Principal.NTAccount]'NT SERVICE\TrustedInstaller').Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
  $replacementRights = [long]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
  $walk = [System.IO.Path]::GetDirectoryName($PrivateDirectory)
  while ($walk) {
    $ancestor = Get-Item -LiteralPath $walk -Force
    if (($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
    $ancestorAcl = Get-Acl -LiteralPath $walk
    if ($ancestorAllowed -notcontains $ancestorAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value) { throw 'owner' }
    foreach ($rule in $ancestorAcl.Access) {
      if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
      if ($ancestorAllowed -notcontains $sid -and ([long]$rule.FileSystemRights -band $replacementRights) -ne 0) { throw 'ancestorwrite' }
    }
    $parent = [System.IO.Path]::GetDirectoryName($walk)
    if ($parent -eq $walk) { break }
    $walk = $parent
  }
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($user)
  $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $propagate = [System.Security.AccessControl.PropagationFlags]::None
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  foreach ($sid in @($user.Value, 'S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', $inherit, $propagate, $allow)
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $PrivateDirectory -AclObject $acl
  $after = Get-Acl -LiteralPath $PrivateDirectory
  if ($after.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $user.Value) { throw 'owner' }
  $currentFullControl = $false
  foreach ($rule in $after.Access) {
    $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($rule.AccessControlType -eq $allow -and $allowed -notcontains $sid) { throw 'unexpected' }
    if ($rule.AccessControlType -eq $allow -and $sid -eq $user.Value -and ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl) { $currentFullControl = $true }
  }
  if (-not $after.AreAccessRulesProtected -or -not $currentFullControl) { throw 'inheritance' }
  exit 0
} catch {
  [Console]::Error.WriteLine('SDP_PRIVATE_DIRECTORY_FAILED')
  exit 1
}
