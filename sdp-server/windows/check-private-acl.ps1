param(
  [Parameter(Mandatory=$true)][ValidateSet('server','client')][string]$Mode,
  [Parameter(Mandatory=$true)][string]$ConfigPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $allowed = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
  $ancestorAllowed = @($allowed)
  try {
    $ancestorAllowed += ([Security.Principal.NTAccount]'NT SERVICE\TrustedInstaller').Translate([Security.Principal.SecurityIdentifier]).Value
  } catch { }
  $replacementRights = [long]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
  function Assert-PrivatePath([string]$Path, [bool]$MayBeMissing) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[\x00-\x1f\x7f]') { throw 'SDP_PRIVATE_ACL_FAILED' }
    foreach ($part in $Path.Substring(3).Split('\')) {
      if (-not $part -or $part -match '[. ]$') { throw 'SDP_PRIVATE_ACL_FAILED' }
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path) { throw 'SDP_PRIVATE_ACL_FAILED' }
    $walk = $full
    while ($walk) {
      if (Test-Path -LiteralPath $walk) {
        $item = Get-Item -LiteralPath $walk -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'SDP_PRIVATE_ACL_FAILED' }
        $ancestorAcl = Get-Acl -LiteralPath $walk
        if ($ancestorAllowed -notcontains $ancestorAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'SDP_PRIVATE_ACL_FAILED' }
        foreach ($rule in $ancestorAcl.Access) {
          if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
          $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
          if ($ancestorAllowed -notcontains $sid -and ([long]$rule.FileSystemRights -band $replacementRights) -ne 0) { throw 'SDP_PRIVATE_ACL_FAILED' }
        }
      }
      $parent = [IO.Path]::GetDirectoryName($walk)
      if ($parent -eq $walk) { break }
      $walk = $parent
    }
    $targets = @([IO.Path]::GetDirectoryName($full))
    if (Test-Path -LiteralPath $full) { $targets += $full }
    elseif (-not $MayBeMissing) { throw 'SDP_PRIVATE_ACL_FAILED' }
    foreach ($target in $targets) {
      $acl = Get-Acl -LiteralPath $target
      $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
      if ($allowed -notcontains $owner) { throw 'SDP_PRIVATE_ACL_FAILED' }
      foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        # Conservative policy: reject any allow right for unrelated identities.
        if ($allowed -notcontains $sid -and [long]$rule.FileSystemRights -ne 0) { throw 'SDP_PRIVATE_ACL_FAILED' }
      }
    }
  }
  Assert-PrivatePath $ConfigPath $false
  $configuration = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $paths = @()
  if ($Mode -eq 'server') {
    if ($configuration.schema -ne 'student.sdp.server.v1') { throw 'SDP_PRIVATE_ACL_FAILED' }
    $paths += @($configuration.caFile,$configuration.certFile,$configuration.keyFile,$configuration.jwtKeyFile,$configuration.registryFile)
    if ($configuration.originKeyFiles) {
      $configuration.originKeyFiles.PSObject.Properties | ForEach-Object { $paths += [string]$_.Value }
    }
    if ($configuration.xdrEvidenceKeyFile) { $paths += $configuration.xdrEvidenceKeyFile }
    foreach ($path in $paths) { Assert-PrivatePath $path $false }
    if ($configuration.xdrEvidenceFile) { Assert-PrivatePath $configuration.xdrEvidenceFile $true }
  } else {
    if ($configuration.schema -ne 'alekov.sdp.host.v1') { throw 'SDP_PRIVATE_ACL_FAILED' }
    $paths += @($configuration.caFile,$configuration.certFile,$configuration.keyFile,$configuration.tokenFile)
    foreach ($path in $paths) { Assert-PrivatePath $path $false }
  }
  Write-Output 'SDP_PRIVATE_ACL_OK'
  exit 0
} catch {
  Write-Output 'SDP_PRIVATE_ACL_FAILED'
  exit 1
}
