# Student-owned, current-user shortcut only. No elevation or settings changes.
$ErrorActionPreference = 'Stop'
try {
    $target = Join-Path $PSScriptRoot 'start-portable.cmd'
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'MISSING_STARTER' }
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    if (-not $desktop) { throw 'DESKTOP_UNAVAILABLE' }
    $destination = Join-Path $desktop 'Student PC Dashboard.lnk'
    if (Test-Path -LiteralPath $destination) { throw 'SHORTCUT_EXISTS' }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($destination)
    $shortcut.TargetPath = $target
    $shortcut.WorkingDirectory = Split-Path -Parent $PSScriptRoot
    $shortcut.Description = 'Student local PC dashboard; Node.js required.'
    $shortcut.Save()
    Write-Output 'Desktop shortcut created. No security settings were changed.'
} catch {
    Write-Error 'Shortcut was not created. Check the launcher and an existing desktop shortcut. No existing shortcut was overwritten.'
    exit 1
}
