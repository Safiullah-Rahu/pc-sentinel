# Installs the built PC Sentinel desktop app for the current user (no admin needed):
# copies dist\PC Sentinel to %LOCALAPPDATA%\Programs\PC Sentinel and adds Desktop + Start Menu shortcuts.
# -StartAtLogin also adds a Startup shortcut that opens it hidden in the tray when you log in.
param([switch]$StartAtLogin)
$ErrorActionPreference = 'Stop'
$src  = Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\PC Sentinel'
$dest = Join-Path $env:LOCALAPPDATA 'Programs\PC Sentinel'
if (-not (Test-Path (Join-Path $src 'PC Sentinel.exe'))) { throw "Build first: pyinstaller pc_sentinel.spec ($src missing)" }

# stop a running copy so files can be replaced
Get-Process -Name 'PC Sentinel' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
if (Test-Path $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
Copy-Item -LiteralPath $src -Destination $dest -Recurse
$exe = Join-Path $dest 'PC Sentinel.exe'

$shell = New-Object -ComObject WScript.Shell
foreach ($dir in [Environment]::GetFolderPath('Desktop'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs')) {
    $lnk = $shell.CreateShortcut((Join-Path $dir 'PC Sentinel.lnk'))
    $lnk.TargetPath = $exe
    $lnk.WorkingDirectory = $dest
    $lnk.IconLocation = "$exe,0"
    $lnk.Description = 'PC Sentinel - see what every app on this PC is doing'
    $lnk.Save()
}
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Desktop')) 'PC Sentinel.url') -ErrorAction SilentlyContinue
if ($StartAtLogin) {
    $lnk = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Startup')) 'PC Sentinel.lnk'))
    $lnk.TargetPath = $exe
    $lnk.Arguments = '--tray'
    $lnk.WorkingDirectory = $dest
    $lnk.IconLocation = "$exe,0"
    $lnk.Description = 'Start PC Sentinel hidden in the system tray at login'
    $lnk.Save()
    # tell the engine its own autostart entry is expected (no alert); harmless if it is not running
    try {
        $tok = Get-Content (Join-Path $env:LOCALAPPDATA 'PCSentinel\token.txt')
        $body = @{ kind = 'persistence'; value = $exe; note = 'PC Sentinel starts itself at login' } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8777/api/actions/allow' -Body $body `
            -Headers @{ 'X-Sentinel-Token' = $tok; 'Content-Type' = 'application/json' } | Out-Null
    } catch {}
}
"Installed to $dest"
"Shortcuts: Desktop + Start Menu$(if ($StartAtLogin) { ' + Startup (tray at login)' })"
