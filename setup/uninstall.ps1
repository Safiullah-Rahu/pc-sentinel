# PC Sentinel — undo the admin setup. Self-elevates.
# Removes the autostart task and desktop shortcut, stops the engine, turns the extra auditing back off,
# removes the file-audit rules it added. Keeps your data folder (%LOCALAPPDATA%\PCSentinel) unless -PurgeData.
param([switch]$PurgeData)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $extra = if ($PurgeData) { ' -PurgeData' } else { '' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"$extra"
    exit
}
$app = Split-Path -Parent $PSScriptRoot
$data = Join-Path $env:LOCALAPPDATA 'PCSentinel'

Unregister-ScheduledTask -TaskName 'PC Sentinel' -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -match 'main\.py' -and $_.ExecutablePath -like "$app*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Desktop')) 'PC Sentinel.url') -ErrorAction SilentlyContinue
# desktop app: stop it, remove its shortcuts (Desktop, Start Menu, Startup) and the installed program folder
Get-Process -Name 'PC Sentinel' -ErrorAction SilentlyContinue | Stop-Process -Force
foreach ($dir in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Startup'),
                 (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs')) {
    Remove-Item -LiteralPath (Join-Path $dir 'PC Sentinel.lnk') -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1
Remove-Item -LiteralPath (Join-Path $env:LOCALAPPDATA 'Programs\PC Sentinel') -Recurse -Force -ErrorAction SilentlyContinue

# auditing back to Windows defaults for the categories setup turned on
foreach ($g in '{0CCE922B-69AE-11D9-BED3-505054503030}', '{0CCE921D-69AE-11D9-BED3-505054503030}',
               '{0CCE9227-69AE-11D9-BED3-505054503030}', '{0CCE9211-69AE-11D9-BED3-505054503030}') {
    & auditpol /set /subcategory:"$g" /success:disable /failure:disable | Out-Null
}
& wevtutil sl 'Microsoft-Windows-DNS-Client/Operational' /e:false

# remove the ReadData audit rules from the watched files
$wl = Join-Path $data 'watched_files.json'
if (Test-Path $wl) {
    foreach ($i in (Get-Content -LiteralPath $wl -Raw | ConvertFrom-Json)) {
        try {
            $acl = Get-Acl -LiteralPath $i.path -Audit
            $acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.FileSystemRights -band 1 } | ForEach-Object { [void]$acl.RemoveAuditRuleSpecific($_) }
            Set-Acl -LiteralPath $i.path -AclObject $acl
        } catch {}
    }
}
if ($PurgeData) { Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'PC Sentinel removed.' -ForegroundColor Green
Start-Sleep -Seconds 3
