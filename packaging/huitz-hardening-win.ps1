# Huitzilopochtli Windows logon/browser hardening (build-time), §17. Placed in
# the install dir by pipeline.install_box (Windows targets) and run once over
# the elevated SSH session. Best-effort: every section guards itself and the
# script always exits 0. Kills: Edge first-run (machine policy), the Shutdown
# Event Tracker, Server Manager at logon (set in C:\Users\Default so profiles
# inherit it — HKCU writes over SSH don't survive sealing), and the python MSI
# advertised-shortcut trap (self-repair on clones can rename the python home
# and silently break scoring — /faus de-advertises, then the Start-menu
# folder goes).

$ErrorActionPreference = 'Continue'

function Info($m) { Write-Output "[huitz-hardening] $m" }

# --- 1. Edge first-run ------------------------------------------------------
try {
    $edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    New-Item -ItemType Directory -Force -Path $edge | Out-Null
    New-ItemProperty -Path $edge -Name 'HideFirstRunExperience' `
        -PropertyType DWord -Value 1 -Force | Out-Null
    # 4 = import nothing at first launch (no bookmarks/settings wizard).
    New-ItemProperty -Path $edge -Name 'AutoImportAtFirstRun' `
        -PropertyType DWord -Value 4 -Force | Out-Null
    # Software rendering: GPU-composited text smears under lossy remote
    # encoders (Guacamole/RDP) — what players see over the workshop link.
    New-ItemProperty -Path $edge -Name 'HardwareAccelerationModeEnabled' `
        -PropertyType DWord -Value 0 -Force | Out-Null
    Info 'Edge first-run experience disabled (machine policy)'
} catch {
    Info "WARNING: could not set Edge policies: $($_.Exception.Message)"
}

# --- 2. Shutdown Event Tracker ----------------------------------------------
try {
    $rel = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability'
    New-Item -ItemType Directory -Force -Path $rel | Out-Null
    New-ItemProperty -Path $rel -Name 'ShutdownReasonOn' `
        -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $rel -Name 'ShutdownReasonUI' `
        -PropertyType DWord -Value 0 -Force | Out-Null
    Info 'Shutdown Event Tracker disabled'
} catch {
    Info "WARNING: could not disable the Shutdown Event Tracker: $($_.Exception.Message)"
}

# --- 3. Server Manager at logon (Default user hive) --------------------------
$info3 = 'Server Manager auto-open disabled in the Default user hive'
try {
    $hive = 'HKEY_LOCAL_MACHINE\HuitzDefault'
    $hivePs = 'HKLM:\HuitzDefault'
    $dat = 'C:\Users\Default\NTUSER.DAT'
    if (Test-Path $dat) {
        # A stale mount from a previous run would make reg load fail; clear it.
        reg unload $hive 2>$null | Out-Null
        $loaded = $false
        try {
            reg load $hive $dat | Out-Null
            $loaded = $true
            $sm = "$hivePs\Software\Microsoft\ServerManager"
            New-Item -Path $sm -Force | Out-Null
            New-ItemProperty -Path $sm -Name 'DoNotOpenAtLogon' `
                -PropertyType DWord -Value 1 -Force | Out-Null
        } finally {
            if ($loaded) {
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                reg unload $hive | Out-Null
            }
        }
    } else {
        $info3 = "WARNING: $dat not found; skipping Server Manager fix"
    }
} catch {
    $info3 = "WARNING: could not edit the Default user hive: $($_.Exception.Message)"
    try { reg unload 'HKEY_LOCAL_MACHINE\HuitzDefault' 2>$null | Out-Null } catch { }
}
Info $info3

# --- 4. Python advertised shortcuts (MSI self-repair trap) -------------------
try {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $codes = @()
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($k in Get-ChildItem $root -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            # GUID-shaped keys only (MSI products); DisplayName 'Python 3*'.
            if ($p.DisplayName -like 'Python 3*' -and $k.PSChildName -match '^\{[0-9A-F-]+\}$') {
                $codes += $k.PSChildName
            }
        }
    }
    if ($codes.Count -eq 0) {
        Info 'no python MSI products found; nothing to repair'
    } else {
        foreach ($code in ($codes | Select-Object -Unique)) {
            Info "repairing python MSI $code (defuses advertised-shortcut self-repair)"
            # Bounded, not -Wait: /faus can block for minutes; hardening must
            # never stall a build. Two minutes, then move on.
            $repair = Start-Process msiexec.exe -ArgumentList "/faus $code /qn" -PassThru
            if (-not $repair.WaitForExit(120000)) {
                Info "WARNING: python MSI repair $code exceeded 120s; continuing"
                Stop-Process -Id $repair.Id -Force -ErrorAction SilentlyContinue
            }
        }
        Get-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.*' `
            -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Info 'python MSI products repaired; Start-menu advertised shortcuts removed'
    }
} catch {
    Info "WARNING: python MSI repair failed: $($_.Exception.Message)"
}

exit 0
