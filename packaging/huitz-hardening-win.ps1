# Huitzilopochtli Windows logon/browser hardening (build-time). See architecture.md §17.
#
# Placed into the install dir by boxbuilder's install step (pipeline.install_box, Windows
# targets only) and run once over the elevated SSH session. Best-effort by design: every
# section guards itself and the script always exits 0 -- a hardening miss must never fail
# an install. What it kills (the pop-ups players should never meet):
#
#   1. Microsoft Edge first-run onboarding -- the "welcome to Edge" wizard every fresh
#      profile walks through -- via machine-wide Edge policies.
#   2. The Shutdown Event Tracker modal at logon ("Why did the computer shut down
#      unexpectedly?"; REDEPLOY.md gotcha 25 -- previously a manual pre-seal step only).
#   3. Server Manager auto-open at logon and its Windows Admin Center promo, set in
#      C:\Users\Default\NTUSER.DAT so every profile created from now on inherits it.
#      An HKCU write over SSH does not survive sealing (gotcha 25's TODO, now closed).
#   4. The python.org MSI advertised-shortcut trap (gotcha 26): the Start-menu entries
#      are MSI entry points; on a clone they fire MSI self-repair, which pops
#      "Another program called 'C:\Program' ... Would you like to rename it?" /
#      "Windows cannot find 'C:\Program\python.exe'" -- clicking Rename renames the
#      python home away and scoring silently dies. Repair the products (/faus refreshes
#      files, registry, and shortcuts so they stop being advertised) and delete the
#      Start-menu folder.

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
    # Software rendering: GPU-composited text smears into gray ghost-streaks on
    # virtual displays under lossy remote encoders (Guacamole/RDP) -- exactly
    # what a player sees with the handbook open over the workshop link.
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
            # GUID-shaped keys only (MSI products); DisplayName 'Python 3*' per gotcha 26.
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
            Start-Process msiexec.exe -ArgumentList "/faus $code /qn" -Wait
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
