# Huitzilopochtli agent installer (Windows). Run once by boxbuilder's
# install_init("windows") after the agent files are placed and ACL-sealed.
#
# Registers the HuitzilopochtliAgent scheduled task as SYSTEM (RunLevel
# HIGHEST) with two triggers -- at startup and repeating every 5 minutes,
# the honor-mode re-grade cadence that pairs with the POSIX systemd timer --
# pointing at huitz-agent-task.ps1 (run agent + mirror report to the Public
# Documents dir). Then runs that task script once so a report exists immediately
# after install instead of up to 5 minutes later.
#
# It also installs the `huitz` console shim (huitz.cmd in the interpreter's
# Scripts dir, on the machine PATH) so the engine's "run huitz join" copy is
# literally true on Windows. With -Ranked (a competition box, agent installed
# disabled) it additionally installs the player's graphical joiner
# (huitz-join-win.pyw + Desktop shortcut) for players who never open a shell.
#
# Register-ScheduledTask repetition quirks vary across Windows builds, so the
# repetition trigger is wrapped in a fallback to schtasks.exe /SC MINUTE,
# which works everywhere; if the modern registration path fails entirely the
# script exits non-zero and the install fails loudly.

param([switch]$Ranked)

$ErrorActionPreference = 'Stop'

$dir = 'C:\ProgramData\huitzilopochtli'
$taskScript = Join-Path $dir 'huitz-agent-task.ps1'
$taskName = 'HuitzilopochtliAgent'

$wrapper = 'powershell.exe'
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$taskScript`""

$action = New-ScheduledTaskAction -Execute $wrapper -Argument $arguments -WorkingDirectory $dir
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew

$startup = New-ScheduledTaskTrigger -AtStartup
try {
    $recurring = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration ([TimeSpan]::FromDays(3650))
    Register-ScheduledTask -TaskName $taskName -Action $action `
        -Trigger @($startup, $recurring) -Principal $principal `
        -Settings $settings -Force | Out-Null
} catch {
    # Older builds reject long repetition durations -- fall back to schtasks,
    # which cannot express two triggers but covers the 5-minute cadence.
    schtasks.exe /Create /F /TN $taskName /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST `
        /TR "`"$wrapper`" $arguments" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks /Create failed with exit code $LASTEXITCODE"
    }
    schtasks.exe /Change /TN $taskName /ST 00:00 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks /Change failed with exit code $LASTEXITCODE"
    }
}

if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw "scheduled task '$taskName' was not registered"
}

# Run once now: install-time report, notifications baseline, visible errors.
& $wrapper -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $taskScript
if ($LASTEXITCODE -ne 0) {
    throw "first huitz run failed with exit code $LASTEXITCODE"
}

Write-Output "huitzilopochtli agent task registered ($taskName)"

# --- the `huitz` command (PATH shim) --------------------------------------
# The engine's join page tells the player to run `huitz join <code>`, and the
# agent console is the zipapp under this dir -- but a Windows box ships no
# console entry point, so that instruction used to be impossible to follow
# (only `py -3 C:\ProgramData\huitzilopochtli\agent.pyz join <code>` worked).
# Install a tiny .cmd that forwards to the interpreter + zipapp, and keep it
# in the interpreter's Scripts dir, which is on the machine PATH for every
# shell (the join itself needs an elevated one).
$py = $null
foreach ($cand in @((Get-Command python -ErrorAction SilentlyContinue).Source,
                    'C:\Python312\python.exe', 'C:\Program Files\Python312\python.exe',
                    'C:\Program\python.exe', 'C:\Program1\python.exe')) {
    if ($cand -and ($cand -notmatch 'WindowsApps') -and (Test-Path -LiteralPath $cand)) {
        $py = $cand; break
    }
}
if (-not $py) { throw 'python.exe not found; the huitz shim needs it' }
$shimDir = Join-Path (Split-Path $py -Parent) 'Scripts'
New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
$shim = Join-Path $shimDir 'huitz.cmd'
@(
    '@echo off',
    'rem huitz: console for this box''s agent (forwarded to the zipapp).',
    ('"' + $py + '" "' + (Join-Path $dir 'agent.pyz') + '" %*')
) | Set-Content -LiteralPath $shim -Encoding ASCII
$envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$machinePath = (Get-ItemProperty -LiteralPath $envKey).Path
if (($machinePath -split ';') -notcontains $shimDir) {
    Set-ItemProperty -LiteralPath $envKey -Name Path -Value (($machinePath.TrimEnd(';')) + ';' + $shimDir)
    $env:PATH = $env:PATH.TrimEnd(';') + ';' + $shimDir
}
& $shim --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw "the huitz shim does not run ($LASTEXITCODE)" }
Write-Output "huitz shim installed: $shim"

# --- the graphical joiner (ranked competition boxes) ----------------------
# The `huitz` shim above makes the console path work; the joiner is the
# click-instead for players who never open a shell.
#
# The launcher must be readable by the token a double-click runs under, which
# is the player's *filtered* (non-elevated) token -- that instance is the one
# that raises the UAC prompt. The install dir is sealed to SYSTEM +
# Administrators with no traversal for Users, so a launcher living there
# cannot be clicked at all; it is copied to the Public mirror dir (where
# report.html and README.html already live) and that one file is sealed
# admin-write / user-read-and-execute. Nothing else about the layout changes.
if ($Ranked) {
    $launcherSrc = Join-Path $dir 'huitz-join-win.pyw'
    if (-not (Test-Path -LiteralPath $launcherSrc)) {
        throw "ranked Windows box is missing $launcherSrc"
    }
    $mirror = Join-Path $env:PUBLIC 'Documents\huitzilopochtli'
    New-Item -ItemType Directory -Force -Path $mirror | Out-Null
    # Same rule as the report mirror: the Public tree is user-writable, so
    # never let a planted junction send this Administrator-run copy elsewhere.
    $mirrorItem = Get-Item -LiteralPath $mirror -Force
    if ($mirrorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "refusing to write the join launcher through a reparse point: $mirror"
    }
    $launcher = Join-Path $mirror 'huitz-join-win.pyw'
    if (Test-Path -LiteralPath $launcher) {
        $launcherItem = Get-Item -LiteralPath $launcher -Force
        if ($launcherItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "refusing to overwrite a reparse-point join launcher: $launcher"
        }
    }
    Copy-Item -Force $launcherSrc $launcher
    icacls "$launcher" /inheritance:r '/grant:r' 'SYSTEM:(F)' 'Administrators:(F)' '*S-1-5-32-545:RX' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to seal the join launcher ($LASTEXITCODE): $launcher"
    }

    # Resolve the interpreter the same way huitz-agent-task.ps1 resolves
    # python, then look beside it for pythonw (windowless). A Microsoft Store
    # App Execution Alias stub matches Test-Path and then opens the Store, so
    # WindowsApps paths are excluded on purpose.
    $py = $null
    foreach ($cand in @((Get-Command python -ErrorAction SilentlyContinue).Source,
                        'C:\Python312\python.exe', 'C:\Program\python.exe',
                        'C:\Program1\python.exe')) {
        if ($cand -and ($cand -notmatch 'WindowsApps') -and (Test-Path -LiteralPath $cand)) {
            $py = $cand; break
        }
    }
    if (-not $py) { throw 'python.exe not found; the join launcher needs it' }
    $pyw = $null
    foreach ($cand in @((Join-Path (Split-Path $py -Parent) 'pythonw.exe'),
                        (Get-Command pythonw -ErrorAction SilentlyContinue).Source)) {
        if ($cand -and ($cand -notmatch 'WindowsApps') -and (Test-Path -LiteralPath $cand)) {
            $pyw = $cand; break
        }
    }
    if (-not $pyw) {
        # python.exe works but leaves a console window behind the prompt.
        $pyw = $py
        Write-Output 'WARNING: pythonw.exe not found; the join icon will open a console window too'
    }
    # Prove the click can reach both halves of the join before the template is
    # sealed -- the zipapp import is the join logic, tkinter is the prompt. A
    # missing tkinter means the launcher degrades to a message box that hands
    # the player the terminal command, so this warns rather than fails.
    & $py -c "import sys; sys.path.insert(0, r'$dir\agent.pyz'); import agent.join, tkinter"
    if ($LASTEXITCODE -ne 0) {
        Write-Output ('WARNING: the join preflight failed (import agent.join + ' +
                      'tkinter) -- the desktop joiner may not open on this box')
    }

    $desktop = Join-Path $env:PUBLIC 'Desktop'
    New-Item -ItemType Directory -Force -Path $desktop | Out-Null
    $lnk = Join-Path $desktop 'Join Competition Box.lnk'
    $made = $false
    try {
        $shell = New-Object -ComObject WScript.Shell
        $link = $shell.CreateShortcut($lnk)
        $link.TargetPath = $pyw
        $link.Arguments = '"' + $launcher + '"'
        $link.WorkingDirectory = $dir
        $link.Description = 'Join this box to your competition slot (enter your one-time code).'
        $link.Save()
        # Read-and-execute for players, write for admins: a Desktop item that
        # launches an elevation prompt is not something a player should be able
        # to rewire.
        icacls "$lnk" /inheritance:r '/grant:r' 'SYSTEM:(F)' 'Administrators:(F)' '*S-1-5-32-545:RX' | Out-Null
        $made = $true
    } catch {
        Write-Output "WARNING: could not create the Desktop shortcut ($_)"
    }
    if (-not $made) {
        # WScript.Shell COM missing (WSH trimmed down) -- a double-clickable
        # .pyw works as long as the file association survived.
        $fallback = Join-Path $desktop 'Join Competition Box.pyw'
        Copy-Item -Force $launcher $fallback
        icacls "$fallback" /inheritance:r '/grant:r' 'SYSTEM:(F)' 'Administrators:(F)' '*S-1-5-32-545:RX' | Out-Null
        Write-Output "installed the join launcher as a .pyw instead: $fallback"
    }
    Write-Output "join launcher installed: $launcher (Desktop: Join Competition Box)"
}

exit 0
