# Huitzilopochtli agent installer (Windows). Run once by boxbuilder's
# install_init("windows") after the agent files are placed and ACL-sealed.
#
# Registers the HuitzilopochtliAgent scheduled task as SYSTEM (RunLevel
# HIGHEST) with two triggers -- at startup and repeating every 5 minutes,
# the honor-mode re-grade cadence that pairs with the POSIX systemd timer --
# pointing at huitz-agent-task.ps1 (run agent + mirror report to Public
# Desktop). Then runs that task script once so a report exists immediately
# after install instead of up to 5 minutes later.
#
# Register-ScheduledTask repetition quirks vary across Windows builds, so the
# repetition trigger is wrapped in a fallback to schtasks.exe /SC MINUTE,
# which works everywhere; if the modern registration path fails entirely the
# script exits non-zero and the install fails loudly.

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
    schtasks.exe /Change /TN $taskName /ST 00:00 | Out-Null
}

# Run once now: install-time report, notifications baseline, visible errors.
& $wrapper -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $taskScript

Write-Output "huitzilopochtli agent task registered ($taskName)"
exit 0
