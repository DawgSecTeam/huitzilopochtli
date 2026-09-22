# Huitzilopochtli agent task action (Windows). See architecture.md §17.
#
# This is what the HuitzilopochtliAgent scheduled task (registered by
# huitzilopochtli-agent-win.ps1) executes every cycle: run the agent once and
# mirror the report to the Public Desktop. It is the Windows analog of the
# systemd unit's ExecStart + ExecStartPost/sync-report.sh pairing -- honor
# mode's agent runs once and exits, and the task's 5-minute cadence is what
# re-grades the box. Windows browsers (and the team account) can always read
# C:\Users\Public\Desktop, so the report shortcut points there.
#
# Install layout (created by pipeline.install_box + the win installer):
#   C:\ProgramData\huitzilopochtli\agent.pyz
#   C:\ProgramData\huitzilopochtli\agent_config.json
#   C:\ProgramData\huitzilopochtli\.score.dat        (honor only, ACL-sealed)
#   C:\ProgramData\huitzilopochtli\report.html       (written by the agent)

$ErrorActionPreference = 'Continue'
$dir = 'C:\ProgramData\huitzilopochtli'
$config = Join-Path $dir 'agent_config.json'

# Resolve python robustly: PATH first, then the py launcher, then the known
# install roots. A live-box incident (2026-09-21) had C:\Program renamed by
# an MSI self-repair dialog (the "Rename" answer) -- scoring must survive
# whatever PATH survives that.
$pyExe = $null
foreach ($cand in @((Get-Command python -ErrorAction SilentlyContinue).Source,
                    'C:\Program\python.exe', 'C:\Program1\python.exe')) {
    if ($cand -and (Test-Path $cand)) { $pyExe = $cand; break }
}
if ($pyExe) {
    & $pyExe (Join-Path $dir 'agent.pyz') $config
} else {
    & py -3 (Join-Path $dir 'agent.pyz') $config
}

$report = Join-Path $dir 'report.html'
if (Test-Path $report) {
    Copy-Item -Force $report (Join-Path $env:PUBLIC 'Desktop\report.html')
}
# report.json (agent/snapshot.py) is what the `huitz` CLI renders from
# (py C:\ProgramData\huitzilopochtli\agent.pyz score). Mirror it alongside
# the HTML so the CLI sees the same grade the Desktop report does.
$snapshot = Join-Path $dir 'report.json'
if (Test-Path $snapshot) {
    Copy-Item -Force $snapshot (Join-Path $env:PUBLIC 'Desktop\report.json')
}
# The forensics answers file is edited by the (UAC-filtered) desktop user
# but written by this SYSTEM task's agent, and os.chmod cannot express NTFS
# ACLs -- so re-grant BUILTIN\Users modify every cycle. Heals boxes whose
# file shipped with the template's read-only ACL too. Harmless when absent.
$forensics = Join-Path $env:PUBLIC 'Desktop\Forensics-Questions.txt'
if (Test-Path $forensics) {
    icacls $forensics /grant '*S-1-5-32-545:M' | Out-Null
}
exit 0
