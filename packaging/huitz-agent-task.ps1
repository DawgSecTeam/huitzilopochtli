# Huitzilopochtli agent task action (Windows), §17. The HuitzilopochtliAgent
# scheduled task (registered by huitzilopochtli-agent-win.ps1) runs this each
# 5-minute cycle: grade once, mirror the report into Public Documents — the
# Windows analog of the service's ExecStart + sync-report.sh. The shortcut
# points at that mirror; the Desktop stays forensics-file + shortcuts.

$ErrorActionPreference = 'Continue'
$dir = 'C:\ProgramData\huitzilopochtli'
$config = Join-Path $dir 'agent_config.json'

# Resolve python robustly: PATH first, then known install roots — scoring
# must survive whatever PATH a box ships with. C:\Python312 is canonical;
# the C:\Program* entries are fallbacks for boxes sealed before the move.
$pyExe = $null
foreach ($cand in @((Get-Command python -ErrorAction SilentlyContinue).Source,
                    'C:\Python312\python.exe',
                    'C:\Program\python.exe', 'C:\Program1\python.exe')) {
    if ($cand -and (Test-Path $cand)) { $pyExe = $cand; break }
}
if ($pyExe) {
    & $pyExe (Join-Path $dir 'agent.pyz') $config
} else {
    & py -3 (Join-Path $dir 'agent.pyz') $config
}

$report = Join-Path $dir 'report.html'
$mirror = Join-Path $env:PUBLIC 'Documents\huitzilopochtli'
if (Test-Path $report) {
    New-Item -ItemType Directory -Force -Path $mirror | Out-Null
    # The Public tree can be user-writable; never let a planted junction/
    # symlink redirect this SYSTEM copy onto a protected file.
    $mirrorItem = Get-Item -LiteralPath $mirror -Force
    if ($mirrorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "refusing to write report mirror through a reparse point: $mirror"
    }
    $dest = Join-Path $mirror 'report.html'
    if (Test-Path -LiteralPath $dest) {
        $destItem = Get-Item -LiteralPath $dest -Force
        if ($destItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "refusing to overwrite a reparse-point report mirror: $dest"
        }
    }
    Copy-Item -Force $report $dest
}
# Mirror report.json too — it's what the `huitz` CLI renders from, so the
# CLI must see the same grade the report shortcut does.
$snapshot = Join-Path $dir 'report.json'
if (Test-Path $snapshot) {
    $dest = Join-Path $mirror 'report.json'
    if (Test-Path -LiteralPath $dest) {
        $destItem = Get-Item -LiteralPath $dest -Force
        if ($destItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "refusing to overwrite a reparse-point report mirror: $dest"
        }
    }
    Copy-Item -Force $snapshot $dest
}
# Legacy pre-Documents copies; only these two files are ever removed — the
# Desktop otherwise belongs to the box.
Remove-Item -Force -ErrorAction Ignore `
    (Join-Path $env:PUBLIC 'Desktop\report.html'),
    (Join-Path $env:PUBLIC 'Desktop\report.json')
# The forensics file is written by this SYSTEM agent but edited by the
# UAC-filtered desktop user, and os.chmod can't express NTFS ACLs — re-grant
# BUILTIN\Users modify every cycle. Harmless when absent.
$forensics = Join-Path $env:PUBLIC 'Desktop\Forensics-Questions.txt'
if (Test-Path $forensics) {
    icacls $forensics /grant '*S-1-5-32-545:M' | Out-Null
}
exit 0
