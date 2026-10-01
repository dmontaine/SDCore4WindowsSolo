# solo-restore-swap.ps1 - put a pending Solo restore in place before SD starts
#
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <root>\solo-restore-swap.ps1 -Root <root> [-CallerPid <n>[,<n>]]
#
# SOLO 25 (the multi-user product's RELEASE_1.1 116, ported).  RESTORE.ACCOUNT
# cannot replace Solo's one account from inside a session - every session is
# in it - so the shared verb unpacks and checks the archive, rewrites the
# staged VOC, and leaves <root>\.sdrestore.pending (six lines, written with
# WRITESEQ to that exact name - agreed with SD Core for Linux, 2 Oct 2026).
# sd.exe's start_sd() (gplsrc/sysseg.c apply_pending_restore) runs this when
# that file exists and SD is stopped, before the shared segment is made: the
# startup task's "sd -start" at boot and "sd -restart" by hand both come
# through there.  SD starts afterwards whatever this answers.
#
# Exit 0 applied; 1 failed (put back, marker kept); 2 not run because an SD
# process from this install is still running (marker kept); 3 nothing pending.
# The LAST line is exactly one of
#    SOLO-RESTORE APPLIED <account> from <archive>
#    SOLO-RESTORE FAILED <reason>
#    SOLO-RESTORE WAITING <reason>
#    SOLO-RESTORE NONE
# and every run that finds a marker appends what it did to <root>\sdrestore.log.
#
# THE ORDER (agreed with Linux): the account's current contents go to
# <root>\.sdrestore.previous, replacing an older copy, and stay there until the
# next restore so a bad one can be undone by hand; the staged contents move in;
# the children are reset to inherit the account directory's ACL; and only then
# is the marker deleted.  sd-account-archive.ps1 -Mode Place does the first
# three, and puts everything back if any step fails.
#
# THE MARKER IS CHECKED, NOT TRUSTED: the target must be an account directory
# under <root>\user_accounts and the staged tree must be under a
# <root>\.sdrestore.<n> directory, so a damaged or hand-made marker cannot
# point the swap at anything else.

# -CallerPid is a STRING of comma-separated pids: under -File, PowerShell hands
# "123,456" over as one string, which an [int[]] parameter would refuse.
param(
    [string]$Root = '',
    [string]$CallerPid = ''
)

$ErrorActionPreference = 'Stop'

# --- pure rules --------------------------------------------------------------

# The marker's six lines as an object, or a throw naming what is wrong.
#   1 format: 1   2 staged tree   3 target account directory   4 account name
#   5 created     6 the archive it came from
function Read-RestoreMarker([string[]]$lines, [string]$root) {
    if ($lines.Count -lt 6) { throw "the marker has $($lines.Count) lines, not 6" }
    if ($lines[0].Trim() -ne 'format: 1') { throw "unknown marker format '$($lines[0].Trim())'" }
    $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
    $m = [pscustomobject]@{
        Staged  = $lines[1].Trim(); Target  = $lines[2].Trim(); Account = $lines[3].Trim()
        Created = $lines[4].Trim(); Archive = $lines[5].Trim()
    }
    if ($m.Account -eq '') { throw 'the marker names no account' }
    foreach ($p in @($m.Staged, $m.Target)) {
        if ($p -notmatch '^[A-Za-z]:[\\/]') { throw "not a full path: '$p'" }
    }
    $m.Staged = [System.IO.Path]::GetFullPath($m.Staged).TrimEnd('\')
    $m.Target = [System.IO.Path]::GetFullPath($m.Target).TrimEnd('\')
    $accounts = $rootFull + '\user_accounts\'
    if (-not $m.Target.StartsWith($accounts, [System.StringComparison]::OrdinalIgnoreCase) -or
        $m.Target.Substring($accounts.Length).Contains('\')) {
        throw "the target is not an account directory under $accounts : $($m.Target)"
    }
    $stagingRoot = Get-StagingRoot $m.Staged $rootFull
    if ($stagingRoot -eq '') { throw "the staged tree is not under $rootFull\.sdrestore.<n>\accounts : $($m.Staged)" }
    $m | Add-Member -NotePropertyName StagingRoot -NotePropertyValue $stagingRoot
    return $m
}

# <root>\.sdrestore.<n> when $staged is <root>\.sdrestore.<n>\accounts\<name>,
# otherwise ''.
function Get-StagingRoot([string]$staged, [string]$rootFull) {
    $acctDir = Split-Path -Parent $staged
    $stage   = Split-Path -Parent $acctDir
    if ((Split-Path -Leaf $acctDir) -ne 'accounts') { return '' }
    if ((Split-Path -Leaf $stage) -notmatch '^\.sdrestore\.\d+$') { return '' }
    if (-not (Split-Path -Parent $stage).Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { return '' }
    return $stage
}

# Names of running processes whose executable lies under $rootFull, other than
# those in $exclude.  A process this user cannot read the path of is not ours.
function Find-RunningSd([string]$rootFull, [int[]]$exclude) {
    $prefix = $rootFull.TrimEnd('\') + '\'
    $found = @()
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        if ($exclude -contains $p.Id) { continue }
        $path = $null
        try { $path = $p.Path } catch { }
        if ($path -and $path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $found += "$($p.ProcessName) ($($p.Id))"
        }
    }
    return ,$found
}

# This process and every process above it.  THE sd.exe THAT RUNS THIS IS NOT
# ONE PROCESS: start_sd() forks, the MSYS2 child execs PowerShell, and that
# child stays alive as a waiting stub - another sd.exe under the install
# folder.  Excluding only the caller's pid would make every swap WAIT for
# itself, so the whole chain is excluded.  A link that cannot be read ends it.
function Get-AncestorPids([int]$start) {
    $ids = @($start)
    $cur = $start
    for ($i = 0; $i -lt 16; $i++) {
        $p = $null
        try { $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction Stop } catch { break }
        if (-not $p -or -not $p.ParentProcessId -or ($ids -contains [int]$p.ParentProcessId)) { break }
        $cur = [int]$p.ParentProcessId
        $ids += $cur
    }
    return ,$ids
}

# --- the run -----------------------------------------------------------------

if ($Root -eq '') { $Root = $PSScriptRoot }
$Root   = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
$marker = Join-Path $Root '.sdrestore.pending'
if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { Write-Output 'SOLO-RESTORE NONE'; exit 3 }

$log = Join-Path $Root 'sdrestore.log'
function Log([string]$m) {
    try { Add-Content -LiteralPath $log -Encoding ASCII -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $m) } catch { }
}
function Finish([int]$code, [string]$line) { Log $line; Write-Output $line; exit $code }

# Not "@(Get-AncestorPids $PID) + ...": the function returns its array as ONE
# object, and @() would nest it - measured, [int[]] then refused the result.
$ancestors = Get-AncestorPids $PID
$callers = @($CallerPid -split ',' | Where-Object { $_ -match '^\s*\d+\s*$' } | ForEach-Object { [int]$_ })
$exclude = [int[]]($ancestors + $callers)
Log "pending restore found: $marker (root $Root, not counting pids $($exclude -join ','))"
try {
    $m = Read-RestoreMarker ([System.IO.File]::ReadAllLines($marker)) $Root
} catch {
    Finish 1 "SOLO-RESTORE FAILED the marker cannot be used - $($_.Exception.Message)"
}
Log "account $($m.Account), staged $($m.Staged), target $($m.Target), from $($m.Archive), made $($m.Created)"

$running = Find-RunningSd $Root $exclude
if ($running.Count -gt 0) {
    Finish 2 ("SOLO-RESTORE WAITING SD is still running from this install: " + ($running -join ', '))
}

$archive = Join-Path $PSScriptRoot 'sd-account-archive.ps1'
$previous = Join-Path $Root '.sdrestore.previous'
$out = @(& $archive -Mode Place -Staged $m.Staged -Target $m.Target -Previous $previous 2>&1 | ForEach-Object { "$_" })
foreach ($l in $out) { Log "  $l" }
$last = @($out | Where-Object { $_.StartsWith('ACC-ARCHIVE ') -and -not $_.StartsWith('ACC-ARCHIVE mode=') }) | Select-Object -Last 1
if (-not $last -or -not $last.StartsWith('ACC-ARCHIVE PLACE OK')) {
    $why = if ($last) { $last } else { 'no result from sd-account-archive.ps1' }
    Finish 1 "SOLO-RESTORE FAILED $why - the account is as it was and the restore is still pending"
}

try { Remove-Item -LiteralPath $marker -Force }
catch { Finish 1 "SOLO-RESTORE FAILED the restore IS in place, but $marker could not be deleted: $($_.Exception.Message)" }
Remove-Item -LiteralPath $m.StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $m.StagingRoot) { Log "note: $($m.StagingRoot) could not be removed" }

Finish 0 "SOLO-RESTORE APPLIED $($m.Account) from $($m.Archive)"
