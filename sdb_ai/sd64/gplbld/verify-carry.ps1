<#
.SYNOPSIS
    The Linux 1.2-0 sandbox suites of carry areas 1 to 5, run against the INSTALLED
    SD Core Solo in its one account, sduser (RELEASE_1.1 143).  ***AN ORDINARY UNELEVATED PROMPT.***

.DESCRIPTION
    gplbld\verify-carry-NAME.py are byte copies of SD Core for Linux's
    sandbox-NAME.py, each at the newest CARRIED commit that touches it (area 1: Linux
    Dev 1c94d00..ba885ac, bundles A-1..A-9, B-1..B-5, B-9, the second sitting parts
    1-32, the data collections, akcase; areas 2-5 to 5315c65: the rest of the data
    collections, the language and option batches, the B-bundle second parts, the QM4
    gap sittings and Fixes), the same files SD Core for Windows carries.  Each one
    writes probe programs into <box>\sys\bp, compiles and runs them in an SD session,
    and judges what the session printed.  Linux gives them a private sandbox; here:

      * the BOX is %LOCALAPPDATA%\SD-verify\carry-box-<time>, holding
          sys            a JUNCTION to sduser's account directory, so the suite's
                         bp, bp.out, cat, $hold ... are that account's;
          user_accounts  an empty directory (Linux passes it as the cwd);
      * verify-carry-run.py stands in for Linux's sandbox-fromtree.py: every
        session the suite asks for is sd-solo.exe with the stdin Linux sends,
        PRECEDED BY THE ACCOUNT PASSWORD (Solo asks for it at every session) and
        followed by two spare OFF lines (SOLO 16).  The suites are NOT edited.

    ***THE ACCOUNT PASSWORD IS ASKED FOR ONCE, at the start, and reaches the
    launcher only through the environment of this process (SD_CARRY_PW).*** It is
    never printed, never written to a file, and the launcher masks it in any
    output; the variable is removed again when the run ends.

    ***WHAT A ROW MEANS HERE.***  The suites were written against a Linux sandbox
    that plays SDSYS.  A row that depends on that, or on a Linux path, a shell
    command or an sd.conf location, can fail on Windows without the feature being
    wrong.  Linux's expected-output lists (P:\sdcore-mail\parity\linux-core-carry-18oct\expected)
    mark such rows "Linux-only"; $Known below names the rows judged N/A on
    Windows, each with its reason, and they are printed as N/A, never as PASS.
    Solo has no SDSYS to play: a row that needs the administrator is expected to
    fail here until it is named in $Known with that reason.  $Known is read from
    verify-carry-known.psd1 beside this script, so a row is named there and the
    script is not edited.  That file also lists the suites that cannot run at all in an
    ordinary account must not run (NotRun, each with the Linux mechanism that stopped it
    - and two that print on the Windows default printer); they are printed as NOT RUN,
    and a run that skipped any is never reported as the whole carry.

    ***NOT CARRIED, AND WHY.***  Seven Linux suites are left out because a suite that
    cannot start exits 2 and would make the whole step COULD NOT RUN: dbgui, footpause,
    inputfill, inputif, inputtrap and fixes-b12 import Linux's pty module (ptydrive) to
    drive a terminal, and sync needs strace.  Three expected lists have no carried
    commit (edseqkey, lockown, qm4def) and terminfo-ext was skipped by instruction;
    splitfull imports Linux's resource module (RLIMIT_FSIZE).  Mechanisms the launcher
    does not emulate - a pty, the TZ variable, sd.conf plus a restart, strace, symlinks,
    a user id, /tmp literals - make a ROW N/A (name it in the data file), not a suite.

    ***THE INSTRUMENT IS WHAT THE SUITES PRINT.***  This step prints every
    suite's own PASS/FAIL lines, then a table of rows per suite.  A suite that
    exits 0 having printed no PASS line is COULD NOT RUN, not a pass.

    Needs: an installed SD Core Solo that matches source (assert-current first),
    python on PATH, and the account password.

.PARAMETER Suite
    Suite names without the verify-carry- prefix (func-b4, coll ...), comma
    separated or as a list.  Default: every verify-carry-*.py in this folder.

.OUTPUTS
    Exit 0 every suite passed, 1 a row failed, 2 a suite could not run.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\verify-carry.ps1 -Suite func-b4,conv-b3
#>

[CmdletBinding()]
param(
    [string[]]$Suite = @(),
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'

$Gplbld  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Run     = Join-Path $Gplbld 'verify-carry-run.py'
$Root    = Join-Path $env:USERPROFILE 'SDCoreSolo'
$SdExe   = Join-Path $Root 'usr\bin\sd-solo.exe'
$Acct    = 'sduser'                                   # ruling 29: the account is always sduser
$AcctDir = Join-Path $Root ('user_accounts\' + $Acct)

# Rows judged N/A on Windows: 'suite' = @{ 'start of the row label' = 'reason' }, in verify-carry-known.psd1.
# Empty until the first run on a fresh install shows which rows are a Linux mechanism, or need SDSYS, and not a feature.
$Known = @{}
$NotRun = @{}                                          # suites that cannot run in this mode at all: 'suite' = 'reason'
$KnownFile = Join-Path $Gplbld 'verify-carry-known.psd1'
if (Test-Path -LiteralPath $KnownFile) {
    $kd = Import-PowerShellDataFile -LiteralPath $KnownFile
    if ($kd.ContainsKey('Rows'))   { $Known  = $kd['Rows'] }
    if ($kd.ContainsKey('NotRun')) { $NotRun = $kd['NotRun'] }
}

function Say([string]$m) { Write-Host $m }
function Bail([int]$code, [string]$why) {
    Say ''
    if ($code -eq 0) { Say "verify-carry: PASSED - $why" }
    elseif ($code -eq 1) { Say "verify-carry: FAILED - $why" }
    else { Say "verify-carry: COULD NOT RUN - $why" }
    exit $code
}
function Read-Password([string]$Prompt) {
    $ss = Read-Host -AsSecureString $Prompt
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

# --- which suites ---------------------------------------------------------------------------------
$all = @(Get-ChildItem -LiteralPath $Gplbld -File -Filter 'verify-carry-*.py' |
         Where-Object { $_.Name -ne 'verify-carry-run.py' } |
         ForEach-Object { $_.Name -replace '^verify-carry-', '' -replace '\.py$', '' } | Sort-Object)
if ($all.Count -lt 60) { Bail 2 "only $($all.Count) verify-carry-*.py found in $Gplbld; expected 93." }
$names = @($Suite | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($names.Count -eq 0) { $names = $all }
foreach ($n in $names) {
    if ($all -notcontains $n) { Bail 2 "no suite called '$n'. Known: $($all -join ', ')" }
}

Say "verify-carry: product    SD Core Solo, account $Acct"
Say "verify-carry: suites     $($names -join ', ')"
Say "verify-carry: launcher   $Run"
Say ''

if (-not (Test-Path -LiteralPath $Run)) { Bail 2 "verify-carry-run.py is missing from $Gplbld." }
if (-not (Test-Path -LiteralPath $SdExe)) { Bail 2 "no sd-solo.exe at $SdExe - SD Core Solo does not look installed." }
if (-not (Test-Path -LiteralPath (Join-Path $AcctDir 'bp'))) { Bail 2 "no bp file at $AcctDir\bp." }
if ($null -eq (Get-Command python -ErrorAction SilentlyContinue)) { Bail 2 'python is not on PATH.' }
$pyv = (& python -c "import sys; print(sys.version_info[0])" 2>&1 | Out-String).Trim()
if ($pyv -ne '3') { Bail 2 "python on PATH is not Python 3 (it answered '$pyv')." }

# --- the install must match source ---------------------------------------------------------------
Say '--- assert-current -------------------------------------------------'
& (Join-Path $Gplbld 'assert-current.ps1')
if ($LASTEXITCODE -ne 0) { Bail 2 'assert-current refuses - the installed tree does not match source.' }

# --- the account password -------------------------------------------------------------------------
$pw = Read-Password "Account password for $Acct"
$bad = $false
if (-not $pw) { $bad = $true }
else { foreach ($c in $pw.ToCharArray()) { if ([int]$c -lt 33 -or [int]$c -gt 126) { $bad = $true } } }
if ($bad) { Bail 2 'the account password is empty or has a character outside printable ASCII (the installer allows 33-126 only).' }

# --- the box ---------------------------------------------------------------------------------------
$logDir = Join-Path $env:LOCALAPPDATA 'SD-verify'
$box = Join-Path $logDir ('carry-box-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = New-Item -ItemType Directory -Path $box -Force
$null = New-Item -ItemType Directory -Path (Join-Path $box 'user_accounts') -Force
$null = New-Item -ItemType Junction -Path (Join-Path $box 'sys') -Target $AcctDir
Say "verify-carry: box        $box"
Say "verify-carry: sys        -> $AcctDir  (a junction)"
if (-not (Test-Path -LiteralPath (Join-Path $box 'sys\bp'))) { Bail 2 'the junction does not show the account bp file.' }
Say ''

$env:SD_EXE = $SdExe
$env:SD_CARRY_CONF = Join-Path $Root 'sd.conf'
$env:SD_CARRY_PW = $pw
$env:SD_CARRY_SPARE_OFF = '2'
$env:SD_CARRY_TIMEOUT = '300'

$rows = @()
$worst = 0
try {
    foreach ($n in $names) {
        $file = Join-Path $Gplbld "verify-carry-$n.py"
        Say "=== $n ====================================================="
        if ($NotRun.ContainsKey($n)) {
            Say ("  [N/A ] the whole suite is not run here   (" + $NotRun[$n] + ")")
            $rows += [pscustomobject]@{ Suite = $n; Rows = 0; Pass = 0; Fail = 0; NA = 0; Exit = '-'; Secs = 0; Verdict = 'NOT RUN' }
            Say ''
            continue
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $pass = 0; $fail = 0; $na = 0; $failed = @()
        # Windows PowerShell 5.1 turns a native command's stderr into a terminating error when
        # ErrorActionPreference is Stop and 2>&1 is used; the suites print to stderr on a failed row.
        $ErrorActionPreference = 'Continue'
        $lines = @(& python -X utf8 $Run $file $box 2>&1 | ForEach-Object { "$_" })
        $rc = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        foreach ($l in $lines) {
            $mark = $false
            if ($l -match '^\s*\[FAIL\]\s*(.*)$') {
                $label = $Matches[1]
                $why = $null
                if ($Known.ContainsKey($n)) {
                    foreach ($k in $Known[$n].Keys) { if ($label.StartsWith($k)) { $why = $Known[$n][$k] } }
                }
                if ($why) { $na++; Say ("  [N/A ] " + $label + "   (" + $why + ")"); $mark = $true }
                else { $fail++; $failed += $label }
            } elseif ($l -match '^\s*\[PASS\]') { $pass++ }
            if (-not $mark) { Say $l.Replace($pw, '********') }
        }
        $sw.Stop()
        # A suite that printed no row at all, or exited with a code that is not 0 or 1 (-1 is a killed run), measured nothing.
        if ($null -eq $rc -or $rc -lt 0 -or $rc -ge 2 -or ($pass + $fail + $na) -eq 0 -or ($rc -eq 0 -and $pass -eq 0)) { $verdict = 'COULD NOT RUN'; $worst = [Math]::Max($worst, 2) }
        elseif ($fail -gt 0 -or ($rc -eq 1 -and $na -eq 0)) { $verdict = 'FAIL'; $worst = [Math]::Max($worst, 1) }
        else { $verdict = 'PASS' }
        $rows += [pscustomobject]@{ Suite = $n; Rows = ($pass + $fail + $na); Pass = $pass; Fail = $fail; NA = $na; Exit = $rc; Secs = [int]$sw.Elapsed.TotalSeconds; Verdict = $verdict }
        Say ''
    }
} finally {
    Remove-Item Env:SD_CARRY_PW -ErrorAction SilentlyContinue
    Remove-Item Env:SD_CARRY_SPARE_OFF -ErrorAction SilentlyContinue
    Remove-Item Env:SD_CARRY_TIMEOUT -ErrorAction SilentlyContinue
    Remove-Item Env:SD_EXE -ErrorAction SilentlyContinue
    Remove-Item Env:SD_CARRY_CONF -ErrorAction SilentlyContinue
    if (-not $Keep) {
        # Remove the junction ITSELF first, and delete the rest of the box only once it is gone:
        # a recursive Remove-Item through a live junction would delete the account it points at.
        $sysLink = Join-Path $box 'sys'
        if (Test-Path -LiteralPath $sysLink) { [System.IO.Directory]::Delete($sysLink, $false) }
        if (-not (Test-Path -LiteralPath $sysLink)) {
            Remove-Item -LiteralPath $box -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "WARNING: the junction $sysLink is still there; the box was left alone." -ForegroundColor Red
        }
        if (-not (Test-Path -LiteralPath (Join-Path $AcctDir 'bp'))) {
            Write-Host 'WARNING: the account bp file is missing after cleanup' -ForegroundColor Red
        }
    }
}

Say '--- summary --------------------------------------------------------'
$rows | Format-Table Suite, Rows, Pass, Fail, NA, Exit, Secs, Verdict -AutoSize | Out-String -Width 200 | ForEach-Object { Say $_.TrimEnd() }
$totR = ($rows | Measure-Object Rows -Sum).Sum
$totF = ($rows | Measure-Object Fail -Sum).Sum
$totN = ($rows | Measure-Object NA -Sum).Sum
$nRun = @($rows | Where-Object { $_.Verdict -ne 'NOT RUN' }).Count
$nSkip = $rows.Count - $nRun
Say ("verify-carry: {0} suite(s) run, {1} NOT RUN here (named in verify-carry-known.psd1), {2} row(s), {3} failed, {4} N/A on Windows" -f $nRun, $nSkip, $totR, $totF, $totN)
if ($nRun -eq 0) { Bail 2 'no suite ran: every suite named is listed as NOT RUN, so nothing was measured.' }

if ($worst -eq 2) { Bail 2 'at least one suite could not run (or printed no PASS row): nothing may be concluded from it.' }
if ($worst -eq 1) { Bail 1 "$totF row(s) failed." }
if ($nSkip -gt 0) { Bail 0 "$totR row(s) in $nRun suite(s); $nSkip suite(s) NOT RUN here, so this is not the whole carry." }
Bail 0 "$totR row(s) in $nRun suite(s)."
