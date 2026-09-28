<#
.SYNOPSIS
    Run one whole SD Core Solo test cycle: build the C if needed, stop SD,
    stage and bootstrap, build the installer, uninstall, DELETE
    %USERPROFILE%\SDCoreSolo, install, assert-current.

.DESCRIPTION
    26 Sep 26 SD Core Solo - SOLO 9 phase 2.  REWRITTEN FOR SOLO.  The
    multi-user cycle (sd.iss, the SD service, C:\Program Files\SD and
    C:\ProgramData\SD, elevated) is in git: git show 21c429d:sdb_ai/sd64/gplbld/cycle.ps1.
    Its reasons are kept here where they still apply, shortened; the long
    measurements behind them are in that version and in HISTORY.md.

    OWNER'S RULINGS THIS FOLLOWS:
      * one command for the whole cycle, no hand-run steps (17 Aug 2026);
      * a test cycle begins with a FRESH install, never a reinstall (15 Aug);
      * no silent install - the wizard runs and a person answers it (23 Aug);
      * compile C if necessary, BASIC always, install always (3 Sep);
      * a Solo cycle WIPES AND REINSTALLS THE REAL %USERPROFILE%\SDCoreSolo
        (26 Sep 2026, SOLO 9).  ANYTHING KEPT THERE IS LOST EVERY CYCLE.

    RUN IT UNELEVATED.  The Solo installer is PrivilegesRequired=lowest and
    asks for elevation itself, once, for its machine step (sd-solo.iss,
    solo-machine.ps1); the uninstaller does the same for its Remove step.
    Started elevated, the "unelevated" install steps would run elevated too,
    which is not what they were written or measured for.

.PARAMETER Stage
    Staging tree, rebuilt from scratch (--force).  Default: the repository's
    own stage\ folder (a long scratch path trips SOLO 12).

.PARAMETER Out
    Where ISCC writes the installer.

.PARAMETER SkipInstall
    Stop after building the installer.  Nothing is uninstalled or deleted -
    the cheap way to find out whether a change compiles.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\cycle.ps1
#>

[CmdletBinding()]
param(
    [string] $Stage = '',
    # 27 Sep 2026 - was %USERPROFILE%\sdout.  A subfolder, not Project_Installers
    # itself: a test build has the release installer's file name and would
    # overwrite it.
    [string] $Out   = (Join-Path $env:USERPROFILE 'Projects\Project_Installers\sdout'),
    [switch] $SkipInstall
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# THE TRANSCRIPT.  Not under the Solo tree, which step 6 deletes.  Any
# transcript this window left open is closed first: PowerShell 5.1 keeps
# several active at once and every one receives every line (measured 24 Aug
# 2026 - one run appended itself to three earlier logs).
$logDir = Join-Path $env:LOCALAPPDATA 'SD-verify'
if (-not (Test-Path -LiteralPath $logDir)) { $null = New-Item -ItemType Directory -Path $logDir -Force }
$script:CycleLog = Join-Path $logDir ('cycle-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$stale = 0
while ($true) {
    try { Stop-Transcript -ErrorAction Stop | Out-Null; $stale++ } catch { break }
}
if ($stale -gt 0) { Write-Host ("closed $stale transcript(s) this window had left open") }
try { Start-Transcript -Path $script:CycleLog -Force | Out-Null } catch { }
Write-Host "transcript: $script:CycleLog"
function StopCycleTranscript { try { Stop-Transcript | Out-Null } catch { } }

# Every path is absolute and derived from this script's location - the
# hand-run sequence broke on a relative path resolved against System32.
$Gplbld   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Sd64     = Split-Path -Parent $Gplbld
$Repo     = Split-Path -Parent (Split-Path -Parent $Sd64)
$Iss      = Join-Path $Gplbld 'sd-solo.iss'
$Bash     = 'C:\msys64\usr\bin\bash.exe'
$SoloRoot = Join-Path $env:USERPROFILE 'SDCoreSolo'
$SoloSd   = Join-Path $SoloRoot 'usr\bin\sd.exe'
if ($Stage -eq '') { $Stage = Join-Path $Repo 'stage' }

# PRE_RELEASE 137: the log is measured for completeness at the end, because
# PowerShell 5.1 drops native output under a fast producer.
. (Join-Path $Gplbld 'transcript-whole.ps1')
function ReportTranscriptWholeness {
    $res = Get-TranscriptWholeness -TranscriptPath $script:CycleLog -StagePath $Stage
    $null = Write-TranscriptWholeness -Result $res
}

# ISCC: the default path, then Inno's uninstall keys (HKLM and HKCU - a
# per-user install writes HKCU), then the per-user default location.
$Iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
if (-not (Test-Path -LiteralPath $Iscc)) {
    foreach ($k in @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1')) {
        try { $loc = (Get-ItemProperty -LiteralPath $k -ErrorAction Stop).InstallLocation } catch { continue }
        if ([string]::IsNullOrWhiteSpace($loc)) { continue }
        $cand = Join-Path $loc 'ISCC.exe'
        if (Test-Path -LiteralPath $cand) { $Iscc = $cand; break }
    }
}
if (-not (Test-Path -LiteralPath $Iscc)) {
    $userIscc = Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
    if (Test-Path -LiteralPath $userIscc) { $Iscc = $userIscc }
}

function Step($n, $msg) { Write-Host ""; Write-Host "== [$n] $msg" -ForegroundColor Cyan }
function Fail($msg) {
    Write-Host ""
    Write-Host "CYCLE STOPPED: $msg" -ForegroundColor Red
    StopCycleTranscript
    exit 1
}
# A Windows path in the /c/... form MSYS2 wants; a backslash through bash -lc
# is eaten as an escape.
function ToMsys([string] $p) {
    $p = $p -replace '\\', '/'
    if ($p -match '^([A-Za-z]):(.*)$') { return "/$($Matches[1].ToLower())$($Matches[2])" }
    return $p
}
# The sd/sdwind processes of THIS tree or the stage - not the multi-user
# service's, which has its own check below.
function SoloProcesses {
    @(Get-Process -Name sd, sdwind -ErrorAction SilentlyContinue | Where-Object {
        $p = $null; try { $p = $_.Path } catch { }
        (-not $p) -or $p.StartsWith($SoloRoot, 'OrdinalIgnoreCase') -or $p.StartsWith($Stage, 'OrdinalIgnoreCase')
    })
}

# ---------------------------------------------------------------------------
# PRECONDITIONS - all checked before anything is stopped, staged or deleted.
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail ("this is ELEVATED.  Run the Solo cycle from an ordinary UNELEVATED PowerShell - the " +
          "installer asks for elevation itself, once, for its machine step.")
}
foreach ($p in @($Iscc, $Bash, $Iss)) {
    if (-not (Test-Path -LiteralPath $p)) { Fail "not found: $p" }
}
foreach ($n in 'Stage', 'Out') {
    $v = (Get-Variable -Name $n).Value
    if (-not [System.IO.Path]::IsPathRooted($v)) { Fail "-$n must be an absolute path, and '$v' is not." }
    Set-Variable -Name $n -Value ([System.IO.Path]::GetFullPath($v))
}
# THE DELETE TARGET, PINNED.  Step 6 removes it recursively, so it must be
# exactly <profile>\SDCoreSolo and nothing that merely resolves there.
if ($SoloRoot -ne [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'SDCoreSolo')) -or
    (Split-Path -Leaf $SoloRoot) -ne 'SDCoreSolo') {
    Fail "the Solo tree resolved to '$SoloRoot', not <profile>\SDCoreSolo - refusing to go on."
}
# THE MULTI-USER PRODUCT BLOCKS BOTH HALVES.  sd-solo.iss refuses to install
# beside it ("SD Core is installed on this computer. Uninstall it first."), and
# while its service runs the machine-wide semaphores make the bootstrap fail
# ("Semaphores are already present", SOLO 8).  Said now, not at step 2 or 7.
$muSvc = Get-Service -Name 'SD' -ErrorAction SilentlyContinue
if ($muSvc -and $muSvc.Status -eq 'Running') {
    Fail ("the multi-user SD service is RUNNING - its semaphores would break the bootstrap.  Stop it " +
          "in an ELEVATED prompt:  C:\Windows\System32\sc.exe stop SD")
}
if ((-not $SkipInstall) -and (Test-Path -LiteralPath 'C:\Program Files\SD\usr\bin\sd.exe')) {
    Fail ("the multi-user SD is installed (C:\Program Files\SD), and the Solo installer refuses to " +
          "install beside it.  Uninstall it first, or use -SkipInstall to only build.")
}

# LINT sd-solo.iss BEFORE ANYTHING EXPENSIVE.  ISPP reads a line starting "#"
# as a directive and ISCC a line starting "[" as a section tag - inside a brace
# comment too - and each cost a whole multi-user cycle (19 Aug, 4 Sep 2026).
$issDirectives = @('define', 'undef', 'include', 'if', 'ifdef', 'ifndef', 'ifexist', 'ifnexist',
                   'elif', 'else', 'endif', 'for', 'sub', 'endsub', 'expr', 'insert', 'append',
                   'emit', 'error', 'pragma', 'file', 'x', 'dim', 'redim')
$issBad = @(Get-Content -LiteralPath $Iss | Select-String -Pattern '^\s*#\s*(\w*)' |
            Where-Object { $issDirectives -notcontains $_.Matches[0].Groups[1].Value.ToLower() })
if ($issBad.Count -gt 0) {
    $issBad | ForEach-Object { Write-Host ("   sd-solo.iss:{0}: {1}" -f $_.LineNumber, $_.Line.Trim()) -ForegroundColor Red }
    Fail ("sd-solo.iss has {0} line(s) starting with '#' that ISPP will read as a directive." -f $issBad.Count)
}
$issSections = @('Setup', 'Languages', 'Messages', 'Tasks', 'Files', 'Dirs', 'Icons', 'Run',
                 'UninstallRun', 'Code', 'Registry', 'InstallDelete', 'UninstallDelete',
                 'Components', 'Types', 'CustomMessages', 'INI', 'LangOptions', 'UninstallRegistry')
$issTags = @(Get-Content -LiteralPath $Iss | Select-String -Pattern '^\s*\[([A-Za-z]*)\]?' |
             Where-Object { $issSections -notcontains $_.Matches[0].Groups[1].Value })
if ($issTags.Count -gt 0) {
    $issTags | ForEach-Object { Write-Host ("   sd-solo.iss:{0}: {1}" -f $_.LineNumber, $_.Line.Trim()) -ForegroundColor Red }
    Fail ("sd-solo.iss has {0} line(s) starting with '[' that ISCC will read as a section tag." -f $issTags.Count)
}

Write-Host ("inputs: stage {0}   out {1}   installer script {2}" -f $Stage, $Out, $Iss)
Write-Host ("        Solo tree {0}   ISCC {1}" -f $SoloRoot, $Iscc)

# THE PACKAGES BESIDE THE INSTALLER, CHECKED BEFORE ANYTHING IS UNINSTALLED OR
# DELETED.  Owner's ruling 27 Sep 2026: "installation package must always have
# the SSH MSI and Python exe available, otherwise it is an invalid installation
# package" - sd-solo.iss refuses to start without them, and the install below
# runs from $Out, so a cycle that got that far would have deleted the tree for
# an installer that then refuses.  They are binaries, so never in the repo:
# placed once in $Out\ssh-server and $Out\python, which the build leaves alone.
if (-not $SkipInstall) {
    $pkgMsi = @(Get-ChildItem -LiteralPath (Join-Path $Out 'ssh-server') -Filter '*.msi' -File -ErrorAction SilentlyContinue)
    $pkgPy  = @(Get-ChildItem -LiteralPath (Join-Path $Out 'python') -Filter 'python-3*-amd64.exe' -File -ErrorAction SilentlyContinue)
    Write-Host ("        beside the installer: ssh-server\*.msi {0}   python\python-3*-amd64.exe {1}" -f
                $(if ($pkgMsi.Count) { $pkgMsi[0].Name } else { 'MISSING' }), $(if ($pkgPy.Count) { $pkgPy[0].Name } else { 'MISSING' }))
    if ($pkgMsi.Count -eq 0 -or $pkgPy.Count -eq 0) {
        Fail ("the installation package is incomplete - put Microsoft's OpenSSH MSI in " + (Join-Path $Out 'ssh-server') +
              " and python.org's python-3.x-amd64.exe in " + (Join-Path $Out 'python') +
              ".  Nothing was uninstalled or deleted.")
    }
}

# ---------------------------------------------------------------------------
# STEP 0 - THE C.  make relinks only what changed, while assert-current
# compares source against the OLDEST binary in bin\, so when anything is stale
# the binaries are deleted and all relinked, and the guard is asked again
# rather than trusting make's exit code (3 Sep 2026, PROJECT_STATUS "110 AND
# 111").  stale-binaries.ps1 is the guard's own rule.  A FULL "make sd",
# sdpy included: sdpy.exe is one of the binaries the guard compares, so
# skipping it leaves the tree stale for ever.  (make's sdpy step fails from an
# agent's shell - the memory file's shell traps - not from the owner's.)
Step 0 "Building the C, if source has moved past bin\"
. (Join-Path $Gplbld 'stale-binaries.ps1')
$binState = Get-BinaryStaleness $Sd64
if (-not $binState.ok) {
    Write-Host ("   $($binState.reason) - building all of it")
    $mustBuild = $true
} elseif ($binState.stale) {
    Write-Host ("   {0} source file(s) newer than bin\{1} ({2}):" -f $binState.uncompiled.Count,
                $binState.oldest.Name, $binState.oldest.LastWriteTime.ToString('dd MMM HH:mm:ss'))
    $binState.uncompiled | Select-Object -First 10 | ForEach-Object {
        Write-Host ("       {0}  {1}" -f $_.LastWriteTime.ToString('dd MMM HH:mm:ss'), $_.FullName.Substring($Sd64.Length + 1))
    }
    $mustBuild = $true
} else {
    Write-Host ("   bin\ built {0}, no source newer - nothing to compile" -f $binState.oldest.LastWriteTime.ToString('dd MMM HH:mm:ss'))
    $mustBuild = $false
}
if ($mustBuild) {
    foreach ($b in $binState.binaries) {
        Remove-Item -LiteralPath $b.FullName -Force -ErrorAction SilentlyContinue
    }
    $mk = "cd '$(ToMsys $Sd64)' && make sd"
    Write-Host "   $Bash -lc ""$mk"""
    & $Bash -lc $mk
    if ($LASTEXITCODE -ne 0) { Fail "make exited $LASTEXITCODE - nothing else has run." }
    $binState = Get-BinaryStaleness $Sd64
    if (-not $binState.ok) { Fail ("after make: " + $binState.reason) }
    if ($binState.stale) {
        Fail ("make exited 0 but {0} source file(s) are STILL newer than bin\{1}." -f
              $binState.uncompiled.Count, $binState.oldest.Name)
    }
    Write-Host ("   built: bin\ now {0}, no source newer" -f $binState.oldest.LastWriteTime.ToString('dd MMM HH:mm:ss'))
}

# ---------------------------------------------------------------------------
# STEP 1 - STOP SD.  The installed Solo SD with its own "sd -stop" (unelevated
# works, SOLO 8), then wait on the PROCESSES, which hold the segment and the
# semaphores.  Named, not killed: a surviving "sd" is somebody's session.
Step 1 "Stopping SD Core Solo"
if (Test-Path -LiteralPath $SoloSd) {
    $stopOut = (& $SoloSd -stop 2>&1 | Out-String)
    $stopOut -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "     $_" }
} else {
    Write-Host "   no Solo install at $SoloSd"
}
$deadline = (Get-Date).AddSeconds(30)
while ((SoloProcesses).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
$left = SoloProcesses
if ($left.Count -gt 0) {
    Fail ("SD is still running after 30s: " + (($left | ForEach-Object { "$($_.Name)($($_.Id))" }) -join ', ') +
          "`n  Close any SD session and run this again.")
}
Write-Host "   SD is stopped"

# ---------------------------------------------------------------------------
# STEP 2 - STAGE AND BOOTSTRAP (this is the BASIC compile).  Through an MSYS2
# LOGIN shell, with output to the console - never a pipe: "sd -start" forks
# sdwind, which holds inherited handles for life.
Step 2 "Staging and bootstrapping into $Stage"
$cmd = "cd '$(ToMsys $Sd64)' && python3 gplbld/stage.py --stage '$(ToMsys $Stage)' --force --bootstrap"
& $Bash -lc $cmd
if ($LASTEXITCODE -ne 0) { Fail "stage.py exited $LASTEXITCODE - the staged tree is not usable" }

# ---------------------------------------------------------------------------
# STEP 3 - IS THE STAGED TREE WHOLE?  What stands between a silent bootstrap
# failure and an installer built from the wreckage (16 Aug 2026).  Locals are
# prefixed: PowerShell names are case-insensitive, and "$out" once overwrote
# the -Out parameter.
Step 3 "Checking the staged tree is whole"
$stSys = Join-Path $Stage 'SDCoreSolo\sdsys'
function CountIn($root, $sub, [switch] $Recurse) {
    $d = Join-Path $root $sub
    if (-not (Test-Path -LiteralPath $d)) { return -1 }
    if ($Recurse) { return (Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue).Count }
    (Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue).Count
}
$nGcat   = CountIn $stSys 'gcat'
$nOut    = CountIn $stSys 'gpl.bp.out'
$nTinfo  = CountIn $stSys 'terminfo' -Recurse
$szCproc = if (Test-Path -LiteralPath (Join-Path $stSys 'gcat\$cproc')) { (Get-Item -LiteralPath (Join-Path $stSys 'gcat\$cproc')).Length } else { -1 }
$szBcomp = if (Test-Path -LiteralPath (Join-Path $stSys 'gcat\$bcomp')) { (Get-Item -LiteralPath (Join-Path $stSys 'gcat\$bcomp')).Length } else { -1 }
$nCred   = CountIn $stSys '$cred'
Write-Host ("   {0}" -f $stSys)
Write-Host ("   gcat {0} (want ~130)   gpl.bp.out {1} (want ~200)   terminfo {2} (want ~100)" -f $nGcat, $nOut, $nTinfo)
Write-Host ("   `$cproc {0} bytes (want >0)   `$bcomp {1} (want ~88,000; under 80,000 is bbcmp.py's seed)   `$cred {2} (want 0)" -f $szCproc, $szBcomp, $nCred)
$faults = @()
if ($szCproc -le 0)   { $faults += '$cproc is the 0-byte placeholder - the bootstrap never reached the last step' }
if ($nGcat   -lt 100) { $faults += "gcat holds $nGcat entries" }
if ($nOut    -lt 150) { $faults += "gpl.bp.out holds $nOut objects" }
if ($nTinfo  -lt 50)  { $faults += "terminfo holds $nTinfo entries - no terminal type would resolve" }
if ($szBcomp -ge 0 -and $szBcomp -lt 80000) { $faults += "`$bcomp is $szBcomp bytes - bbcmp.py's seed, not BCOMP's own object" }
if (-not (Test-Path -LiteralPath (Join-Path $stSys 'voc'))) { $faults += "voc is absent - 'sd -i' did not complete" }
if ($nCred -gt 0)     { $faults += "the stage holds $nCred credential record(s) - a probe ran on it; sd-solo.iss would refuse the build" }
if ($faults) { Fail ("the staged tree is not whole:`n  - " + ($faults -join "`n  - ")) }
Write-Host "   staged tree is whole"

# ---------------------------------------------------------------------------
# STEP 4 - THE INSTALLER.  Freshness is checked against a time this run owns:
# an ISCC that exits 0 having written nothing leaves the PREVIOUS installer
# newest in $Out (2 Sep 2026).
Step 4 "Building the installer"
if (-not (Test-Path -LiteralPath $Out)) { New-Item -ItemType Directory -Path $Out | Out-Null }
$isccStart = Get-Date
& $Iscc "/DStage=$Stage" "/O$Out" $Iss
if ($LASTEXITCODE -ne 0) { Fail "ISCC exited $LASTEXITCODE" }
$setup = Get-ChildItem -LiteralPath $Out -Filter 'sd-solo-setup-*.exe' |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $setup) { Fail "ISCC reported success but no sd-solo-setup-*.exe is in $Out" }
if ($setup.LastWriteTime -lt $isccStart) {
    Fail ("ISCC exited 0 but the newest installer in $Out predates this run: $($setup.Name) " +
          "written $($setup.LastWriteTime), ISCC started $isccStart.")
}
Write-Host ("   {0}, {1:N0} bytes, {2}" -f $setup.FullName, $setup.Length, $setup.LastWriteTime)
# SOLO 18: the control file's template goes beside every installer built.  As
# .sample it is inert - only a file named sd-solo-setup.conf is read.  If one
# of those is here, THIS cycle's install is driven by it: said out loud.
Copy-Item -LiteralPath (Join-Path $Gplbld 'sd-solo-setup.conf.sample') -Destination $Out -Force
Write-Host ("   control file template: {0}" -f (Join-Path $Out 'sd-solo-setup.conf.sample'))
if (Test-Path -LiteralPath (Join-Path $Out 'sd-solo-setup.conf')) {
    Write-Host ("   CONTROL FILE PRESENT: {0} - this install will be MANAGED and take its answers from it" -f
                (Join-Path $Out 'sd-solo-setup.conf')) -ForegroundColor Yellow
}

if ($SkipInstall) {
    Write-Host ""
    ReportTranscriptWholeness
    Write-Host ""
    Write-Host "-SkipInstall: stopping here.  The installed tree is untouched and STALE." -ForegroundColor Yellow
    StopCycleTranscript
    exit 0
}

# ---------------------------------------------------------------------------
# STEP 5 - UNINSTALL.  The PREVIOUS install's uninstaller (unins000.exe is
# written at install time, so an uninstaller fix is verified one cycle late).
# It stops SD and runs solo-machine Remove, which asks for elevation - answer
# the prompt.  Inno's uninstaller copies itself and returns at once, so the
# wait is on unins000.exe disappearing, not on the process.
Step 5 "Uninstalling"
$unins = Join-Path $SoloRoot 'unins000.exe'
if (Test-Path -LiteralPath $unins) {
    & $unins /VERYSILENT
    $deadline = (Get-Date).AddSeconds(180)
    while ((Test-Path -LiteralPath $unins) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    Write-Host ("   uninstaller ran; {0} {1}" -f $unins, $(if (Test-Path -LiteralPath $unins) { 'STILL PRESENT - it did not finish in 180s' } else { 'gone' }))
    if (Test-Path -LiteralPath $unins) { Fail "the uninstaller did not finish - was its elevation prompt declined?" }
} else {
    Write-Host "   nothing to uninstall ($unins absent)"
}

# ---------------------------------------------------------------------------
# STEP 6 - DELETE THE SOLO TREE.  Owner, 26 Sep 2026: the real tree, every
# cycle.  The uninstaller keeps sdsys, user_accounts and sd.conf on purpose, so
# without this the next install is an UPGRADE of whatever tree came first.
Step 6 "Deleting $SoloRoot"
if (Test-Path -LiteralPath $SoloRoot) {
    Remove-Item -LiteralPath $SoloRoot -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path -LiteralPath $SoloRoot) {
    Fail "could not delete $SoloRoot - something still has a handle on it.  Close any SD session or Explorer window and run this again."
}
Write-Host "   $SoloRoot gone"

# ---------------------------------------------------------------------------
# STEP 7 - INSTALL.  No silent switch: the wizard runs and you answer it
# (account, admin and account passwords; the optional tasks).  Start-Process
# -Wait, because the call operator does not wait for a GUI-subsystem program.
# The TREE decides, not Setup's exit: wait until the installed counts reach
# the staged ones, then until they stop moving.
Step 7 "Installing - answer the wizard"
Start-Process -FilePath $setup.FullName -Wait
$igcat = Join-Path $SoloRoot 'sdsys\gcat'
$iout  = Join-Path $SoloRoot 'sdsys\gpl.bp.out'
function Cnt($d) { if (Test-Path -LiteralPath $d) { (Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue).Count } else { 0 } }
$deadline = (Get-Date).AddSeconds(300)
while ((Get-Date) -lt $deadline) {
    if (((Cnt $igcat) -ge $nGcat) -and ((Cnt $iout) -ge $nOut)) { break }
    Start-Sleep -Seconds 1
}
$before = -1
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    $now = (Cnt $igcat) + (Cnt $iout)
    if ($now -eq $before) { break }
    $before = $now
    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------------------------
# STEP 8 - WHAT WAS INSTALLED, against the stage rather than a constant.
Step 8 "What was installed"
if (-not (Test-Path -LiteralPath $igcat)) { Fail "no $igcat after the install - it did not complete" }
$iGcat = Cnt $igcat
$iOut  = Cnt $iout
Write-Host ("   gcat {0} (staged {1})   gpl.bp.out {2} (staged {3})" -f $iGcat, $nGcat, $iOut, $nOut)
if (($iGcat -lt $nGcat) -or ($iOut -lt $nOut)) {
    Fail ("the install is SHORT of the staged tree - gcat {0}/{1}, gpl.bp.out {2}/{3}." -f $iGcat, $nGcat, $iOut, $nOut)
}
# The passwords the wizard sets (SOLO 5, 15): $ADMIN, the account's own record
# and $STORED (the DPAPI copy for one-shot commands); $GLOBAL in managed mode.
$credDir = Join-Path $SoloRoot 'sdsys\$cred'
$credNames = @()
try { $credNames = @(Get-ChildItem -LiteralPath $credDir -File -Force -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { }
Write-Host ("   credential register: {0}" -f $(if ($credNames.Count) { $credNames -join ', ' } else { 'EMPTY' }))
if ($credNames -notcontains '$ADMIN') { Write-Host '   NO $ADMIN - the admin password step did not store one.' -ForegroundColor Yellow }
if ($credNames -notcontains '$STORED') { Write-Host '   NO $STORED - a one-shot "sd <command>" will need the password on its input.' -ForegroundColor Yellow }

Write-Host ""
ReportTranscriptWholeness
Write-Host ""
& (Join-Path $Gplbld 'assert-current.ps1')
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "CYCLE COMPLETE - the install matches source.  Measure now, and stop measuring at the next source change." -ForegroundColor Green
    StopCycleTranscript
} else {
    Write-Host ""
    Write-Host "INSTALLED, BUT assert-current REFUSES - read what it listed above before believing any measurement." -ForegroundColor Yellow
    StopCycleTranscript
    exit 1
}
