# test-solostart-units.ps1 - free-tier guard for solo-start.ps1, what the SIGN-IN startup task runs (SOLO 38).
# It loads the script's OWN functions out of the file by parsing it (nothing is re-typed) and drives
# Start-SoloSd against a STAND-IN sd-solo (a .cmd that answers -start and -stop the way the real one was
# measured to) in a scratch directory.  Test-SdRunning is replaced by a stub that reads the stand-in's state, so
# no real SD, no real sdwind and no real task is touched.  No tree, no elevation.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run.
#
# WHAT IT PROTECTS (measured on a guest, 6 Oct 2026): signing out kills sdwind and leaves the shared segment, and
# the next "sd-solo -start" refuses ("SD did not shut down cleanly ... Run sd-solo -stop") with exit 1 and a
# message on stderr - the same exit 1 that "SD is already started" gives.  The sign-in task's start was that
# refusal, reported as success, so after one sign-out SD never started again.  The helper must (1) start SD,
# (2) clear the leftover with -stop and start once more when the start failed AND no sdwind is running,
# (3) NEVER stop an SD that is running, (4) not loop, (5) leave a log.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'solo-start.ps1'
if (-not (Test-Path $src)) { Write-Host "NO TREE: $src missing"; exit 2 }

$fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label"; $script:fail++ }
}

# ---- 1. the file parses and has the functions the task relies on ---------------------------------------------
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$t, [ref]$e)
$names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
Write-Host ('functions: ' + ($names -join ', '))
Check 'solo-start.ps1 parses with 0 errors' ($e.Count -eq 0)
Check 'it defines Start-SoloSd, Invoke-SoloSd, Test-SdRunning and Write-StartLog' (($names -contains 'Start-SoloSd') -and ($names -contains 'Invoke-SoloSd') -and ($names -contains 'Test-SdRunning') -and ($names -contains 'Write-StartLog'))
$bytes = [IO.File]::ReadAllBytes($src)
$bom = 0; for ($i = 1; $i -lt $bytes.Length - 2; $i++) { if ($bytes[$i] -eq 0xEF -and $bytes[$i + 1] -eq 0xBB -and $bytes[$i + 2] -eq 0xBF) { $bom++ } }
Check 'no embedded BOM past offset 0' ($bom -eq 0)
$text = [IO.File]::ReadAllText($src)
$code = (($text -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Check 'sd-solo.exe is started HIDDEN, only its stderr is captured, and it is waited for with WaitForExit() (the process alone)' (
    $code -match 'Start-Process -FilePath \$SdExe -ArgumentList \$Arg -WindowStyle Hidden -PassThru -RedirectStandardError' -and $code -match '\$p\.WaitForExit\(\)' -and $code -match '\$null = \$p\.Handle')
Check 'it never uses Start-Process -Wait (that waits for sdwind too, so the helper never finished and the installer failed the step)' ($code -notmatch 'Start-Process[^\r\n]*-Wait')
Check 'the only place -stop is asked for is behind "failed AND no sdwind running"' (
    ([regex]::Matches($code, "'-stop'")).Count -eq 1 -and $code -match '(?s)if \(\$r\.Code -ne 0 -and -not \(Test-SdRunning\)\) \{.*?Invoke-SoloSd \$SdExe ''-stop''')

# ---- 2. drive Start-SoloSd against a stand-in -------------------------------------------------------------------
$scratch = Join-Path $env:TEMP ('sdsolostart-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $scratch | Out-Null
$stub = Join-Path $scratch 'sd-solo-stub.cmd'
# The stand-in answers like the real one did: MODE_OK starts; MODE_RUNNING says "already started" (exit 1);
# MODE_WRECK refuses until -stop has been run, then starts; MODE_BROKEN refuses always.  Every call is logged.
# (Labels and no nested parenthesised blocks: an "exit /b 1" inside nested blocks reported exit 0 here, and the
# real sd-solo.exe was measured to exit 1 for exactly this refusal.)
$stubText = @'
@echo off
set D=%SOLO_STUB_DIR%
echo %1>>"%D%\calls.txt"
if "%1"=="-stop" goto stop
if "%1"=="-start" goto start
exit /b 2
:stop
echo stopped>"%D%\stopped.flag"
exit /b 0
:start
if exist "%D%\mode_ok.flag" goto up
if exist "%D%\mode_running.flag" goto already
if exist "%D%\mode_wreck.flag" goto wreck
echo some other failure>&2
exit /b 1
:up
echo up>"%D%\running.flag"
rem  the real "sd -start" leaves sdwind running as a descendant for as long as SD is up; so does this (25 s)
start "" /b cmd /c "ping -n 26 127.0.0.1 >nul"
exit /b 0
:already
echo SD is already started - sdwind is running.>&2
exit /b 1
:wreck
if exist "%D%\stopped.flag" goto up
echo SD did not shut down cleanly: the shared segment is still here but sdwind is not running.>&2
exit /b 1
'@
[IO.File]::WriteAllText($stub, $stubText)

# Load the real functions, then replace ONLY the process check.
. ([scriptblock]::Create((($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Extent.Text }) -join "`n`n")))
function Test-SdRunning { return ((Test-Path (Join-Path $env:SOLO_STUB_DIR 'running.flag')) -or (Test-Path (Join-Path $env:SOLO_STUB_DIR 'mode_running.flag'))) }
$stubbed = (Get-Command Test-SdRunning).ScriptBlock.ToString() -match 'SOLO_STUB_DIR'
Check 'Test-SdRunning is the stand-in''s (so no real sdwind is looked at)' $stubbed

function Run-Case([string]$mode) {
    $d = Join-Path $scratch ('case-' + $mode + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Path $d | Out-Null
    [IO.File]::WriteAllText((Join-Path $d ('mode_' + $mode + '.flag')), 'x')
    $env:SOLO_STUB_DIR = $d
    $log = Join-Path $d 'solo-start.log'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rc = Start-SoloSd $stub $log
    $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $calls = if (Test-Path (Join-Path $d 'calls.txt')) { @(Get-Content (Join-Path $d 'calls.txt') | ForEach-Object { $_.Trim() }) } else { @() }
    $logText = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
    Write-Host ('--- ' + $mode + ': rc ' + $rc + ' in ' + $secs + ' s  calls: ' + ($calls -join ' ') + '  log lines: ' + @(Get-Content $log).Count)
    return [pscustomobject]@{ Rc = $rc; Calls = $calls; Log = $logText; Secs = $secs }
}

$a = Run-Case 'ok'
Check 'a clean start: -start only, exit 0, and no -stop' ($a.Rc -eq 0 -and ($a.Calls -join ',') -eq '-start')
$b = Run-Case 'wreck'
Check 'WRECKAGE (the measured sign-out case): -start refused, then -stop, then -start again - and SD ends up running (exit 0)' ($b.Rc -eq 0 -and ($b.Calls -join ',') -eq '-start,-stop,-start')
Check 'wreckage: the log names the refusal ("did not shut down cleanly"), the clearing, and the result' (
    $b.Log -match 'did not shut down cleanly' -and $b.Log -match 'clearing with sd-solo -stop' -and $b.Log -match 'result: sdwind running = True')
# THE ROW THAT WOULD HAVE CAUGHT THE FIRST VERSION: a successful start leaves a 25-second descendant (as sdwind is),
# and the helper must come back long before it ends.  With Start-Process -Wait it took the full 25 s and the
# installer, seeing the task still "Running", failed the step although SD was up.
Check ('a successful start does not wait for what it started: the clean case took ' + $a.Secs + ' s and the wreckage case ' + $b.Secs + ' s (a 25 s descendant was left running)') ($a.Secs -lt 12 -and $b.Secs -lt 12)
$c = Run-Case 'running'
Check 'SD ALREADY RUNNING: -start says "already started" (exit 1), and it is NOT stopped - one call, exit 0' ($c.Rc -eq 0 -and ($c.Calls -join ',') -eq '-start' -and $c.Log -match 'already started')
$d2 = Run-Case 'broken'
Check 'a start that always fails: -start, -stop, -start ONCE more and then it gives up (exit 1), no loop' ($d2.Rc -eq 1 -and ($d2.Calls -join ',') -eq '-start,-stop,-start' -and $d2.Log -match 'result: sdwind running = False')
$env:SOLO_STUB_DIR = $null

# ---- 3. a missing sd-solo.exe is reported, not run ---------------------------------------------------------------
$log3 = Join-Path $scratch 'missing.log'
$rc3 = Start-SoloSd (Join-Path $scratch 'nope.exe') $log3
Check 'no sd-solo.exe: exit 1 and the log says nothing was started' ($rc3 -eq 1 -and (Get-Content $log3 -Raw) -match 'nothing started')

# ---- 4. the log trims itself ---------------------------------------------------------------------------------
$log4 = Join-Path $scratch 'big.log'
[IO.File]::WriteAllText($log4, ('x' * 100 + "`r`n") * 800)
Write-StartLog $log4 'one more line'
$n4 = @(Get-Content $log4).Count
Check 'a log over 64 KB is cut to its last 200 lines before the new line is added' ($n4 -le 202 -and (Get-Content $log4 -Tail 1) -match 'one more line')

# ---- 5. it ships, and the machine script runs it ---------------------------------------------------------------
$stage = [IO.File]::ReadAllText((Join-Path $here 'stage.py'))
Check 'stage.py ships solo-start.ps1' ($stage -match "'solo-start\.ps1'")
$machine = [IO.File]::ReadAllText((Join-Path $here 'solo-machine.ps1'))
Check 'solo-machine.ps1''s sign-in task runs solo-start.ps1 with -File' ($machine -match "solo-start\.ps1'" -and $machine -match '-ExecutionPolicy Bypass -File "')

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-start units: ALL PASS'; exit 0 }
Write-Host "solo-start units: $fail FAILED"; exit 1
