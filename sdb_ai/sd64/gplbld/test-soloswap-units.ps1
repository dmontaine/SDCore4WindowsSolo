# test-soloswap-units.ps1 - drive solo-restore-swap.ps1, its rules and whole runs.
#
#   powershell -ExecutionPolicy Bypass -File C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\test-soloswap-units.ps1
#
# ORDINARY UNELEVATED PROMPT.  No install, no SD, no elevation.  Exit 0 all
# passed, 1 something failed, 2 could not set up.  Everything it makes is under
# %TEMP%\test-soloswap-<pid> and is removed at the end.
#
# WHY IT EXISTS.  SOLO 25: the swap replaces the one account's data before SD
# starts, with nobody watching (the startup task at boot).  The marker rules are
# lifted from the file by AST and driven directly; the whole script is then RUN,
# with the real sd-account-archive.ps1 beside it in a scratch install folder, for
# each outcome - applied, nothing pending, put back after a failure, and waiting
# while another SD process runs.  And the trap that would have shipped: the
# sd.exe that runs the swap leaves a forked stub alive under the install folder,
# so the swap is run FROM a process under the folder and must not wait for it.
#
# NOT SHIPPED - assert-current exempts test-* scripts by name.

$ErrorActionPreference = 'Stop'

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$subject = Join-Path $here 'solo-restore-swap.ps1'
$archive = Join-Path $here 'sd-account-archive.ps1'

Write-Host "test-soloswap-units: subject $subject"
foreach ($f in @($subject, $archive)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Host "test-soloswap-units: $f not found."; exit 2 }
}

$tok = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($subject, [ref]$tok, [ref]$errs)
if ($errs.Count -gt 0) { Write-Host "test-soloswap-units: subject has $($errs.Count) parse error(s)."; exit 2 }
$wanted = @('Read-RestoreMarker', 'Get-StagingRoot')
$lifted = 0
foreach ($name in $wanted) {
    $fn = @($ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name
    }, $true))
    if ($fn.Count -ne 1) { Write-Host "test-soloswap-units: expected exactly one $name, found $($fn.Count)."; exit 2 }
    . ([scriptblock]::Create($fn[0].Extent.Text))
    $lifted++
}
if ($lifted -ne $wanted.Count) { Write-Host 'test-soloswap-units: VOID - not every function was lifted.'; exit 2 }
Write-Host "  lifted $lifted functions"

$script:pass = 0
$script:fail = 0
function Check([string]$what, [bool]$ok, [string]$detail = '') {
    if ($ok) { $script:pass++; Write-Host "  [PASS] $what" }
    else     { $script:fail++; Write-Host "  [FAIL] $what $detail" }
}
function Throws([scriptblock]$sb, [string]$like) {
    try { & $sb; return 'no exception' } catch {
        if ($_.Exception.Message -like $like) { return '' }
        return "wrong exception: $($_.Exception.Message)"
    }
}

$work = Join-Path $env:TEMP ("test-soloswap-" + $PID)
$pinger = $null
try {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    $root = Join-Path $work 'SDCoreSolo'
    [void][System.IO.Directory]::CreateDirectory($root)
    Copy-Item -LiteralPath $subject -Destination $root
    Copy-Item -LiteralPath $archive -Destination $root
    Write-Host "  scratch install folder $root"

    $target = Join-Path $root 'user_accounts\sduser'
    function New-Pending([string]$n, [string]$tag) {
        foreach ($d in @("$target\voc", "$root\.sdrestore.$n\accounts\sduser\voc", "$root\.sdrestore.$n\accounts\sduser\bp")) {
            [void][System.IO.Directory]::CreateDirectory($d)
        }
        [System.IO.File]::WriteAllText("$root\.sdrestore.$n\accounts\sduser\bp\$tag", "$tag`n")
        [System.IO.File]::WriteAllText("$root\.sdrestore.$n\manifest.txt", "format: 1`n")
        $lines = @('format: 1', "$root\.sdrestore.$n\accounts\sduser", $target, 'sduser',
                   '2026-10-02 10:00:00', "C:\backups\SD-host-sduser-$tag.zip")
        [System.IO.File]::WriteAllText("$root\.sdrestore.pending", (($lines -join "`n") + "`n"))
    }
    # 'Continue' around the native call: under 'Stop' a child's stderr line
    # becomes a terminating error here and the outcome is never read.
    function Run-Swap([string]$exe = 'powershell.exe') {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = @(& $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\solo-restore-swap.ps1" -Root $root 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        return [pscustomobject]@{ Code = $code; Last = ($out | Select-Object -Last 1); All = $out }
    }

    # --- 1. marker rules ------------------------------------------------------
    Write-Host ''
    Write-Host '1. marker rules'
    $good = @('format: 1', "$root\.sdrestore.3\accounts\sduser", $target, 'sduser', 'x', 'y.zip')
    $m = Read-RestoreMarker $good $root
    Check 'a good marker is read' ($m.Account -eq 'sduser' -and $m.StagingRoot -eq "$root\.sdrestore.3")
    Check 'forward slashes are accepted' ((Read-RestoreMarker @('format: 1', ("$root\.sdrestore.3\accounts\sduser" -replace '\\', '/'), ($target -replace '\\', '/'), 'sduser', 'x', 'y') $root).Target -eq $target)
    $bad = @(
        @{ Why = 'five lines';          L = @('format: 1', 'a', 'b', 'c', 'd');                                                       Like = '*not 6*' },
        @{ Why = 'another format';      L = @('format: 2') + $good[1..5];                                                              Like = '*unknown marker format*' },
        @{ Why = 'a relative path';     L = @('format: 1', '.sdrestore.3\accounts\sduser') + $good[2..5];                              Like = '*not a full path*' },
        @{ Why = 'a target elsewhere';  L = @('format: 1', $good[1], 'C:\Windows', 'sduser', 'x', 'y');                                Like = '*not an account directory*' },
        @{ Why = 'a nested target';     L = @('format: 1', $good[1], "$target\bp", 'sduser', 'x', 'y');                                Like = '*not an account directory*' },
        @{ Why = 'staged elsewhere';    L = @('format: 1', "$root\elsewhere\accounts\sduser", $target, 'sduser', 'x', 'y');            Like = '*staged tree is not under*' },
        @{ Why = 'no account name';     L = @('format: 1', $good[1], $target, ' ', 'x', 'y');                                          Like = '*names no account*' }
    )
    foreach ($b in $bad) {
        $r = Throws { Read-RestoreMarker $b.L $root } $b.Like
        Check "refused: $($b.Why)" ($r -eq '') $r
    }

    # --- 2. a whole run that applies ------------------------------------------
    Write-Host ''
    Write-Host '2. applied'
    [void][System.IO.Directory]::CreateDirectory("$target\voc")
    [System.IO.File]::WriteAllText("$target\old.txt", "old`n")
    New-Pending '5' 'new1'
    $r = Run-Swap
    Check "exit 0 and APPLIED ($($r.Code): $($r.Last))" ($r.Code -eq 0 -and $r.Last -like 'SOLO-RESTORE APPLIED sduser from *new1.zip')
    Check 'the new contents are in the account' (Test-Path -LiteralPath "$target\bp\new1")
    Check 'the old contents are gone from it' (-not (Test-Path -LiteralPath "$target\old.txt"))
    Check 'the old contents are kept in .sdrestore.previous' (Test-Path -LiteralPath "$root\.sdrestore.previous\old.txt")
    Check 'the marker is deleted' (-not (Test-Path -LiteralPath "$root\.sdrestore.pending"))
    Check 'the staging directory is removed' (-not (Test-Path -LiteralPath "$root\.sdrestore.5"))
    Check 'the log says what happened' ((Get-Content -LiteralPath "$root\sdrestore.log" -Raw) -like '*ACC-ARCHIVE PLACE OK*SOLO-RESTORE APPLIED*')

    Write-Host ''
    Write-Host '3. nothing pending'
    $r = Run-Swap
    Check "exit 3 and NONE ($($r.Code): $($r.Last))" ($r.Code -eq 3 -and $r.Last -eq 'SOLO-RESTORE NONE')

    # --- 4. a second restore replaces .sdrestore.previous ----------------------
    Write-Host ''
    Write-Host '4. a second restore'
    New-Pending '6' 'new2'
    $r = Run-Swap
    Check "applied again ($($r.Code))" ($r.Code -eq 0)
    Check '.sdrestore.previous now holds the FIRST restore, not the original' ((Test-Path -LiteralPath "$root\.sdrestore.previous\bp\new1") -and -not (Test-Path -LiteralPath "$root\.sdrestore.previous\old.txt"))

    # --- 5. a failure puts everything back -------------------------------------
    Write-Host ''
    Write-Host '5. failure'
    New-Pending '7' 'new3'
    $lockPath = "$root\.sdrestore.7\accounts\sduser\zz-locked"
    [System.IO.File]::WriteAllText($lockPath, "z`n")
    $lock = [System.IO.File]::Open($lockPath, 'Open', 'Read', 'None')
    try { $r = Run-Swap } finally { $lock.Dispose() }
    Check "exit 1 and FAILED ($($r.Code): $($r.Last))" ($r.Code -eq 1 -and $r.Last -like 'SOLO-RESTORE FAILED*still pending')
    Check 'the account is as it was' ((Test-Path -LiteralPath "$target\bp\new2") -and -not (Test-Path -LiteralPath "$target\bp\new3"))
    Check 'the marker is kept' (Test-Path -LiteralPath "$root\.sdrestore.pending")
    Remove-Item -LiteralPath "$root\.sdrestore.pending" -Force

    # --- 6. waiting while SD runs, and not waiting for its own caller ---------
    Write-Host ''
    Write-Host '6. running processes'
    $bin = Join-Path $root 'usr\bin'
    [void][System.IO.Directory]::CreateDirectory($bin)
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\PING.EXE') -Destination (Join-Path $bin 'sdwind.exe')
    New-Pending '8' 'new4'
    $pinger = Start-Process -FilePath (Join-Path $bin 'sdwind.exe') -ArgumentList '-n', '60', '127.0.0.1' -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 500
    $r = Run-Swap
    Check "exit 2 and WAITING while a process from the install runs ($($r.Code): $($r.Last))" ($r.Code -eq 2 -and $r.Last -like 'SOLO-RESTORE WAITING*sdwind*')
    Check 'nothing was changed' ((Test-Path -LiteralPath "$target\bp\new2") -and (Test-Path -LiteralPath "$root\.sdrestore.pending"))
    Stop-Process -Id $pinger.Id -Force -ErrorAction SilentlyContinue
    $pinger = $null
    Start-Sleep -Milliseconds 300

    # The PARENT must be under the install folder and the swap its CHILD - the
    # shape start_sd() makes (the forked sd.exe stub waiting on PowerShell).  A
    # first version ran the swap IN the copy, so the copy was the swap's own
    # $PID, excluded anyway, and a mutant that dropped the ancestor walk stayed
    # green.  Now the copy launches the system's powershell.exe, which runs it.
    $stub = Join-Path $bin 'sd.exe'
    $sysPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Copy-Item -LiteralPath $sysPs -Destination $stub
    $inner = "& '$sysPs' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '$root\solo-restore-swap.ps1' -Root '$root'; exit `$LASTEXITCODE"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $all = @(& $stub -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $inner 2>&1 | ForEach-Object { "$_" })
    $r = [pscustomobject]@{ Code = $LASTEXITCODE; Last = ($all | Select-Object -Last 1); All = $all }
    $ErrorActionPreference = $prev
    if ($r.All -match 'SOLO-RESTORE') {
        Check "run FROM a process under the install folder, it does not wait for its own caller ($($r.Code): $($r.Last))" ($r.Code -eq 0 -and $r.Last -like 'SOLO-RESTORE APPLIED*new4.zip')
    } else {
        Check 'could run the swap from a copy of powershell.exe under the install folder' $false ($r.All -join ' | ')
    }
}
catch {
    Write-Host "test-soloswap-units: STOPPED - $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace
    if ($pinger) { Stop-Process -Id $pinger.Id -Force -ErrorAction SilentlyContinue }
    if ($script:fail -gt 0) { Write-Host "test-soloswap-units: FAILED - $($script:fail) failed before it stopped."; exit 1 }
    exit 2
}
finally {
    if ($pinger) { Stop-Process -Id $pinger.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 200
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:pass -eq 0) { Write-Host 'test-soloswap-units: VOID - no check ran.'; exit 2 }
if ($script:fail -gt 0) { Write-Host "test-soloswap-units: FAILED - $($script:pass) passed, $($script:fail) failed."; exit 1 }
Write-Host "test-soloswap-units: PASSED - $($script:pass) of $($script:pass) checks passed."
exit 0
