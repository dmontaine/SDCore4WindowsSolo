# test-apilistener-units.ps1 - free-tier guard for SOLO 33's fix: the installer's FIRST start of SD listens on
# nothing, and the API listener is switched on only after the firewall rule exists.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = every row passes, 1 = a row failed, 2 = could not run.  No install, no VM, no elevation, no SD.
#
# WHY IT EXISTS.  Measured 6 and 7 Oct 2026 in fresh guests: Windows showed its "allow this app?" alert for sdwind
# during an install even with the "reach" box unticked, and an Allow left two sdwind.exe rules open to ANY address on
# Public.  Cause: solo-setup.ps1's unelevated "sd -start" ran with APIPORT on, before any rule.  The owner chose
# option 1 (7 Oct 2026): ship sd.conf with APIPORT commented out, make the rule in the elevated step, THEN switch the
# listener on (solo-api-listener.ps1), THEN start SD from the startup task (session 0, which cannot show an alert).
# Nothing here can SEE the alert - that needs a guest - so this holds the three things that make it not happen:
#   1. solo-api-listener.ps1 does what it says (rows 1-14, on scratch copies, round trips compared byte for byte);
#   2. the installer copies ONLY the no-listener sd.conf (row 15);
#   3. solo-machine.ps1 makes the rule and the switch BEFORE it registers the startup task (rows 16-17).
# INSTRUMENT RULES: every row's real inputs are echoed; the null case is refused (a script that does nothing fails
# the "changed" rows); and a MUTANT (the script with its active form altered) must be flagged.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $here 'solo-api-listener.ps1'
$machine = Join-Path $here 'solo-machine.ps1'
$iss = Join-Path $here 'sd-solo.iss'
$stagepy = Join-Path $here 'stage.py'
foreach ($f in @($script, $machine, $iss, $stagepy)) { if (-not (Test-Path -LiteralPath $f)) { Write-Host "NO TREE: $f missing"; exit 2 } }
Write-Host "subject  : $script"

$fail = 0
function Check([string]$label, [bool]$ok) { if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label"; $script:fail++ } }

$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$work = Join-Path $env:TEMP ('test-apilistener-' + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Run([string]$exe, [string[]]$argv) {
    $o = & $ps -NoProfile -ExecutionPolicy Bypass -File $exe @argv 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Out = (($o | ForEach-Object { "$_" }) -join "`n") }
}
function Put([string]$name, [string]$text) {
    $p = Join-Path $work $name
    [IO.File]::WriteAllText($p, $text, [Text.Encoding]::ASCII)
    return $p
}
function Hash([string]$p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
function Txt([string]$p) { return [IO.File]::ReadAllText($p, [Text.Encoding]::ASCII) }
function ActiveCount([string]$text) { return @($text -split "`r?`n" | Where-Object { $_.Trim() -ceq 'APIPORT=4249' }).Count }

$crlf = "`r`n"
$off  = 'A=1' + $crlf + '# note about the api' + $crlf + '# APIPORT=4249' + $crlf + 'B=2' + $crlf
$on   = 'A=1' + $crlf + '# note about the api' + $crlf + 'APIPORT=4249' + $crlf + 'B=2' + $crlf

# ---- 1. the file parses -----------------------------------------------------------------------------
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(($script -replace '\\', '/'), [ref]$t, [ref]$e)
Check 'solo-api-listener.ps1 parses with 0 errors' ($e.Count -eq 0)

# ---- 2. -Show on a commented file: OFF, nothing changes -----------------------------------------------
$f1 = Put 'c1.conf' $off
$h1 = Hash $f1
$r = Run $script @('-Show', '-ConfPath', $f1)
Write-Host ("  -Show c1: exit {0}" -f $r.Code)
Check '-Show on a commented line says OFF, exits 0 and changes nothing' ($r.Code -eq 0 -and $r.Out -match 'state  : OFF' -and (Hash $f1) -eq $h1)

# ---- 3. -On: exactly one active line, nothing else moved, CRLF kept ---------------------------------------
$r = Run $script @('-On', '-ConfPath', $f1)
Write-Host ("  -On c1: exit {0}" -f $r.Code)
$after = Txt $f1
Check '-On exits 0 and says ON' ($r.Code -eq 0 -and $r.Out -match 'the API listener is ON')
Check '-On leaves exactly one active APIPORT=4249 line' ((ActiveCount $after) -eq 1)
Check '-On changed ONLY that line: the file equals the expected bytes (CRLF kept)' ($after -ceq $on)

# ---- 4. -On again: already ON, byte-identical ----------------------------------------------------------
$h2 = Hash $f1
$r = Run $script @('-On', '-ConfPath', $f1)
Check '-On again says already ON and changes nothing' ($r.Code -eq 0 -and $r.Out -match 'already ON' -and (Hash $f1) -eq $h2)

# ---- 5. -Off: the round trip restores the ORIGINAL bytes -----------------------------------------------
$r = Run $script @('-Off', '-ConfPath', $f1)
Check '-Off exits 0 and the file is byte-identical to the original (round trip)' ($r.Code -eq 0 -and (Hash $f1) -eq $h1)

# ---- 6. legacy form: an earlier build's APIPORT=4243 is ON, and -On / -Off normalise it ----------------
$f2 = Put 'legacy.conf' ('A=1' + $crlf + 'APIPORT=4243' + $crlf + 'B=2' + $crlf)
$r = Run $script @('-Show', '-ConfPath', $f2)
Check 'a legacy APIPORT=4243 reads as ON and the report names port 4249' ($r.Out -match 'state  : ON' -and $r.Out -match 'listens on port 4249')
$r = Run $script @('-On', '-ConfPath', $f2)
Check '-On rewrites a legacy line to the 4249 form' ($r.Code -eq 0 -and (ActiveCount (Txt $f2)) -eq 1 -and (Txt $f2) -notmatch '4243')
$f2b = Put 'legacy2.conf' ('A=1' + $crlf + 'APIPORT=4243' + $crlf + 'B=2' + $crlf)
$r = Run $script @('-Off', '-ConfPath', $f2b)
Check '-Off on a legacy line comments it out (no active line left)' ($r.Code -eq 0 -and (ActiveCount (Txt $f2b)) -eq 0 -and (Txt $f2b) -match '(?m)^# APIPORT=4249')

# ---- 7. an LF-only file stays LF-only -----------------------------------------------------------------
$f3 = Put 'lf.conf' ("A=1`n# APIPORT=4249`nB=2`n")
$r = Run $script @('-On', '-ConfPath', $f3)
$lf = Txt $f3
Check '-On on an LF-only file keeps LF (no CR introduced) and has one active line' ($r.Code -eq 0 -and $lf -notmatch "`r" -and (ActiveCount $lf) -eq 1)

# ---- 8. neither form: -Off is already true, -On appends one ------------------------------------------
$f4 = Put 'none1.conf' ('A=1' + $crlf + 'B=2' + $crlf)
$h4 = Hash $f4
$r = Run $script @('-Off', '-ConfPath', $f4)
Check 'a file with no APIPORT line: -Off says already OFF and changes nothing' ($r.Code -eq 0 -and $r.Out -match 'already OFF' -and (Hash $f4) -eq $h4)
$r = Run $script @('-On', '-ConfPath', $f4)
$n = Txt $f4
Check 'a file with no APIPORT line: -On appends exactly one active line and keeps the rest' ($r.Code -eq 0 -and (ActiveCount $n) -eq 1 -and $n.StartsWith('A=1' + $crlf + 'B=2' + $crlf) -and $n.EndsWith($crlf))

# ---- 9. case: apiport=4249 in lower case is NOT the setting (stage.py's own check is case-sensitive) -----
$f5 = Put 'case.conf' ('apiport=4249' + $crlf + '# APIPORT=4249' + $crlf)
$r = Run $script @('-Show', '-ConfPath', $f5)
Check 'a lower-case apiport=4249 is not read as the setting' ($r.Out -match 'state  : OFF')

# ---- 10. refusals ----------------------------------------------------------------------------------------
$r = Run $script @('-On', '-ConfPath', (Join-Path $work 'does-not-exist.conf'))
Check 'a missing file is exit 2' ($r.Code -eq 2)
$r = Run $script @('-ConfPath', $f1)
Check 'no action given is exit 2' ($r.Code -eq 2)
$r = Run $script @('-On', '-Off', '-ConfPath', $f1)
Check '-On with -Off is exit 2' ($r.Code -eq 2)

# ---- 11. the REAL staged no-listener sd.conf, when a stage exists --------------------------------------
$real = Join-Path $here '..\..\..\stage\SDCoreSolo\sd-standalone.conf'
if (Test-Path -LiteralPath $real) {
    $f6 = Join-Path $work 'real.conf'
    Copy-Item -LiteralPath $real -Destination $f6
    $h6 = Hash $f6
    $a0 = ActiveCount (Txt $f6)
    $r1 = Run $script @('-On', '-ConfPath', $f6); $a1 = ActiveCount (Txt $f6)
    $r2 = Run $script @('-Off', '-ConfPath', $f6)
    Write-Host ("  real staged sd-standalone.conf: active {0} -> {1} -> {2}" -f $a0, $a1, (ActiveCount (Txt $f6)))
    Check 'the real staged sd-standalone.conf has no active APIPORT, -On makes one, -Off restores it byte for byte' ($a0 -eq 0 -and $r1.Code -eq 0 -and $a1 -eq 1 -and $r2.Code -eq 0 -and (Hash $f6) -eq $h6)
} else { Write-Host '  (no stage: the real-file row is skipped)' }

# ---- 12. MUTANT: a script whose active form is altered must be flagged --------------------------------
$mut = Join-Path $work 'mutant.ps1'
$src = [IO.File]::ReadAllText($script)
$mutText = $src.Replace("`$ACTIVE    = 'APIPORT=4249'", "`$ACTIVE    = 'APIPORT=4250'")
Check 'CONTROL: the mutation changed the script text' ($mutText -ne $src)
[IO.File]::WriteAllText($mut, $mutText)
$fm = Put 'mut.conf' $off
$rm = Run $mut @('-On', '-ConfPath', $fm)
Check 'MUTANT: with a wrong active form, "-On" does not give one active APIPORT=4249 line (the checks above would fail)' ((ActiveCount (Txt $fm)) -ne 1 -or $rm.Code -ne 0)

# ---- 13. the installer copies ONLY the no-listener sd.conf --------------------------------------------
$issCode = (([IO.File]::ReadAllLines($iss) | Where-Object { $_ -notmatch '^\s*;' }) -join "`n")
$filesSd = [regex]::Matches($issCode, '(?m)^Source:\s*"[^"]*\\sd(-standalone)?\.conf"[^\n]*(\\\r?\n[^\n]*)?')
$names = @($filesSd | ForEach-Object { $_.Value })
Write-Host ("  sd.conf [Files] entries: {0}" -f $names.Count)
Check 'the installer has exactly one [Files] entry for sd.conf, and it is the no-listener sd-standalone.conf with no Check on the API box' (
    $names.Count -eq 1 -and $names[0] -match 'sd-standalone\.conf' -and $names[0] -notmatch 'ApiWanted')

# ---- 14. solo-machine.ps1: rule, then listener switch, THEN the startup task -----------------------------
$mt = ([IO.File]::ReadAllLines($machine) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
$tryAt = $mt.IndexOf("`ntry {")
$iRule = $mt.IndexOf("Invoke-Shipped 'api-firewall.ps1' @('-Restrict')", $tryAt)
$iSwitch = $mt.IndexOf("Invoke-Shipped 'solo-api-listener.ps1'", $tryAt)
$regCall = [regex]::Match($mt.Substring($tryAt), '(?m)^\s+Register-SoloTask\s*$')
$iTask = if ($regCall.Success) { $tryAt + $regCall.Index } else { -1 }
Write-Host ("  positions in the main flow: rule {0}, listener switch {1}, Register-SoloTask {2}" -f $iRule, $iSwitch, $iTask)
Check 'solo-machine.ps1 makes the firewall rule, then switches the listener, and only then registers the startup task' ($iRule -gt 0 -and $iSwitch -gt $iRule -and $iTask -gt $iSwitch)
Check 'the listener switch follows the API box: -On with -Api, -Off without' ($mt -match "solo-api-listener\.ps1'\s+@\(\`$\(if \(\`$Api\) \{ '-On' \} else \{ '-Off' \}\)\)")

# ---- 15. the script ships --------------------------------------------------------------------------------
$sp = [IO.File]::ReadAllText($stagepy)
Check "stage.py's ship list names solo-api-listener.ps1" ($sp -match "'solo-api-listener\.ps1'")

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -gt 0) { Write-Host "test-apilistener-units: FAILED - $fail row(s)"; exit 1 }
Write-Host 'test-apilistener-units: PASSED'
exit 0
