# test-sshguard-units.ps1 - free-tier guard for solo-sshguard.ps1, the per-address ssh lock-out in front of Solo's
# sshd (from Linux Solo's test-sshguard-units.py, LSOLO 29; carried 17 Nov 2026, four-version audit decision D1).
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = every row passed and every mutant went red, 1 = a row failed or a mutant stayed green, 2 = could not run.
#
# WHAT IT MEASURES, on RECORDED sshd log lines (no sshd, no firewall, no elevation, no network):
#   RULE rows   - the counting rule, loaded out of the script's "sshguard_logic" region (nothing re-typed): two wrong
#                 passwords do not lock, the third does; another address is not affected; a failed KEY never counts
#                 (and is not taken for a sign-in); a sign-in forgets; failures older than the window and a lock older
#                 than its length are forgotten; an "invalid user" password failure counts; the address is the LAST
#                 "from <addr> port <n> ssh2" (a user name cannot choose it); a line whose message does not start the
#                 line is not counted; a name that is not an address is ignored; ::ffff: is folded; the state file
#                 round-trips; the log reader keeps an incomplete line for later and a first run of the task starts at
#                 the end.
#   SCRIPT rows - the real script in a child process with -TestDir (its test hook: one pass, a scratch folder, the
#                 clock from SDSOLO_TEST_NOW, and the firewall and processes replaced by RULES= / CUT= lines): the third
#                 failure prints CUT and the rule, -List names the address and ends "SOLO SSH GUARD LOCKED 1", -Unlock
#                 ends "UNLOCKED 1" and the rule goes, the lock lifts by itself, a bad address and no switch are refused.
#   MUTANTS     - each copy of the logic region below must turn at least one RULE row red (never locks, records
#                 nothing, key failures counted, a sign-in not forgetting, the window ignored, the lock never ending,
#                 four tries, the FIRST address taken, an unanchored message).  A mutant whose target is not found
#                 exactly once stops the run (exit 2): it would test nothing.
# NOT MEASURED HERE: the real sshd's -E line prefix, the firewall rule refusing a connection, the child being ended.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'solo-sshguard.ps1'
if (-not (Test-Path -LiteralPath $src)) { Write-Host "NO TREE: $src missing"; exit 2 }
Write-Host "guard under test: $src"
$text = [IO.File]::ReadAllText($src)
$m = [regex]::Match($text, '(?s)# BEGIN sshguard_logic[^\n]*\n(.*?)# END sshguard_logic')
if (-not $m.Success) { Write-Host 'CANNOT RUN: no "# BEGIN sshguard_logic ... # END sshguard_logic" region in the script'; exit 2 }
$region = $m.Groups[1].Value

$t = $null; $e = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$t, [ref]$e)

# A recorded line, in the form Windows' sshd is expected to write with -E (pid, date, time; NOT MEASURED - see the
# script's header) and, for one row, with no prefix at all.
function L([string]$msg) { return '4120 2026-11-17 10:00:00.123 ' + $msg }

# The RULE rows: run against one loaded copy of the logic; returns the labels of the rows that failed, and prints
# every row when $verbose.
$ruleRows = {
    param([string]$code, [bool]$verbose, [string]$scratch)
    . ([scriptblock]::Create($code))
    $bad = New-Object System.Collections.ArrayList
    $counter = @{ n = 0 }
    function Row([string]$label, [bool]$ok, [string]$seen) {
        $counter.n++
        if ($verbose) { Write-Host ($(if ($ok) { 'PASS  ' } else { 'FAIL  ' }) + $label + '   [' + $seen + ']') }
        if (-not $ok) { [void]$bad.Add($label) }
    }
    function Feed($st, [string[]]$lines, [long]$now) { $r = @(); foreach ($l in $lines) { $r += (Add-Event $st (Get-LineEvent $l) $now) }; return ($r -join ',') }
    function Lk($st, [long]$now) { return ((Get-LockedAddrs $st $now) -join ',') }
    $A = '192.0.2.7'; $B = '198.51.100.9'
    $fA = L ('Failed password for don from ' + $A + ' port 50101 ssh2')
    $fB = L ('Failed password for don from ' + $B + ' port 50102 ssh2')

    $st = New-State
    $r = Feed $st @($fA, $fA) 1000
    Row 'two wrong passwords from one address do not lock it' ((Lk $st 1001) -eq '' -and $r -eq 'COUNT,COUNT') ('events ' + $r + ', locked [' + (Lk $st 1001) + ']')
    $r = Feed $st @($fA) 1020
    Row 'the third within ten minutes LOCKS that address' ((Lk $st 1021) -eq $A -and $r -eq 'LOCK') ('event ' + $r + ', locked [' + (Lk $st 1021) + ']')
    $r = Feed $st @($fB) 1030
    Row 'another address is not affected by the lock (one failure, not locked)' ((Lk $st 1031) -eq $A -and $r -eq 'COUNT' -and $st.Addrs[$B].Fails.Count -eq 1) ('locked [' + (Lk $st 1031) + ']')
    Row 'the lock still holds at 599 s' ((Lk $st 1619) -eq $A) ('locked at 1619 [' + (Lk $st 1619) + ']')
    Limit-State $st 1620
    Row 'the lock ends after ten minutes and the address is forgotten' ((Lk $st 1620) -eq '' -and -not $st.Addrs.ContainsKey($A)) ('locked at 1620 [' + (Lk $st 1620) + '], known: ' + (@($st.Addrs.Keys) -join ','))

    $st = New-State
    $kA = L ('Failed publickey for don from ' + $A + ' port 50103 ssh2')
    $r = Feed $st @($kA, $kA, $kA, $kA, $kA) 2000
    Row 'five failed KEYS from one address count for nothing' ($st.Addrs.Count -eq 0 -and (Lk $st 2001) -eq '') ('events ' + $r + ', addresses known ' + $st.Addrs.Count)
    $r = Feed $st @($fA, $fA, $kA, $fA) 2010
    Row 'a failed key between wrong passwords is not a sign-in: the third password still locks' ((Lk $st 2011) -eq $A) ('events ' + $r + ', locked [' + (Lk $st 2011) + ']')

    $st = New-State
    $r = Feed $st @($fA, $fA, (L ('Accepted password for don from ' + $A + ' port 50104 ssh2')), $fA) 3000
    Row 'a sign-in (password) forgets the failures: two, a sign-in, one more = not locked' ((Lk $st 3001) -eq '' -and $st.Addrs[$A].Fails.Count -eq 1) ('events ' + $r)
    $st = New-State
    $r = Feed $st @($fA, $fA, (L ('Accepted publickey for don from ' + $A + ' port 50105 ssh2: ED25519 SHA256:q1w2e3')), $fA) 3100
    Row 'a sign-in by key (sshd adds ": <type> <fingerprint>" after ssh2) forgets the failures' ((Lk $st 3101) -eq '' -and $st.Addrs[$A].Fails.Count -eq 1) ('events ' + $r)

    $st = New-State
    $null = Feed $st @($fA) 4000; $null = Feed $st @($fA) 4300; $r = Feed $st @($fA) 4700
    Row 'three failures spread over more than ten minutes do not lock (the oldest has left the window)' ((Lk $st 4701) -eq '' -and $st.Addrs[$A].Fails.Count -eq 2) ('last event ' + $r + ', failures kept ' + $st.Addrs[$A].Fails.Count)

    $st = New-State
    $iu = L ('Failed password for invalid user root from ' + $A + ' port 50106 ssh2')
    $r = Feed $st @($iu, $iu, $iu) 5000
    Row 'a wrong password for a user who does not exist counts too (as on Linux)' ((Lk $st 5001) -eq $A) ('events ' + $r)

    $st = New-State
    # The name ends ": " so that a reader taking the FIRST address could treat the rest as a key sign-in's suffix.
    $inj = L ('Failed password for invalid user x from 10.9.9.9 port 1 ssh2: from ' + $B + ' port 50107 ssh2')
    $ev = Get-LineEvent $inj
    Row 'the address is the LAST "from ... port ... ssh2" on the line, the one sshd appends - not one in a user name' ($null -ne $ev -and $ev.Addr -eq $B) ('addr ' + $(if ($ev) { $ev.Addr } else { 'none' }))
    $ev2 = Get-LineEvent (L 'Connection closed by authenticating user Failed password for a from 10.9.9.9 port 1 ssh2')
    $ev3 = Get-LineEvent (L 'Invalid user Accepted password for a from 10.9.9.9 port 1 ssh2')
    Row 'a line whose message does not START after the prefix is not counted (a user name holding the words)' ($null -eq $ev2 -and $null -eq $ev3) ('events ' + [string]$ev2 + '/' + [string]$ev3)
    $ev4 = Get-LineEvent ('Failed password for don from ' + $A + ' port 50108 ssh2')
    $ev5 = Get-LineEvent ('sshd-session.exe: Failed password for don from ' + $A + ' port 50108 ssh2')
    Row 'a line with no prefix, and one with an "sshd...:" tag, are read' ($null -ne $ev4 -and $ev4.Kind -eq 'fail' -and $null -ne $ev5 -and $ev5.Addr -eq $A) 'two forms'
    $ev6 = Get-LineEvent (L 'Failed password for don from evil.example port 50109 ssh2')
    $ev7 = Get-LineEvent (L 'Failed password for don from ::ffff:192.0.2.7 port 50110 ssh2')
    $ev8 = Get-LineEvent (L 'Failed password for don from 2001:db8::5 port 50111 ssh2')
    Row 'a name that is not an address is ignored; ::ffff:192.0.2.7 is 192.0.2.7; an IPv6 address is read' ($null -eq $ev6 -and $ev7.Addr -eq $A -and $ev8.Addr -eq '2001:db8::5') ([string]$ev7.Addr + ' ' + [string]$ev8.Addr)
    Row 'the IPv6 lock rule''s name has no colon in it' ((Get-RuleName '2001:db8::5') -eq 'SD-Solo-SSH-Guard-2001-db8--5') (Get-RuleName '2001:db8::5')

    $sp = Join-Path $scratch 'rt.state'
    $st = New-State; $st.Offset = 1234
    $null = Feed $st @($fA, $fA, $fA, $fB) 6000
    Write-State $st $sp 6001
    $back = Read-State $sp
    Row 'the state file round-trips: the offset, the lock and its end, the other address''s failure' ($back.Offset -eq 1234 -and (Lk $back 6002) -eq $A -and $back.Addrs[$A].Until -eq 6600 -and $back.Addrs[$B].Fails.Count -eq 1) ((Get-Content $sp) -join ' | ')

    $lp = Join-Path $scratch 'r.log'
    [IO.File]::WriteAllText($lp, ($fA + "`r`n" + $fA + "`r`n" + 'Failed passw'))
    $st = New-State
    $got = @(Read-NewLines $st $lp $false)
    Row 'the log reader returns the complete lines and keeps the incomplete one for the next pass' ($got.Count -eq 2 -and $st.Offset -eq ($fA.Length * 2 + 4)) ('lines ' + $got.Count + ', offset ' + $st.Offset)
    [IO.File]::AppendAllText($lp, ('ord for don from ' + $A + ' port 1 ssh2' + "`r`n"))
    $got = @(Read-NewLines $st $lp $false)
    Row 'the incomplete line is read whole once it is finished' ($got.Count -eq 1 -and $null -ne (Get-LineEvent $got[0])) ('lines ' + $got.Count)
    $st = New-State
    $got = @(Read-NewLines $st $lp $true)
    Row 'the task''s first pass starts at the END of the log (old failures are not counted again)' ($got.Count -eq 0 -and $st.Offset -eq (Get-Item $lp).Length) ('lines ' + $got.Count + ', offset ' + $st.Offset)

    return [pscustomobject]@{ Bad = @($bad); Count = $counter.n }
}

$scratch = Join-Path $env:TEMP ('sdsshguard-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $scratch | Out-Null
$fail = 0
function Check([string]$label, [bool]$ok, [string]$seen) {
    if ($ok) { Write-Host "PASS  $label   [$seen]" } else { Write-Host "FAIL  $label   [$seen]"; $script:fail++ }
}
Check 'solo-sshguard.ps1 parses with 0 errors' ($e.Count -eq 0) ('errors ' + $e.Count)

Write-Host '--- RULE rows (the logic region of the real script)'
$res = & $ruleRows $region $true $scratch
if ($res.Count -eq 0) { Write-Host 'REFUSED: the null case - no RULE rows ran'; Remove-Item $scratch -Recurse -Force; exit 2 }
$fail += $res.Bad.Count
Write-Host ('RULE rows: ' + $res.Count + ' run, ' + $res.Bad.Count + ' failed')

# ---- SCRIPT rows: the real file, in a child process, with its test hook ------------------------------------------
Write-Host '--- SCRIPT rows (the real script, -TestDir, clock from SDSOLO_TEST_NOW)'
$td = Join-Path $scratch 'machine'
New-Item -ItemType Directory -Path $td | Out-Null
$log = Join-Path $td 'sshd.log'
$saveNow = $env:SDSOLO_TEST_NOW
function Run-Guard([long]$now, [string[]]$a) {
    $env:SDSOLO_TEST_NOW = [string]$now
    $o = & powershell -NoProfile -ExecutionPolicy Bypass -File $src @a -TestDir $td 2>&1 | Out-String
    $script:lastCode = $LASTEXITCODE
    Write-Host ('  $ solo-sshguard.ps1 ' + ($a -join ' ') + ' -TestDir <scratch>  (now ' + $now + ', exit ' + $script:lastCode + ')')
    foreach ($x in ($o.Trim() -split "`r?`n")) { Write-Host ('  | ' + $x) }
    return $o
}
$X = '203.0.113.5'
$fx = L ('Failed password for don from ' + $X + ' port 40001 ssh2')
[IO.File]::WriteAllText($log, ($fx + "`r`n" + $fx + "`r`n"))
$o = Run-Guard 10000 @('-Serve')
Check 'two wrong passwords: no rule, nothing cut' ($script:lastCode -eq 0 -and $o -match '(?m)^RULES=\s*$' -and $o -notmatch 'CUT=') 'RULES= empty'
[IO.File]::AppendAllText($log, ($fx + "`r`n"))
$o = Run-Guard 10010 @('-Serve')
Check 'the third: the connection is cut and the block rule is wanted for that address' ($o -match ('(?m)^CUT=' + [regex]::Escape($X) + '\s*$') -and $o -match ('(?m)^RULES=' + [regex]::Escape($X) + '\s*$') -and $o -match 'locking 203\.0\.113\.5 for 10 minutes') 'CUT= and RULES='
$o = Run-Guard 10020 @('-Serve')
Check 'a pass with no new lines reads nothing again (the offset held) and keeps the rule' ($o -notmatch 'CUT=' -and $o -match ('(?m)^RULES=' + [regex]::Escape($X))) 'no CUT, RULES kept'
$o = Run-Guard 10030 @('-List')
Check '-List names the address as LOCKED and ends "SOLO SSH GUARD LOCKED 1"' ($o -match ([regex]::Escape($X) + '  LOCKED until ') -and $o -match '(?m)^SOLO SSH GUARD LOCKED 1\s*$') 'LOCKED 1'
$o = Run-Guard 10040 @('-Unlock', 'not-an-address')
Check '-Unlock refuses something that is not an address (ERROR=, exit 1)' ($script:lastCode -eq 1 -and $o -match 'ERROR=not an address') 'refused'
$o = Run-Guard 10050 @('-Unlock', $X)
Check '-Unlock <address> ends "SOLO SSH GUARD UNLOCKED 1" and no rule is wanted' ($script:lastCode -eq 0 -and $o -match '(?m)^SOLO SSH GUARD UNLOCKED 1\s*$' -and $o -match '(?m)^RULES=\s*$') 'UNLOCKED 1'
$o = Run-Guard 10060 @('-List')
Check 'after it, -List ends "SOLO SSH GUARD LOCKED 0"' ($o -match '(?m)^SOLO SSH GUARD LOCKED 0\s*$') 'LOCKED 0'
[IO.File]::AppendAllText($log, ($fx + "`r`n" + $fx + "`r`n" + $fx + "`r`n"))
$null = Run-Guard 20000 @('-Serve')
$o = Run-Guard 20599 @('-Serve')
Check 'locked again; still locked at 599 s' ($o -match ('(?m)^RULES=' + [regex]::Escape($X))) 'RULES kept'
$o = Run-Guard 20600 @('-Serve')
Check 'at ten minutes the lock lifts by itself: no rule is wanted' ($o -match '(?m)^RULES=\s*$') 'RULES= empty'
$o = Run-Guard 20610 @('-List')
Check 'and -List shows nothing locked' ($o -match '(?m)^SOLO SSH GUARD LOCKED 0\s*$') 'LOCKED 0'
$o = Run-Guard 20620 @()
Check 'no switch is refused (ERROR=, exit 1)' ($script:lastCode -eq 1 -and $o -match 'ERROR=give exactly one') 'refused'
$env:SDSOLO_TEST_NOW = $saveNow

# ---- MUTANTS -------------------------------------------------------------------------------------------------------
Write-Host '--- MUTANTS (each must turn a RULE row red)'
$mutants = @(
    @('never locks',              'if ($e.Fails.Count -ge $MaxFails)', 'if ($false)'),
    @('records nothing',          '$e.Fails = @(@($e.Fails | Where-Object { ($now - $_) -lt $Window }) + $now)', '$e.Fails = @()'),
    @('key failures counted',     '(Failed password|Accepted \S+)', '(Failed \S+|Accepted \S+)'),
    @('sign-in does not forget',  'if ($st.Addrs.ContainsKey($ev.Addr)) { $st.Addrs.Remove($ev.Addr) }', '$null = 0'),
    @('window ignored',           '$Window = 600 ', '$Window = 1000000000 '),
    @('lock never ends',          '$LockFor = 600 ', '$LockFor = 1000000000 '),
    @('four tries, not three',    '$MaxFails = 3 ', '$MaxFails = 4 '),
    @('the FIRST address taken',  ' for .* from (\S+) port', ' for .*? from (\S+) port'),
    @('message not anchored',     '''^[0-9 :./T+-]*', '''^.*?'),
    @('first pass from the start','$(if ($fromEnd) { $len } else { 0 })', '0')
)
$green = 0
foreach ($mu in $mutants) {
    $n = ([regex]::Matches($region, [regex]::Escape($mu[1]))).Count
    if ($n -ne 1) { Write-Host ("CANNOT RUN: mutant '" + $mu[0] + "' expects its target once in the logic region, found " + $n); Remove-Item $scratch -Recurse -Force; exit 2 }
    $mr = & $ruleRows ($region.Replace($mu[1], $mu[2])) $false $scratch
    $red = $mr.Bad.Count -gt 0
    if (-not $red) { $green++ }
    Write-Host ("  mutant '" + $mu[0] + "': " + $(if ($red) { 'RED as it must be (' + $mr.Bad.Count + ' rows: ' + ($mr.Bad[0]) + ')' } else { 'STILL GREEN - the rows miss it' }))
}
Check ('every mutant went red (' + ($mutants.Count - $green) + ' of ' + $mutants.Count + ')') ($green -eq 0) ('green ' + $green)

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'sshguard units: ALL PASS'; exit 0 }
Write-Host "sshguard units: $fail FAILED"; exit 1
