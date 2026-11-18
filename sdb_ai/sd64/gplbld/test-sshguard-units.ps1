# test-sshguard-units.ps1 - free-tier guard for solo-sshguard.ps1, the per-address ssh lock-out in front of Solo's
# sshd (from Linux Solo's test-sshguard-units.py, LSOLO 29; carried 17 Nov 2026, four-version audit decision D1;
# 17 Nov 2026, SOLO 77: the source is the OpenSSH/Operational event channel, not sshd's -E log).
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = every row passed and every mutant went red, 1 = a row failed or a mutant stayed green, 2 = could not run.
#
# WHAT IT MEASURES (no sshd, no firewall, no elevation, no network):
#   RULE rows   - the logic, loaded out of the script's "sshguard_logic" region (nothing re-typed), on RECORDED channel
#                 records (record number, pid, sshd's message): two wrong passwords do not lock, the third does; another
#                 address is not affected; a failed KEY never counts (and is not a sign-in); a sign-in forgets; the
#                 window and the lock end; an "invalid user" failure counts.  ATTRIBUTION: a failure counts only from
#                 a pid that wrote "Connection from ... on ... port 4251" (the port-22 sshd's records, with no such line
#                 or with port 22, count for nothing; a pid reused by a port-22 connection stops being Solo's), only
#                 for that connection's own address (a failure line ending in another address is not counted), and
#                 not after the connection's closing line or $ConnLife; a record from another provider or with no pid
#                 is ignored; "Server listening ... port 4251" is seen.  WRITERS (the channel is writable by any
#                 signed-in user): a record is believed only from the listener or its child, both Windows' sshd image,
#                 the child started after the listener; dropped: a non-sshd image, another parent, a child older
#                 than the listener, a listener that is not sshd, no listener, an exited never-verified pid, a
#                 record written after its verified process was seen gone, a reused pid (another creation time);
#                 kept: an exited pid verified while alive, a connection verified before the listener restarted;
#                 a gone pid's verification is forgotten after $VerifiedLife.  PARSING: the address is the LAST "from ...
#                 port ... ssh2"; a message must START the payload (no prefix, no tag); ::ffff: is folded.  The state
#                 file round-trips (connections too).  THE READING PATH, on the recorded source: the bookmark moves,
#                 nothing is read twice, a first pass of the task starts at the END, a cleared source is read from its
#                 start.  THE READING PATH ON A REAL CHANNEL (Application, always present; and OpenSSH/Operational
#                 when this computer has it): Get-LastId is the newest record (Get-WinEvent's own answer), Get-Records
#                 returns only records after the bookmark, oldest first, with their pid and provider; the OpenSSH
#                 payload is sshd's message, not the "sshd" process field; a channel that does not exist THROWS.
#   SCRIPT rows - the real script in a child process with -TestDir (its test hook: one pass, a scratch folder, records
#                 from <folder>\events.txt, the clock from SDSOLO_TEST_NOW, and the firewall and processes replaced by
#                 RULES= / CUT= lines): the third failure prints CUT and the rule, -List names the source and the
#                 address and ends "SOLO SSH GUARD LOCKED 1", -Unlock ends "UNLOCKED 1" and the rule goes, the lock lifts
#                 by itself, a bad address and no switch are refused, the first pass writes "watching ...: ok".
#   PIN rows    - what the guard relies on elsewhere: Solo's sshd_config (solo-sshd.ps1 Get-Config) says LogLevel
#                 VERBOSE and LoginGraceTime 120 (and $ConnLife is longer); the sshd task (solo-machine.ps1) has no -E;
#                 the installer's two checks anchor on the words the guard writes.
#   MUTANTS     - each copy of the logic region below must turn at least one RULE row red.  A mutant whose target is
#                 not found exactly once stops the run (exit 2): it would test nothing.
# NOT MEASURED HERE: Solo's own sshd writing "Connection from ... port 4251" to the channel (VERBOSE; the port-22 sshd
# at INFO never does), the firewall rule refusing a connection, the child being ended.  verify-solo.ps1 leg 18e and
# the installer's "read Solo's sshd start" check measure the first on an installed Solo.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'solo-sshguard.ps1'
$sshdSrc = Join-Path $here 'solo-sshd.ps1'
$machineSrc = Join-Path $here 'solo-machine.ps1'
foreach ($f in @($src, $sshdSrc, $machineSrc)) { if (-not (Test-Path -LiteralPath $f)) { Write-Host "NO TREE: $f missing"; exit 2 } }
Write-Host "guard under test: $src"
$text = [IO.File]::ReadAllText($src)
$m = [regex]::Match($text, '(?s)# BEGIN sshguard_logic[^\n]*\n(.*?)# END sshguard_logic')
if (-not $m.Success) { Write-Host 'CANNOT RUN: no "# BEGIN sshguard_logic ... # END sshguard_logic" region in the script'; exit 2 }
$region = $m.Groups[1].Value

$t = $null; $e = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$t, [ref]$e)

# The real-channel ground truth, taken OUTSIDE the logic under test (Get-WinEvent, not EventLogReader).
$haveOpenSsh = $null -ne (Get-WinEvent -ListLog 'OpenSSH/Operational' -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 })
Write-Host ('real channels: Application; OpenSSH/Operational ' + $(if ($haveOpenSsh) { 'present, with records' } else { 'ABSENT or empty - its row and mutant are not run on this computer' }))

# The RULE rows: run against one loaded copy of the logic; returns the labels of the rows that failed, and prints
# every row when $verbose.
$ruleRows = {
    param([string]$code, [bool]$verbose, [string]$scratch, [bool]$openSsh)
    . ([scriptblock]::Create($code))
    $bad = New-Object System.Collections.ArrayList
    $counter = @{ n = 0 }
    function Row([string]$label, [bool]$ok, [string]$seen) {
        $counter.n++
        if ($verbose) { Write-Host ($(if ($ok) { 'PASS  ' } else { 'FAIL  ' }) + $label + '   [' + $seen + ']') }
        if (-not $ok) { [void]$bad.Add($label) }
    }
    $script:rid = 0
    # Not R, C or F: R is the alias of Invoke-History, and an alias wins over a function.
    function Rc([int]$procId, [string]$msg) { $script:rid++; return @{ Id = [long]$script:rid; Pid = $procId; Provider = 'OpenSSH'; Text = $msg; Time = $null } }
    function Cn([int]$procId, [string]$addr, [int]$port = 4251) { return (Rc $procId ('Connection from ' + $addr + ' port 5' + $procId + ' on 0.0.0.0 port ' + $port)) }
    function Fp([int]$procId, [string]$addr) { return (Rc $procId ('Failed password for don from ' + $addr + ' port 5' + $procId + ' ssh2')) }
    # The world the counting rows run in: listener pid 4000 running Windows' sshd, and every pid a record names is
    # added as its running child (the WRITER rows below build their own worlds).
    $img = $SshdImages[0]
    function New-World {
        $l = @{ Pid = 4000; Parent = 1; Image = $img; Created = [long]100 }
        return @{ Procs = @{ '4000' = $l }; Listener = $l; Vc = @{} }
    }
    function Add-Proc($w, [int]$procId, [int]$parent, [long]$created, [string]$image) { $w.Procs[[string]$procId] = @{ Pid = $procId; Parent = $parent; Image = $image; Created = $created } }
    $script:W = New-World
    function AR($st, $x, [long]$now) {
        if ($null -ne $x.Pid -and -not $script:W.Procs.ContainsKey([string]$x.Pid)) { Add-Proc $script:W $x.Pid 4000 200 $img }
        return (Add-Record $st $x $now $script:W)
    }
    function Feed($st, $recs, [long]$now) { $r = @(); foreach ($x in $recs) { $r += (AR $st $x $now).R }; return ($r -join ',') }
    function Lk($st, [long]$now) { return ((Get-LockedAddrs $st $now) -join ',') }
    $A = '192.0.2.7'; $B = '198.51.100.9'

    $st = New-State
    $r = Feed $st @((Cn 101 $A), (Fp 101 $A), (Fp 101 $A)) 1000
    Row 'two wrong passwords on a Solo connection do not lock the address' ((Lk $st 1001) -eq '' -and $r -eq 'CONN,COUNT,COUNT') ('events ' + $r + ', locked [' + (Lk $st 1001) + ']')
    $r = Feed $st @((Cn 102 $A), (Fp 102 $A)) 1020
    Row 'the third within ten minutes (a second connection) LOCKS that address' ((Lk $st 1021) -eq $A -and $r -eq 'CONN,LOCK') ('events ' + $r + ', locked [' + (Lk $st 1021) + ']')
    $r = Feed $st @((Cn 103 $B), (Fp 103 $B)) 1030
    Row 'another address is not affected by the lock (one failure, not locked)' ((Lk $st 1031) -eq $A -and $r -eq 'CONN,COUNT' -and $st.Addrs[$B].Fails.Count -eq 1) ('locked [' + (Lk $st 1031) + ']')
    Row 'the lock still holds at 599 s' ((Lk $st 1619) -eq $A) ('locked at 1619 [' + (Lk $st 1619) + ']')
    Limit-State $st 1620
    Row 'the lock ends after ten minutes and the address is forgotten' ((Lk $st 1620) -eq '' -and -not $st.Addrs.ContainsKey($A)) ('locked at 1620 [' + (Lk $st 1620) + '], known: ' + (@($st.Addrs.Keys) -join ','))

    $st = New-State
    $k = { param($p) Rc $p ('Failed publickey for don from ' + $A + ' port 5' + $p + ' ssh2') }
    $r = Feed $st @((Cn 201 $A), (& $k 201), (& $k 201), (& $k 201), (& $k 201), (& $k 201)) 2000
    Row 'five failed KEYS from one address count for nothing' ($st.Addrs.Count -eq 0 -and (Lk $st 2001) -eq '') ('events ' + $r + ', addresses known ' + $st.Addrs.Count)
    $r = Feed $st @((Fp 201 $A), (Fp 201 $A), (& $k 201), (Fp 201 $A)) 2010
    Row 'a failed key between wrong passwords is not a sign-in: the third password still locks' ((Lk $st 2011) -eq $A) ('events ' + $r + ', locked [' + (Lk $st 2011) + ']')

    $st = New-State
    $r = Feed $st @((Cn 301 $A), (Fp 301 $A), (Fp 301 $A), (Rc 301 ('Accepted password for don from ' + $A + ' port 5301 ssh2')), (Cn 302 $A), (Fp 302 $A)) 3000
    Row 'a sign-in (password) forgets the failures: two, a sign-in, one more = not locked' ((Lk $st 3001) -eq '' -and $st.Addrs[$A].Fails.Count -eq 1) ('events ' + $r)
    $st = New-State
    $r = Feed $st @((Cn 311 $A), (Fp 311 $A), (Fp 311 $A), (Rc 311 ('Accepted publickey for don from ' + $A + ' port 5311 ssh2: ED25519 SHA256:q1w2e3')), (Cn 312 $A), (Fp 312 $A)) 3100
    Row 'a sign-in by key (sshd adds ": <type> <fingerprint>" after ssh2) forgets the failures' ((Lk $st 3101) -eq '' -and $st.Addrs[$A].Fails.Count -eq 1) ('events ' + $r)

    $st = New-State
    $null = Feed $st @((Cn 401 $A), (Fp 401 $A)) 4000; $null = Feed $st @((Cn 402 $A), (Fp 402 $A)) 4300; $r = Feed $st @((Cn 403 $A), (Fp 403 $A)) 4700
    Row 'three failures spread over more than ten minutes do not lock (the oldest has left the window)' ((Lk $st 4701) -eq '' -and $st.Addrs[$A].Fails.Count -eq 2) ('events ' + $r + ', failures kept ' + $st.Addrs[$A].Fails.Count)

    $st = New-State
    $iu = Rc 501 ('Failed password for invalid user root from ' + $A + ' port 5501 ssh2')
    $r = Feed $st @((Cn 501 $A), $iu, (Rc 501 $iu.Text), (Rc 501 $iu.Text)) 5000
    Row 'a wrong password for a user who does not exist counts too (as on Linux)' ((Lk $st 5001) -eq $A) ('events ' + $r)

    # ---- attribution: only Solo's connections count
    $st = New-State
    $r = Feed $st @((Fp 601 $A), (Fp 601 $A), (Fp 601 $A), (Fp 601 $A)) 6000
    Row 'the port-22 sshd''s failures (a pid that wrote no "Connection from ... port 4251") count for nothing' ($st.Addrs.Count -eq 0 -and $r -eq ',,,') ('events [' + $r + '], addresses known ' + $st.Addrs.Count)
    $r = Feed $st @((Cn 602 $A 22), (Fp 602 $A), (Fp 602 $A), (Fp 602 $A)) 6010
    Row 'a connection on port 22 (VERBOSE there too) counts for nothing' ($st.Addrs.Count -eq 0) ('events [' + $r + ']')
    $r = Feed $st @((Cn 603 $A), (Fp 603 $A), (Cn 603 $A 22), (Fp 603 $A), (Fp 603 $A)) 6020
    Row 'a Solo pid reused by a port-22 connection stops being Solo''s (one failure counted, not three)' ((Lk $st 6021) -eq '' -and $st.Addrs[$A].Fails.Count -eq 1) ('events ' + $r)
    $st = New-State
    $r = Feed $st @((Cn 604 $A), (Fp 604 $A), (Rc 604 ('Disconnected from authenticating user don ' + $A + ' port 5604 [preauth]')), (Fp 604 $A), (Fp 604 $A)) 6100
    Row 'after the connection''s closing line its pid is not Solo''s (one failure counted)' ($st.Addrs[$A].Fails.Count -eq 1 -and -not $st.Conns.ContainsKey('604')) ('events ' + $r)
    $st = New-State
    $null = Feed $st @((Cn 605 $A), (Fp 605 $A)) 6200
    Limit-State $st (6200 + $ConnLife)
    $r = Feed $st @((Fp 605 $A), (Fp 605 $A)) (6200 + $ConnLife)
    Row 'a connection older than $ConnLife is forgotten (its later failures are not counted)' ($st.Addrs[$A].Fails.Count -eq 1 -and $r -eq ',') ('events [' + $r + '], ConnLife ' + $ConnLife)
    $st = New-State
    $r = Feed $st @((Cn 606 $A), (Fp 606 $B), (Fp 606 $B), (Fp 606 $B)) 6300
    Row 'a failure line ending in ANOTHER address than its connection''s is not counted (MISMATCH)' ($st.Addrs.Count -eq 0 -and $r -eq 'CONN,MISMATCH,MISMATCH,MISMATCH') ('events ' + $r)
    $st = New-State
    $o = Cn 607 $A; $o.Provider = 'Someone-Else'
    $f1 = Fp 607 $A; $f1.Provider = 'Someone-Else'
    $np = Fp 607 $A; $np.Pid = $null
    $r = Feed $st @($o, $f1, (Cn 608 $A), $np, $np, $np) 6400
    Row 'a record from another provider, or with no pid, is ignored' ($st.Addrs.Count -eq 0 -and -not $st.Conns.ContainsKey('607')) ('events ' + $r)
    $r1 = (AR (New-State) (Rc 4000 'Server listening on 0.0.0.0 port 4251.') 6500).R
    $r2 = (AR (New-State) (Rc 610 'Server listening on 0.0.0.0 port 22.') 6500).R
    Row 'Solo''s listener start ("Server listening on ... port 4251.") is seen, port 22''s is not' ($r1 -eq 'LISTEN' -and $r2 -eq '') ($r1 + '/' + $r2)

    # ---- WRITER rows: a record is believed only from Solo's sshd as SYSTEM sees it
    function Try1($w, [int]$procId, [string]$label, [string]$wantV) {
        $s = New-State
        $ax = Add-Record $s (Cn $procId $A) 8000 $w
        $ok = ($ax.R -eq 'DROP' -and $ax.V -eq $wantV -and -not $s.Conns.ContainsKey([string]$procId))
        Row $label $ok ('R ' + $ax.R + ', V ' + $ax.V + ' (want DROP ' + $wantV + ')')
    }
    $w = New-World; Add-Proc $w 900 4000 200 'c:\users\public\sshd.exe'
    Try1 $w 900 'a FORGED record: a child of the listener whose image is not Windows'' sshd is dropped' 'forged'
    $w = New-World; Add-Proc $w 901 6512 200 $img
    Try1 $w 901 'a record from an sshd whose parent is NOT Solo''s listener (port 22''s) is dropped' 'forged'
    $w = New-World; Add-Proc $w 902 4000 50 $img
    Try1 $w 902 'a record from a child of the listener''s pid that started BEFORE the listener (a reused parent pid) is dropped' 'forged'
    $w = New-World; $w.Listener.Image = 'c:\temp\sshd.exe'; Add-Proc $w 903 4000 200 $img
    Try1 $w 903 'with a listener that is not Windows'' sshd, nothing is believed' 'forged'
    $w = New-World; $w.Listener = $null; Add-Proc $w 904 4000 200 $img
    Try1 $w 904 'with no listener on 4251, nothing is believed' 'nolistener'
    $w = New-World
    Try1 $w 905 'a record from a process that has EXITED and was NEVER verified is dropped' 'unverified'
    $w = New-World; Add-Proc $w 906 4000 200 'c:\users\public\x.exe'
    # Not $a: PowerShell names are case-blind, and $A is the address every row uses.
    $ax = Add-Record (New-State) (Rc 906 'Server listening on 0.0.0.0 port 4251.') 8000 $w
    Row 'a forged "Server listening ... port 4251" is dropped too' ($ax.R -eq 'DROP' -and $ax.V -eq 'forged') ('R ' + $ax.R + ', V ' + $ax.V)

    # Verified while alive (the 100 ms listing), exited before its records are read: kept; a record written after
    # it was seen gone: dropped.
    $w = New-World; Add-Proc $w 910 4000 200 $img
    Update-Verified $w 1000
    $w.Procs.Remove('910')
    Update-Verified $w 2000
    $s = New-State
    $c1 = Cn 910 $A; $c1.Time = 1500
    $f1 = Fp 910 $A; $f1.Time = 1600
    $f2 = Fp 910 $A; $f2.Time = 2500
    $ra = @((Add-Record $s $c1 8000 $w).R, (Add-Record $s $f1 8000 $w).R)
    Row 'an EXITED process verified earlier while alive is believed: its connection and failure (written before it was seen gone) count' (($ra -join ',') -eq 'CONN,COUNT' -and $s.Addrs[$A].Fails.Count -eq 1) ('events ' + ($ra -join ',') + ', Vc gone ' + $w.Vc['910'].Gone)
    $rb = Add-Record $s $f2 8000 $w
    Row 'a record under that pid written AFTER it was seen gone is dropped' ($rb.R -eq 'DROP' -and $rb.V -eq 'gone' -and $s.Addrs[$A].Fails.Count -eq 1) ('R ' + $rb.R + ', V ' + $rb.V)
    Update-Verified $w (2000 + $VerifiedLife + 1)
    Row 'a gone pid''s verification is forgotten after $VerifiedLife' (-not $w.Vc.ContainsKey('910')) ('Vc keys ' + (@($w.Vc.Keys) -join ','))

    # PID REUSE: the same pid, another creation time.
    $w = New-World; Add-Proc $w 911 4000 200 $img
    $s = New-State
    $ra = (Add-Record $s (Cn 911 $A) 8000 $w).R
    Add-Proc $w 911 4000 300 'c:\users\public\x.exe'
    $rb = Add-Record $s (Fp 911 $A) 8000 $w
    Row 'PID REUSE: a verified pid now running another program (another creation time) is dropped, and its failure not counted' ($ra -eq 'CONN' -and $rb.R -eq 'DROP' -and $rb.V -eq 'forged' -and -not $s.Addrs.ContainsKey($A) -and -not $w.Vc.ContainsKey('911')) ('first ' + $ra + ', then R ' + $rb.R + ' V ' + $rb.V)
    $w = New-World; Add-Proc $w 912 4000 200 $img
    Update-Verified $w 1000
    Add-Proc $w 912 6512 300 $img
    Update-Verified $w 2000
    $g = $w.Vc['912'].Gone
    $rc = Add-Record (New-State) (Cn 912 $A) 8000 $w
    Row 'PID REUSE seen by the listing: the old verification is marked gone and the new process (port 22''s) is dropped' ($g -eq 2000 -and $rc.R -eq 'DROP' -and $rc.V -eq 'forged') ('gone ' + $g + ', R ' + $rc.R + ' V ' + $rc.V)
    $w = New-World; Add-Proc $w 913 4000 200 $img
    $s = New-State
    $null = Add-Record $s (Cn 913 $A) 8000 $w
    $w.Listener = @{ Pid = 4001; Parent = 1; Image = $img; Created = [long]250 }; $w.Procs['4001'] = $w.Listener
    $rd = (Add-Record $s (Fp 913 $A) 8000 $w).R
    Row 'a connection verified before the listener restarted is still believed (same process, verified while alive)' ($rd -eq 'COUNT') ('R ' + $rd)

    # ---- parsing
    $inj = 'Failed password for invalid user x from 10.9.9.9 port 1 ssh2: from ' + $B + ' port 50107 ssh2'
    $ev = Get-LineEvent $inj
    Row 'the address is the LAST "from ... port ... ssh2" on the line, the one sshd appends - not one in a user name' ($null -ne $ev -and $ev.Addr -eq $B) ('addr ' + $(if ($ev) { $ev.Addr } else { 'none' }))
    $ev2 = Get-LineEvent 'Connection closed by authenticating user Failed password for a from 10.9.9.9 port 1 ssh2'
    $ev3 = Get-LineEvent 'Invalid user Accepted password for a from 10.9.9.9 port 1 ssh2'
    Row 'a line whose message does not START the payload is not a failure or a sign-in (a user name holding the words)' (($null -eq $ev2 -or $ev2.Kind -eq 'end') -and $null -eq $ev3) ('events ' + $(if ($ev2) { $ev2.Kind } else { 'none' }) + '/' + [string]$ev3)
    $ev4 = Get-LineEvent ('Failed password for don from ' + $A + ' port 50108 ssh2')
    $ev5 = Get-LineEvent ('sshd-session.exe: Failed password for don from ' + $A + ' port 50108 ssh2')
    $ev5b = Get-LineEvent ('4120 2026-11-17 10:00:00.123 Failed password for don from ' + $A + ' port 50108 ssh2')
    Row 'the bare payload is read; a tagged or prefixed line is NOT (the channel payload has no prefix)' ($null -ne $ev4 -and $ev4.Kind -eq 'fail' -and $null -eq $ev5 -and $null -eq $ev5b) 'three forms'
    $ev6 = Get-LineEvent 'Failed password for don from evil.example port 50109 ssh2'
    $ev7 = Get-LineEvent 'Failed password for don from ::ffff:192.0.2.7 port 50110 ssh2'
    $ev8 = Get-LineEvent 'Failed password for don from 2001:db8::5 port 50111 ssh2'
    $ev9 = Get-LineEvent 'Connection from ::ffff:192.0.2.7 port 50112 on ::ffff:127.0.0.1 port 4251 rdomain ""'
    Row 'a name that is not an address is ignored; ::ffff:192.0.2.7 is 192.0.2.7; IPv6 is read; a Connection line''s peer and port' ($null -eq $ev6 -and $ev7.Addr -eq $A -and $ev8.Addr -eq '2001:db8::5' -and $ev9.Kind -eq 'conn' -and $ev9.Addr -eq $A -and $ev9.Port -eq 4251) ([string]$ev7.Addr + ' ' + [string]$ev8.Addr + ' ' + [string]$ev9.Addr + ':' + [string]$ev9.Port)
    Row 'the IPv6 lock rule''s name has no colon in it' ((Get-RuleName '2001:db8::5') -eq 'SD-Solo-SSH-Guard-2001-db8--5') (Get-RuleName '2001:db8::5')

    $sp = Join-Path $scratch 'rt.state'
    $st = New-State; $st.Offset = 1234
    $null = Feed $st @((Cn 701 $A), (Fp 701 $A), (Fp 701 $A), (Fp 701 $A), (Cn 702 $B), (Fp 702 $B)) 7000
    Write-State $st $sp 7001
    $back = Read-State $sp
    Row 'the state file round-trips: the offset, the lock and its end, the other address''s failure, the connections' ($back.Offset -eq 1234 -and (Lk $back 7002) -eq $A -and $back.Addrs[$A].Until -eq 7600 -and $back.Addrs[$B].Fails.Count -eq 1 -and $back.Conns['702'].Addr -eq $B -and $back.Conns['701'].Time -eq 7000) ((Get-Content $sp) -join ' | ')

    # ---- the reading path, on the recorded source
    $ef = Join-Path $scratch 'events.txt'
    $fs = 'file:' + $ef
    [IO.File]::WriteAllLines($ef, [string[]]@('5 801 Connection from 192.0.2.7 port 1 on 0.0.0.0 port 4251', '6 801 Failed password for don from 192.0.2.7 port 1 ssh2', '7 999 Server listening on :: port 22.'))
    $st = New-State
    $got = @(Read-NewRecords $st $fs $false)
    Row 'a first read from the start returns every record, oldest first, and the bookmark is the last record' ($got.Count -eq 3 -and $got[0].Id -eq 5 -and $got[2].Id -eq 7 -and $got[1].Pid -eq 801 -and $st.Offset -eq 7) ('records ' + $got.Count + ', offset ' + $st.Offset)
    $got = @(Read-NewRecords $st $fs $false)
    Row 'a pass with nothing new reads nothing (nothing is read twice)' ($got.Count -eq 0 -and $st.Offset -eq 7) ('records ' + $got.Count)
    [IO.File]::AppendAllText($ef, "8 801 Failed password for don from 192.0.2.7 port 1 ssh2`r`n")
    $got = @(Read-NewRecords $st $fs $false)
    Row 'a new record is read once, and only it' ($got.Count -eq 1 -and $got[0].Id -eq 8 -and $st.Offset -eq 8) ('records ' + $got.Count + ', offset ' + $st.Offset)
    $st2 = New-State
    $got = @(Read-NewRecords $st2 $fs $true)
    Row 'the task''s first pass starts at the END (old records are not counted again)' ($got.Count -eq 0 -and $st2.Offset -eq 8) ('records ' + $got.Count + ', offset ' + $st2.Offset)
    $st.Offset = 50
    $got = @(Read-NewRecords $st $fs $false)
    Row 'a source whose newest record is older than the bookmark was cleared: it is read from its start' ($got.Count -eq 4 -and $st.Offset -eq 8) ('records ' + $got.Count + ', offset ' + $st.Offset)

    # ---- the reading path, on a REAL channel
    $truth = Get-WinEvent -LogName 'Application' -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -eq $truth) { Row 'the Application log has a record to read' $false 'Get-WinEvent found none' }
    else {
        $lastId = Get-LastId 'Application'
        Row 'Get-LastId on a real channel is its NEWEST record (Get-WinEvent''s answer, or newer)' ($lastId -ge $truth.RecordId -and $lastId -lt ($truth.RecordId + 50)) ('Get-LastId ' + $lastId + ', Get-WinEvent ' + $truth.RecordId)
        $recs = @(Get-Records 'Application' ($lastId - 4))
        $asc = $true; for ($i = 1; $i -lt $recs.Count; $i++) { if ($recs[$i].Id -le $recs[$i - 1].Id) { $asc = $false } }
        $gt = @($recs | Where-Object { $_.Id -le ($lastId - 4) }).Count -eq 0
        $first = $(if ($recs.Count -gt 0) { $recs[0].Id } else { -1 })
        Row 'Get-Records returns ONLY the records after the bookmark, oldest first, with pid and provider' ($recs.Count -ge 4 -and $asc -and $gt -and $first -eq ($lastId - 3) -and @($recs | Where-Object { $null -ne $_.Pid -and $_.Provider }).Count -ge 1) ('records ' + $recs.Count + ', first ' + $first + ' (want ' + ($lastId - 3) + '), ascending ' + $asc)
        $st3 = New-State
        $got = @(Read-NewRecords $st3 'Application' $true)
        Row 'a first pass of the task on a real channel reads nothing and sets the bookmark to its newest record' ($st3.Offset -ge $lastId -and $got.Count -lt 50) ('offset ' + $st3.Offset + ', records ' + $got.Count)
    }
    $threw = $false
    try { $null = @(Get-Records 'SD-No/SuchChannel' 0) } catch { $threw = $true }
    $threw2 = $false
    try { $null = Get-LastId 'SD-No/SuchChannel' } catch { $threw2 = $true }
    Row 'a channel that does not exist THROWS (a pass that read nothing must not look like one that read the source)' ($threw -and $threw2) ('Get-Records threw ' + $threw + ', Get-LastId threw ' + $threw2)
    if ($openSsh) {
        $ol = Get-LastId $Channel
        $or = @(Get-Records $Channel ($ol - 5))
        $osshd = @($or | Where-Object { $_.Provider -eq $Provider -and $_.Text -ne '' -and $_.Text -ne 'sshd' -and $_.Text -ne 'sshd-session' }).Count
        Row 'OpenSSH/Operational: the payload read is sshd''s MESSAGE (not the "sshd" process field), provider OpenSSH' ($or.Count -ge 1 -and $osshd -eq $or.Count) ('records ' + $or.Count + ', with a message ' + $osshd + '; first: ' + $(if ($or.Count) { $or[0].Text } else { '' }))
    }

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
$res = & $ruleRows $region $true $scratch $haveOpenSsh
if ($res.Count -eq 0) { Write-Host 'REFUSED: the null case - no RULE rows ran'; Remove-Item $scratch -Recurse -Force; exit 2 }
$fail += $res.Bad.Count
Write-Host ('RULE rows: ' + $res.Count + ' run, ' + $res.Bad.Count + ' failed')

# ---- SCRIPT rows: the real file, in a child process, with its test hook ------------------------------------------
Write-Host '--- SCRIPT rows (the real script, -TestDir, records from events.txt, clock from SDSOLO_TEST_NOW)'
$td = Join-Path $scratch 'machine'
New-Item -ItemType Directory -Path $td | Out-Null
$ev = Join-Path $td 'events.txt'
$saveNow = $env:SDSOLO_TEST_NOW
function Run-Guard([long]$now, [string[]]$a) {
    $env:SDSOLO_TEST_NOW = [string]$now
    $o = & powershell -NoProfile -ExecutionPolicy Bypass -File $src @a -TestDir $td 2>&1 | Out-String
    $script:lastCode = $LASTEXITCODE
    Write-Host ('  $ solo-sshguard.ps1 ' + ($a -join ' ') + ' -TestDir <scratch>  (now ' + $now + ', exit ' + $script:lastCode + ')')
    foreach ($x in ($o.Trim() -split "`r?`n")) { Write-Host ('  | ' + $x) }
    return $o
}
$script:n = 100
function Add-Ev([int]$procId, [string]$msg) { $script:n++; [IO.File]::AppendAllText($ev, ([string]$script:n + ' ' + $procId + ' ' + $msg + "`r`n")) }
$X = '203.0.113.5'
function Add-Try([int]$procId) {
    Add-Ev $procId ('Connection from ' + $X + ' port 4' + $procId + ' on 0.0.0.0 port 4251')
    Add-Ev $procId ('Failed password for don from ' + $X + ' port 4' + $procId + ' ssh2')
}
# The processes: Solo's listener 4000 (Windows' sshd), its children 1001-1006, and 3001, a child of the listener whose
# program is not Windows' sshd (a forger cannot be one, but the check must not care how it got there).
$sysSshd = Join-Path ([Environment]::SystemDirectory) 'OpenSSH\sshd.exe'
$pl = @('listener 4000', ('proc 4000 1 100 ' + $sysSshd))
foreach ($p in 1001..1006) { $pl += ('proc ' + $p + ' 4000 200 ' + $sysSshd) }
$pl += 'proc 3001 4000 200 C:\Users\Public\sshd.exe'
[IO.File]::WriteAllLines((Join-Path $td 'procs.txt'), [string[]]$pl)
Write-Host ('  procs.txt: ' + ($pl -join ' | '))
Add-Try 1001; Add-Try 1002
Add-Ev 2201 ('Failed password for don from ' + $X + ' port 40009 ssh2')     # the port-22 sshd's: no Connection line
Add-Ev 3001 ('Connection from ' + $X + ' port 43001 on 0.0.0.0 port 4251')  # the forger: three tries
foreach ($i in 1..3) { Add-Ev 3001 ('Failed password for don from ' + $X + ' port 43001 ssh2') }
$script:n = 109; Add-Ev 4000 'Server listening on 0.0.0.0 port 4251.'
$o = Run-Guard 10000 @('-Serve')
Check 'two wrong passwords (and one of port 22''s): no rule, nothing cut; the first pass says it read its source' ($script:lastCode -eq 0 -and $o -match '(?m)^RULES=\s*$' -and $o -notmatch 'CUT=' -and $o -match 'sd-solo-sshguard: watching file:.*: ok, from record 110') 'RULES= empty, watching ... ok'
Check 'the forger''s connection and three failures are dropped, logged ONCE: "unverified record from pid 3001 dropped (forged"' (@([regex]::Matches($o, 'unverified record from pid 3001 dropped \(forged')).Count -eq 1 -and $o -notmatch 'wrong password from 203\.0\.113\.5 \(pid 3001\)') 'one drop line'
Check 'the listener''s own start is read: "Solo''s sshd is listening: pid 4000"' ($o -match 'sd-solo-sshguard: Solo''s sshd is listening: pid 4000 \(Server listening on 0\.0\.0\.0 port 4251\.\)') 'listening: pid 4000'
Add-Try 1003
$o = Run-Guard 10010 @('-Serve')
Check 'the third: the connection is cut and the block rule is wanted for that address' ($o -match ('(?m)^CUT=' + [regex]::Escape($X) + '\s*$') -and $o -match ('(?m)^RULES=' + [regex]::Escape($X) + '\s*$') -and $o -match 'locking 203\.0\.113\.5 for 10 minutes') 'CUT= and RULES='
$o = Run-Guard 10020 @('-Serve')
Check 'a pass with no new records reads nothing again (the bookmark held) and keeps the rule' ($o -notmatch 'CUT=' -and $o -match ('(?m)^RULES=' + [regex]::Escape($X))) 'no CUT, RULES kept'
$o = Run-Guard 10030 @('-List')
Check '-List names the source and its bookmark, the address as LOCKED, and ends "SOLO SSH GUARD LOCKED 1"' ($o -match 'source file:.*: read up to record 112' -and $o -match ([regex]::Escape($X) + '  LOCKED until ') -and $o -match '(?m)^SOLO SSH GUARD LOCKED 1\s*$') 'LOCKED 1'
$o = Run-Guard 10040 @('-Unlock', 'not-an-address')
Check '-Unlock refuses something that is not an address (ERROR=, exit 1)' ($script:lastCode -eq 1 -and $o -match 'ERROR=not an address') 'refused'
$o = Run-Guard 10050 @('-Unlock', $X)
Check '-Unlock <address> ends "SOLO SSH GUARD UNLOCKED 1" and no rule is wanted' ($script:lastCode -eq 0 -and $o -match '(?m)^SOLO SSH GUARD UNLOCKED 1\s*$' -and $o -match '(?m)^RULES=\s*$') 'UNLOCKED 1'
$o = Run-Guard 10060 @('-List')
Check 'after it, -List ends "SOLO SSH GUARD LOCKED 0"' ($o -match '(?m)^SOLO SSH GUARD LOCKED 0\s*$') 'LOCKED 0'
Add-Try 1004; Add-Try 1005; Add-Try 1006
$null = Run-Guard 20000 @('-Serve')
$o = Run-Guard 20599 @('-Serve')
Check 'locked again; still locked at 599 s' ($o -match ('(?m)^RULES=' + [regex]::Escape($X))) 'RULES kept'
$o = Run-Guard 20600 @('-Serve')
Check 'at ten minutes the lock lifts by itself: no rule is wanted' ($o -match '(?m)^RULES=\s*$') 'RULES= empty'
$o = Run-Guard 20610 @('-List')
Check 'and -List shows nothing locked' ($o -match '(?m)^SOLO SSH GUARD LOCKED 0\s*$') 'LOCKED 0'
$o = Run-Guard 20620 @()
Check 'no switch is refused (ERROR=, exit 1)' ($script:lastCode -eq 1 -and $o -match 'ERROR=give exactly one') 'refused'
Remove-Item -LiteralPath (Join-Path $td 'guard.state') -Force
$o = Run-Guard 20630 @('-List')
Check 'with no guard.state, -List says the source was NEVER READ' ($o -match 'NEVER READ') 'NEVER READ'
$env:SDSOLO_TEST_NOW = $saveNow

# ---- PIN rows: what the guard relies on in the other two scripts ---------------------------------------------------
Write-Host '--- PIN rows (solo-sshd.ps1 and solo-machine.ps1)'
$sshdText = [IO.File]::ReadAllText($sshdSrc)
$machText = [IO.File]::ReadAllText($machineSrc)
$cfgBlock = [regex]::Match($sshdText, '(?s)function Get-Config.*?\n}').Value
$cl = [regex]::Match($region, '\$ConnLife = (\d+)')
Check 'Solo''s sshd_config says LogLevel VERBOSE (the "Connection from ... port 4251" line) and LoginGraceTime 120' ($cfgBlock -match "'LogLevel VERBOSE'" -and $cfgBlock -match "'LoginGraceTime 120'" -and $cfgBlock -notmatch "'LogLevel INFO'") 'Get-Config'
Check '$ConnLife is longer than LoginGraceTime 120' ($cl.Success -and [int]$cl.Groups[1].Value -gt 120) ('ConnLife ' + $cl.Groups[1].Value)
$argLine = [regex]::Match($machText, '(?m)^\s*\$arg = ''-D -f "'' \+ \$cfgPath \+ ''"''\s*$')
Check 'the "SD Core Solo SSH" task runs sshd -D -f <config> with NO -E (so sshd logs to the channel)' ($argLine.Success -and $machText -notmatch '-E "'' \+ \$logPath') 'Register-SshTask $arg'
Check 'the installer''s first check anchors on the words the guard writes after its first read' ($machText.Contains('sd-solo-sshguard: watching OpenSSH/Operational: ok, from record \d+') -and $text.Contains('Say (''watching '' + $source + '': ok, from record '' + $st.Offset)') -and $text.Contains("`$Channel = 'OpenSSH/Operational'")) 'watching ... ok'
Check 'the installer''s second check anchors on the guard''s "Solo''s sshd is listening: pid" line' ($machText.Contains('sd-solo-sshguard: Solo''''s sshd is listening: pid (\d+) ') -and $text.Contains('Say (''Solo''''s sshd is listening: pid '' + $rec.Pid + '' ('' + $rec.Text + '')'')')) 'listening: pid'

# ---- MUTANTS -------------------------------------------------------------------------------------------------------
Write-Host '--- MUTANTS (each must turn a RULE row red)'
$mutants = @(
    @('never locks',               'if ($e.Fails.Count -ge $MaxFails)', 'if ($false)'),
    @('records nothing',           '$e.Fails = @(@($e.Fails | Where-Object { ($now - $_) -lt $Window }) + $now)', '$e.Fails = @()'),
    @('key failures counted',      '(Failed password|Accepted \S+)', '(Failed \S+|Accepted \S+)'),
    @('sign-in does not forget',   'if ($st.Addrs.ContainsKey($ev.Addr)) { $st.Addrs.Remove($ev.Addr) }', '$null = 0'),
    @('window ignored',            '$Window = 600 ', '$Window = 1000000000 '),
    @('lock never ends',           '$LockFor = 600 ', '$LockFor = 1000000000 '),
    @('four tries, not three',     '$MaxFails = 3 ', '$MaxFails = 4 '),
    @('the FIRST address taken',   ' for .* from (\S+) port', ' for .*? from (\S+) port'),
    @('message not anchored',      '''^(Failed password|Accepted \S+) for', '''^.*?(Failed password|Accepted \S+) for'),
    @('any pid is Solo''s',        'if (-not $st.Conns.ContainsKey($p)) { return $none }', 'if (-not $st.Conns.ContainsKey($p)) { $st.Conns[$p] = @{ Addr = $ev.Addr; Time = $now } }'),
    @('the port is not checked',   'if ($ev.Port -eq $SshPort) {', 'if ($true) {'),
    @('a reused pid stays Solo''s','            if ($st.Conns.ContainsKey($p)) { $st.Conns.Remove($p) }' + "`n" + '            return $none', '            return $none'),
    @('the closing line ignored',  '''end'' { if ($st.Conns.ContainsKey($p)) { $st.Conns.Remove($p) }; return $none }', '''end'' { return $none }'),
    @('a connection never expires','$ConnLife = 180 ', '$ConnLife = 1000000000 '),
    @('another address counted',   'if ($st.Conns[$p].Addr -ne $ev.Addr)', 'if ($false)'),
    @('provider not checked',      '$rec.Provider -ne $Provider -or ', ''),
    @('listener start not seen',   'if ($ev.Port -ne $SshPort) { return $none }', 'if ($true) { return $none }'),
    @('writer never checked',      'if ($null -eq $world -or $null -eq $world.Listener) { return ''nolistener'' }', 'return ''ok'''),
    @('image not checked',         'if ($SshdImages -notcontains ([string]$p.Image).ToLowerInvariant()) { return $false }', '$null = 0'),
    @('listener image not checked','if ($SshdImages -notcontains ([string]$listener.Image).ToLowerInvariant()) { return $false }', '$null = 0'),
    @('parent not checked',        'return ($p.Parent -eq $listener.Pid -and $p.Created -ge $listener.Created)', 'return $true'),
    @('start time not checked',    ' -and $p.Created -ge $listener.Created)', ')'),
    @('exited never-verified kept','if ($null -eq $c) { return ''unverified'' }', 'if ($null -eq $c) { return ''cached'' }'),
    @('exited verified dropped',   '    return ''cached''' + "`n" + '}', '    return ''unverified''' + "`n" + '}'),
    @('a reused pid believed',     'if ($null -ne $c -and $c.Created -eq $p.Created -and $c.Gone -eq 0) { return ''cached'' }', 'if ($null -ne $c) { return ''cached'' }'),
    @('written after gone kept',   'if ($c.Gone -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $c.Gone) { return ''gone'' }', '$null = 0'),
    @('the listing verifies nothing', 'if ((Test-SoloProcess $p $world.Listener) -and', 'if ($false -and'),
    @('gone never marked',         '{ $c.Gone = $nowTicks }', '{ }'),
    @('gone never forgotten',      '($nowTicks - $c.Gone) -gt $VerifiedLife', '$false'),
    @('a failure''s writer not checked', '    if (-not $st.Conns.ContainsKey($p)) { return $none }' + "`n" + '    $v = Test-RecordProcess $world $rec', '    if (-not $st.Conns.ContainsKey($p)) { return $none }' + "`n" + '    $v = ''ok'''),
    @('state loses connections',   'foreach ($p in @($st.Conns.Keys | Sort-Object)) { $out +=', 'foreach ($p in @()) { $out +='),
    @('file reader reads the bookmark again', '[long]$m.Groups[1].Value -gt $after', '[long]$m.Groups[1].Value -ge $after'),
    @('channel reader reads the bookmark again', '[EventRecordID > ', '[EventRecordID >= '),
    @('last id is the OLDEST',     '$q.ReverseDirection = $true', '$q.ReverseDirection = $false'),
    @('a missing channel reads as empty', '$q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($src, [System.Diagnostics.Eventing.Reader.PathType]::LogName, (', 'if (-not (Get-WinEvent -ListLog $src -ErrorAction SilentlyContinue)) { return @() }; $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($src, [System.Diagnostics.Eventing.Reader.PathType]::LogName, ('),
    @('first pass from the start', '$(if ($fromEnd) { $last } else { [long]0 })', '[long]0'),
    @('a cleared source not re-read', 'if ($last -lt $st.Offset) { $st.Offset = [long]0 }', '$null = 0'),
    @('the bookmark never moves',  'if ($recs.Count -gt 0) { $st.Offset = [long]$recs[$recs.Count - 1].Id }', '$null = 0')
)
if ($haveOpenSsh) { $mutants += , @('the payload is the process field', '$txt = [string]$r.Properties[1].Value', '$txt = [string]$r.Properties[0].Value') }
else { Write-Host "  mutant 'the payload is the process field': NOT RUN - this computer has no OpenSSH/Operational records" }
# The region's line ends are the file's; a target written with "`n" must match them.
$nl = $(if ($region.Contains("`r`n")) { "`r`n" } else { "`n" })
$green = 0
foreach ($mu in $mutants) {
    $tgt = $mu[1].Replace("`n", $nl); $rep = $mu[2].Replace("`n", $nl)
    $n = ([regex]::Matches($region, [regex]::Escape($tgt))).Count
    if ($n -ne 1) { Write-Host ("CANNOT RUN: mutant '" + $mu[0] + "' expects its target once in the logic region, found " + $n); Remove-Item $scratch -Recurse -Force; exit 2 }
    $mr = & $ruleRows ($region.Replace($tgt, $rep)) $false $scratch $haveOpenSsh
    $red = $mr.Bad.Count -gt 0
    if (-not $red) { $green++ }
    Write-Host ("  mutant '" + $mu[0] + "': " + $(if ($red) { 'RED as it must be (' + $mr.Bad.Count + ' rows: ' + ($mr.Bad[0]) + ')' } else { 'STILL GREEN - the rows miss it' }))
}
Check ('every mutant went red (' + ($mutants.Count - $green) + ' of ' + $mutants.Count + ')') ($green -eq 0) ('green ' + $green)

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'sshguard units: ALL PASS'; exit 0 }
Write-Host "sshguard units: $fail FAILED"; exit 1
