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
#                 record written after its verified process was seen gone or after its EXACT exit time (a caught
#                 writer's), a reused pid (another creation time); kept: an exited pid verified while alive, a
#                 caught writer that has exited (the real shape: a refused connection lives ~65 ms, measured
#                 17 Nov 2026), a connection verified before the listener restarted (and dropped after its exit);
#                 a gone pid is marked gone at its exit time, and its verification is forgotten after
#                 $VerifiedLife.  PARSING: the address is the LAST "from ...
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
#                 by itself, a bad address and no switch are refused, the first pass writes "watching ...: ok", a
#                 writer listed "exited" in procs.txt is believed.
#   TRACED rows - (the third build: a connection's process is known from the process start/stop trace only)
#                 a traced life of Solo's counts inside its life and is dropped after its exit; another account,
#                 another program, or no account on either side is forged; a reused pid's records are each judged
#                 against the life the pid had at the record's time; a start stamped up to $TraceSlack late still
#                 owns the record; a record older than the live process or the cached verification under its pid
#                 is unverified; only records $TraceGrace old are judged and the bookmark goes back for the rest.
#   NATIVE rows - SoloSshWatch (the script's sshguard_native region, compiled here) on a child PING.EXE of this
#                 shell: caught with its parent, image, account and creation time; after its exit still held, with
#                 the exact exit time; let go past the hold; a pid not running is not caught.  The trace's
#                 bookkeeping fed recorded start/stop events: two lives of a pid, the stop ends the right one, an
#                 exited life is forgotten after the hold; the subscription throws when it may not subscribe.  Eight
#                 native mutants (renamed copies) must each turn a NATIVE row red.  -Serve starts the trace before
#                 its loop, and a pass judges only ripe records and reads the lives (text pins).
#   PIN rows    - what the guard relies on elsewhere: Solo's sshd_config (solo-sshd.ps1 Get-Config) says LogLevel
#                 VERBOSE and LoginGraceTime 120 (and $ConnLife is longer); the sshd task (solo-machine.ps1) has no -E;
#                 the installer's two checks anchor on the words the guard writes.
#   MUTANTS     - each copy of the logic region below must PARSE and turn at least one RULE row red (a copy that
#                 does not parse, or a native copy that does not compile, counts as green: it tests nothing).  A
#                 mutant whose target is not found exactly once stops the run (exit 2): it would test nothing.
# NOT MEASURED HERE: Solo's own sshd writing "Connection from ... port 4251" to the channel (VERBOSE; the port-22 sshd
# at INFO never does), the process trace delivering Solo's sshd starts and stops as SYSTEM, in time and with the
# listener's account (an unelevated subscription is refused), the firewall rule refusing a
# connection, the child being ended.  verify-solo.ps1 leg 18e (a wrong password must be COUNTED) and the
# installer's "read Solo's sshd start" check measure the first two on an installed Solo.

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
        $l = @{ Pid = 4000; Parent = 1; Image = $img; Sid = 'S-1-5-18'; Created = [long]100 }
        return @{ Procs = @{ '4000' = $l }; Lives = @{}; Listener = $l; Vc = @{} }
    }
    function Add-Proc($w, [int]$procId, [int]$parent, [long]$created, [string]$image, [long]$exited = 0) { $w.Procs[[string]$procId] = @{ Pid = $procId; Parent = $parent; Image = $image; Created = $created; Exited = $exited } }
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
    $r = Feed $st @((Cn 104 $A), (Fp 104 $A), (Fp 104 $A)) 1025
    Row 'a failure from an address already locked extends the lock and is not a new LOCK (logged once, as Linux)' ((Lk $st 1026) -eq $A -and $r -eq 'CONN,RELOCK,RELOCK' -and $st.Addrs[$A].Until -eq (1025 + $LockFor)) ('events ' + $r + ', until ' + $st.Addrs[$A].Until)
    $r = Feed $st @((Cn 103 $B), (Fp 103 $B)) 1030
    Row 'another address is not affected by the lock (one failure, not locked)' ((Lk $st 1031) -eq $A -and $r -eq 'CONN,COUNT' -and $st.Addrs[$B].Fails.Count -eq 1) ('locked [' + (Lk $st 1031) + ']')
    Row 'the lock still holds at 599 s after the last failure' ((Lk $st 1624) -eq $A) ('locked at 1624 [' + (Lk $st 1624) + ']')
    Limit-State $st 1625
    Row 'the lock ends ten minutes after the last failure and the address is forgotten' ((Lk $st 1625) -eq '' -and -not $st.Addrs.ContainsKey($A)) ('locked at 1625 [' + (Lk $st 1625) + '], known: ' + (@($st.Addrs.Keys) -join ','))

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
    $w.Procs['913'].Exited = [long]1500
    Update-Verified $w 3000
    $f3 = Fp 913 $A; $f3.Time = 1400
    $f4 = Fp 913 $A; $f4.Time = 1600
    $re = (Add-Record $s $f3 8000 $w).R
    $rf = Add-Record $s $f4 8000 $w
    Row 'that connection, EXITED at 1500: a record of 1400 is still believed, one of 1600 is dropped (gone)' ($re -eq 'COUNT' -and $rf.R -eq 'DROP' -and $rf.V -eq 'gone' -and $w.Vc['913'].Gone -eq 1500) ('1400: ' + $re + ', 1600: ' + $rf.R + ' ' + $rf.V + ', Vc gone ' + $w.Vc['913'].Gone)

    # THE REAL SHAPE (measured 17 Nov 2026): the writer is caught while it runs and its handle kept, so the guard
    # knows its EXACT exit time; a refused connection has exited (~65 ms) long before its records are read.
    $w = New-World; Add-Proc $w 930 4000 200 $img 1500
    $s = New-State
    $c1 = Cn 930 $A; $c1.Time = 1300
    $f1 = Fp 930 $A; $f1.Time = 1450
    $f2 = Fp 930 $A; $f2.Time = 1501
    $ra = @((Add-Record $s $c1 8000 $w).R, (Add-Record $s $f1 8000 $w).R)
    $rb = Add-Record $s $f2 8000 $w
    Row 'a CAUGHT writer that has exited (exit time 1500): its connection and failure written before the exit count' (($ra -join ',') -eq 'CONN,COUNT' -and $s.Addrs[$A].Fails.Count -eq 1) ('events ' + ($ra -join ','))
    Row 'a record under that pid written AFTER its exit time is dropped (gone), not counted' ($rb.R -eq 'DROP' -and $rb.V -eq 'gone' -and $s.Addrs[$A].Fails.Count -eq 1) ('R ' + $rb.R + ', V ' + $rb.V)
    $w = New-World; Add-Proc $w 931 4000 200 $img
    Update-Verified $w 1000
    $w.Procs['931'].Exited = [long]1500
    Update-Verified $w 3000
    Add-Proc $w 932 4000 200 $img 1700
    Update-Verified $w 3000
    Row 'the listing marks a verified pid gone AT ITS EXIT TIME (1500, not the 3000 it was noticed), and one caught already exited at its exit (1700)' ($w.Vc['931'].Gone -eq 1500 -and $w.Vc['932'].Gone -eq 1700) ('gone ' + $w.Vc['931'].Gone + ' / ' + $w.Vc['932'].Gone)

    # ---- TRACED LIVES (the third build): a connection's process is known only from the start/stop trace - pid,
    # parent, program NAME, account, start and exit - and each record is judged by its pid AND its time.  Real
    # tick scales, because $TraceSlack is 2 s.
    # Not $S: PowerShell names are case-blind, and $s is the state these rows use.
    $T0 = [long]639000000000000000; $Sec = [long]10000000
    function Add-Life($w, [int]$procId, [int]$parent, [long]$created, [long]$exited, [string]$name, [string]$sid) {
        $k = [string]$procId
        if (-not $w.Lives.ContainsKey($k)) { $w.Lives[$k] = @() }
        $w.Lives[$k] += @{ Pid = $procId; Parent = $parent; Image = ''; Name = $name; Sid = $sid; Created = $created; Exited = $exited }
    }
    function At($x, [long]$t) { $x.Time = $t; return $x }
    $w = New-World; Add-Life $w 950 4000 ($T0 + $Sec) ($T0 + 2 * $Sec) 'sshd.exe' 'S-1-5-18'
    $s = New-State
    $ra = @((Add-Record $s (At (Cn 950 $A) ($T0 + $Sec + 1000)) 8000 $w).R, (Add-Record $s (At (Fp 950 $A) ($T0 + $Sec + 5000)) 8000 $w).R)
    $rb = Add-Record $s (At (Fp 950 $A) ($T0 + 3 * $Sec)) 8000 $w
    Row 'a TRACED life (sshd.exe, the listener''s account, parent the listener) is Solo''s: its connection and failure inside its life count' (($ra -join ',') -eq 'CONN,COUNT' -and $s.Addrs[$A].Fails.Count -eq 1) ('events ' + ($ra -join ','))
    Row 'a record under that pid AFTER the traced exit is dropped (gone)' ($rb.R -eq 'DROP' -and $rb.V -eq 'gone') ('R ' + $rb.R + ', V ' + $rb.V)
    $w = New-World; Add-Life $w 951 4000 ($T0 + $Sec) 0 'sshd.exe' 'S-1-5-21-1-2-3-1001'
    $ax = Add-Record (New-State) (At (Cn 951 $A) ($T0 + 2 * $Sec)) 8000 $w
    Row 'a traced child of the listener running as ANOTHER account is dropped (forged)' ($ax.R -eq 'DROP' -and $ax.V -eq 'forged') ('R ' + $ax.R + ', V ' + $ax.V)
    $w = New-World; Add-Life $w 952 4000 ($T0 + $Sec) 0 'evil.exe' 'S-1-5-18'
    $ax = Add-Record (New-State) (At (Cn 952 $A) ($T0 + 2 * $Sec)) 8000 $w
    Row 'a traced child of the listener whose program is not sshd is dropped (forged)' ($ax.R -eq 'DROP' -and $ax.V -eq 'forged') ('R ' + $ax.R + ', V ' + $ax.V)
    $w = New-World; $w.Listener.Sid = ''; Add-Life $w 953 4000 ($T0 + $Sec) 0 'sshd.exe' ''
    $ax = Add-Record (New-State) (At (Cn 953 $A) ($T0 + 2 * $Sec)) 8000 $w
    Row 'with neither account known, a traced child is dropped (an empty account is not a match)' ($ax.R -eq 'DROP' -and $ax.V -eq 'forged') ('R ' + $ax.R + ', V ' + $ax.V)
    # PID REUSE in the trace: a Solo life (T0+1 s .. T0+2 s), then a forger's (parent another process) from T0+10 s.
    $w = New-World; Add-Life $w 954 4000 ($T0 + $Sec) ($T0 + 2 * $Sec) 'sshd.exe' 'S-1-5-18'; Add-Life $w 954 6512 ($T0 + 10 * $Sec) 0 'sshd.exe' 'S-1-5-18'
    $r1 = (Add-Record (New-State) (At (Cn 954 $A) ($T0 + $Sec + 1000)) 8000 $w).R
    $w.Vc = @{}
    $r2 = Add-Record (New-State) (At (Cn 954 $A) ($T0 + 11 * $Sec)) 8000 $w
    $w.Vc = @{}
    $r3 = Add-Record (New-State) (At (Cn 954 $A) ($T0 + 5 * $Sec)) 8000 $w
    Row 'PID REUSE in the trace: each record is judged against the life its pid had AT ITS TIME (Solo''s: CONN; the forger''s: forged; between the two: gone)' ($r1 -eq 'CONN' -and $r2.V -eq 'forged' -and $r3.V -eq 'gone') ('T0+1s ' + $r1 + ', T0+11s ' + $r2.R + ' ' + $r2.V + ', T0+5s ' + $r3.R + ' ' + $r3.V)
    $w = New-World; Add-Life $w 955 4000 ($T0 + $Sec) 0 'sshd.exe' 'S-1-5-18'
    $rs = (Add-Record (New-State) (At (Cn 955 $A) ($T0 + [long]5000000)) 8000 $w).R
    $rt = Add-Record (New-State) (At (Cn 955 $A) ($T0 - 2 * $Sec)) 8000 $w
    Row 'a traced start stamped up to $TraceSlack after the record still owns it; one 3 s after does not (unverified)' ($rs -eq 'CONN' -and $rt.R -eq 'DROP' -and $rt.V -eq 'unverified') ('0.5 s before: ' + $rs + ', 3 s before: ' + $rt.R + ' ' + $rt.V)
    # A live entry, or a cached verification, says nothing about a record OLDER than its process.
    $w = New-World; Add-Proc $w 956 4000 ($T0 + 10 * $Sec) $img
    $ru = Add-Record (New-State) (At (Cn 956 $A) ($T0 + $Sec)) 8000 $w
    $w = New-World; $w.Vc['957'] = @{ Created = $T0 + 10 * $Sec; Gone = [long]0 }
    $rv = Test-RecordProcess $w (At (Cn 957 $A) ($T0 + $Sec))
    Row 'a record older than the live process under its pid, or than its cached verification, is dropped (unverified)' ($ru.R -eq 'DROP' -and $ru.V -eq 'unverified' -and $rv -eq 'unverified') ('live: ' + $ru.R + ' ' + $ru.V + ', cached: ' + $rv)
    # RIPENESS: only records $TraceGrace old are judged; the bookmark goes back to just before the first newer one.
    $st = New-State; $st.Offset = 40
    $rr = @(@{ Id = 41; Time = $T0 }, @{ Id = 42; Time = $T0 + $Sec }, @{ Id = 43; Time = $T0 + 10 * $Sec }, @{ Id = 44; Time = $T0 + 11 * $Sec })
    $st.Offset = 44
    $ripe = @(Select-Ripe $st $rr ($T0 + 5 * $Sec))
    Row 'records newer than the cutoff are not judged now, and the bookmark goes back to read them again' ($ripe.Count -eq 2 -and $ripe[1].Id -eq 42 -and $st.Offset -eq 42) ('ripe ' + $ripe.Count + ', offset ' + $st.Offset)

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
$pl += ('proc 1007 4000 200 exited 300 ' + $sysSshd)
# Traced lives (the real shape since the third build): 1008 Solo's (sshd.exe, the listener's account), 3002 a
# child of the listener under another account.
$pl += 'sid 4000 S-1-5-18'
$pl += 'life 1008 4000 200 300 sshd.exe S-1-5-18'
$pl += 'life 3002 4000 200 0 sshd.exe S-1-5-21-1-2-3-1001'
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
Add-Try 1007
$o = Run-Guard 10070 @('-Serve')
Check 'a writer listed as EXITED ("proc ... exited <ticks> <image>", the real shape of a refused connection) is believed: its wrong password counts' ($o -match 'a wrong password from 203\.0\.113\.5 \(pid 1007\)' -and $o -notmatch 'pid 1007 dropped') 'wrong password (pid 1007)'
Add-Try 1008; Add-Try 3002
$o = Run-Guard 10080 @('-Serve')
Check 'a TRACED life ("life ..." in procs.txt) of Solo''s is believed; one under another account is dropped (forged)' ($o -match 'a wrong password from 203\.0\.113\.5 \(pid 1008\)' -and $o -match 'unverified record from pid 3002 dropped \(forged' -and $o -notmatch '\(pid 3002\)') 'pid 1008 counted, 3002 forged'
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

# ---- NATIVE rows: SoloSshWatch, the process catcher, compiled from the script and driven on OUR OWN child ---------
# (unelevated we may open our own child, not Solo's SYSTEM sshd; the C# is the same either way).  Each mutant is a
# renamed copy (a type cannot be compiled twice in one process) and must turn a NATIVE row red.
Write-Host '--- NATIVE rows (the sshguard_native region, compiled; a child PING.EXE -n 2 127.0.0.1 of this shell)'
$nm = [regex]::Match($text, "(?s)# BEGIN sshguard_native[^\n]*\n.*?\`$NativeSource = @'\r?\n(.*?)\r?\n'@")
if (-not $nm.Success) { Write-Host 'CANNOT RUN: no "$NativeSource = @''...''@" in the sshguard_native region'; Remove-Item $scratch -Recurse -Force; exit 2 }
$native = $nm.Groups[1].Value
$ping = Join-Path ([Environment]::SystemDirectory) 'PING.EXE'
function Test-Native([string]$code, [string]$suffix, [bool]$verbose) {
    $bad = New-Object System.Collections.ArrayList
    function NRow([string]$label, [bool]$ok, [string]$seen) {
        if ($verbose) { Write-Host ($(if ($ok) { 'PASS  ' } else { 'FAIL  ' }) + $label + '   [' + $seen + ']') }
        if (-not $ok) { [void]$bad.Add($label) }
    }
    $tn = 'SoloSshWatch' + $suffix
    try { Add-Type -TypeDefinition ($code.Replace('SoloSshWatch', $tn).Replace('SoloProcInfo', 'SoloProcInfo' + $suffix)) -ReferencedAssemblies 'System.Management' -ErrorAction Stop }
    catch { NRow 'the native region compiles' $false $_.Exception.Message; return @($bad) }
    NRow 'the native region compiles' $true $tn
    $ty = [type]$tn
    $p = Start-Process -FilePath $ping -ArgumentList '-n', '2', '127.0.0.1' -WindowStyle Hidden -PassThru
    $caught = $ty::Catch($p.Id)
    $i = @($ty::Snapshot([long]600000000) | Where-Object { $_.Pid -eq $p.Id })
    $wantC = $p.StartTime.ToUniversalTime().Ticks
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ok = ($caught -and $i.Count -eq 1 -and $i[0].Parent -eq $PID -and $i[0].Image -eq $ping -and $i[0].Created -eq $wantC -and $i[0].Exited -eq 0 -and $i[0].Sid -eq $me)
    NRow 'a running process is caught: its parent (this shell), image, account (ours) and creation time (Process.StartTime''s ticks), not exited' $ok ('caught ' + $caught + $(if ($i.Count) { ', parent ' + $i[0].Parent + ' (want ' + $PID + '), image ' + $i[0].Image + ', sid ' + $i[0].Sid + ' (want ' + $me + '), created ' + $i[0].Created + ' (want ' + $wantC + '), exited ' + $i[0].Exited } else { ', not in the snapshot' }))
    $p.WaitForExit()
    $i = @($ty::Snapshot([long]600000000) | Where-Object { $_.Pid -eq $p.Id })
    $wantX = $p.ExitTime.ToUniversalTime().Ticks
    NRow 'after it EXITS it is still held: the exact exit time (Process.ExitTime''s ticks), and the image read while it ran' ($i.Count -eq 1 -and $i[0].Exited -eq $wantX -and $i[0].Image -eq $ping) $(if ($i.Count) { 'exited ' + $i[0].Exited + ' (want ' + $wantX + '), image ' + $i[0].Image } else { 'not in the snapshot' })
    Start-Sleep -Milliseconds 20
    $i = @($ty::Snapshot([long]0) | Where-Object { $_.Pid -eq $p.Id })
    NRow 'once past the hold its handle is let go and it is forgotten' ($i.Count -eq 0) ('entries for the pid ' + $i.Count)
    $c2 = $ty::Catch(2147483644)
    NRow 'a pid that is not running is not caught' (-not $c2) ('Catch ' + $c2)
    # THE TRACE's bookkeeping, fed recorded events (the subscription itself needs an administrator): two lives of
    # one pid, a stop that ends the right one, and an exited life forgotten after the hold.
    $tp = 2147483640
    $t0 = [DateTime]::UtcNow.Ticks - 50000000
    $ty::AddStart($tp, 4000, 'sshd.exe', 'S-1-5-18', $t0)
    $ty::AddStart($tp, 6000, 'sshd.exe', 'S-1-5-18', $t0 + 30000000)
    $ty::AddStop($tp, $t0 + 10000000)
    $lv = @($ty::LivesSnapshot([long]600000000) | Where-Object { $_.Pid -eq $tp } | Sort-Object Created)
    NRow 'two starts of one pid are two lives (parent, program, account kept); the stop ends the life that had started by then' ($lv.Count -eq 2 -and $lv[0].Parent -eq 4000 -and $lv[0].Name -eq 'sshd.exe' -and $lv[0].Sid -eq 'S-1-5-18' -and $lv[0].Exited -eq ($t0 + 10000000) -and $lv[1].Exited -eq 0) ('lives ' + $lv.Count + $(if ($lv.Count -eq 2) { ', exited ' + $lv[0].Exited + ' / ' + $lv[1].Exited } else { '' }))
    $lv = @($ty::LivesSnapshot([long]10000000) | Where-Object { $_.Pid -eq $tp })
    NRow 'an exited life older than the hold is forgotten, a running one is kept' ($lv.Count -eq 1 -and $lv[0].Parent -eq 6000) ('lives ' + $lv.Count)
    $threw = $false; $msg = ''
    try { $ty::StartTrace(); $ty::StopTrace() } catch { $threw = $true; $msg = $_.Exception.InnerException.Message }
    $elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    NRow 'the trace subscription THROWS when it cannot subscribe (unelevated: "Access denied"); elevated it starts' ($(if ($elev) { -not $threw } else { $threw })) ('elevated ' + $elev + ', threw ' + $threw + ' ' + $msg)
    return @($bad)
}
$nb = @(Test-Native $native '' $true)
$fail += $nb.Count
Write-Host ('NATIVE rows: ' + $nb.Count + ' failed')
Check '-Serve starts the trace before its first pass, compiled with TEMP in the machine folder' ($text.Contains('[SoloSshWatch]::StartTrace()') -and $text.Contains('$env:TMP = $dir; $env:TEMP = $dir') -and $text.IndexOf('[SoloSshWatch]::StartTrace()') -lt $text.IndexOf('while ($true) {')) 'StartTrace before the loop'
Check 'a pass judges only records $TraceGrace old (Select-Ripe), and reads the trace''s lives into the world' ($text.Contains('$ripe = @(Select-Ripe $st $recs ((Get-NowTicks) - $TraceGrace))') -and $text.Contains('foreach ($rec in $ripe) {') -and $text.Contains('[SoloSshWatch]::LivesSnapshot($HoldTicks)') -and $text.Contains('$script:World.Lives = $lives')) 'ripe records, lives'
$nmut = @(
    @('a stop marks no life',     'if (best != null) best.Exited = exited;', 'if (best == null) best = null;'),
    @('a stop ends a later life', 'i.Exited == 0 && i.Created <= exited &&', 'i.Exited == 0 &&'),
    @('exited lives never forgotten', 'kv.Value.RemoveAll(i => i.Exited != 0 && now - i.Exited > holdTicks);', 'kv.Value.RemoveAll(i => false);'),
    @('the account not read',     'i.Sid = TokenSid(h);', 'i.Sid = "";'),
    @('the exit time never read', 'if (en.I.Exited == 0 && WaitForSingleObject(en.H, 0) == 0)', 'if (en.I.Exited == 0 && en.H == IntPtr.Zero)'),
    @('the parent not read',      'i.Parent = (int)b.InheritedFromUniqueProcessId.ToInt64();', 'i.Parent = 0;'),
    @('the image not read',       'i.Image = sb.ToString(0, (int)n);', 'i.Image = "";'),
    @('handles never let go',     'foreach (int p in gone) { CloseHandle(Map[p].H); Map.Remove(p); }', 'gone.Clear();')
)
$ng = 0; $k = 0
foreach ($mu in $nmut) {
    $k++
    if (([regex]::Matches($native, [regex]::Escape($mu[1]))).Count -ne 1) { Write-Host ("CANNOT RUN: native mutant '" + $mu[0] + "' expects its target once"); Remove-Item $scratch -Recurse -Force; exit 2 }
    $mb = @(Test-Native ($native.Replace($mu[1], $mu[2])) ('M' + $k) $false)
    # A mutant that does not compile proves nothing about the rows: it counts as green.
    $red = $mb.Count -gt 0 -and $mb -notcontains 'the native region compiles'
    if (-not $red) { $ng++ }
    Write-Host ("  native mutant '" + $mu[0] + "': " + $(if ($red) { 'RED as it must be (' + $mb[0] + ')' } elseif ($mb.Count) { 'DOES NOT COMPILE - it tests nothing' } else { 'STILL GREEN - the rows miss it' }))
}
Check ('every native mutant went red (' + ($nmut.Count - $ng) + ' of ' + $nmut.Count + ')') ($ng -eq 0) ('green ' + $ng)

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
    # A target or replacement built with + is in parentheses: the comma binds tighter than +, so without them the
    # pieces became separate array elements and the mutant tested something else (found 17 Nov 2026).
    @('a reused pid stays Solo''s',('            if ($st.Conns.ContainsKey($p)) { $st.Conns.Remove($p) }' + "`n" + '            return $none'), '            return $none'),
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
    @('exited verified dropped',   ('    return ''cached''' + "`n" + '}'), ('    return ''unverified''' + "`n" + '}')),
    @('a reused pid believed',     'if ($null -ne $c -and $c.Created -eq $p.Created) {', 'if ($null -ne $c) {'),
    @('written after gone kept',   ('$rec.Time -lt $c.Created) { return ''unverified'' }' + "`n" + '    if ($c.Gone -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $c.Gone) { return ''gone'' }'), '$rec.Time -lt $c.Created) { return ''unverified'' }'),
    @('a record older than its cached process kept', '    if ($null -ne $rec.Time -and $rec.Time -lt $c.Created) { return ''unverified'' }', '    $null = 0'),
    @('a live entry owns older records', '($null -eq $rec.Time -or $rec.Time -ge $p.Created)', '$true'),
    @('a traced account not checked', ' -and $p.Sid -and $p.Sid -eq $listener.Sid', ''),
    @('an empty account matches',  ' -and $p.Sid -and $p.Sid -eq $listener.Sid', ' -and $p.Sid -eq $listener.Sid'),
    @('a traced program not checked', '$SshdNames -contains ([string]$p.Name).ToLowerInvariant() -and ', ''),
    @('the first life, not the latest', 'if ($null -eq $best -or $l.Created -gt $best.Created) { $best = $l }', 'if ($null -eq $best) { $best = $l }'),
    @('a life started after the record used', 'if ($null -ne $rec.Time -and $l.Created -gt ($rec.Time + $TraceSlack)) { continue }', '$null = 0'),
    @('no slack for a late start', '($rec.Time + $TraceSlack)', '$rec.Time'),
    @('every record judged at once', 'if ($null -ne $r.Time -and $r.Time -gt $cutoff) { $st.Offset = [long]$r.Id - 1; break }', '$null = 0'),
    @('the bookmark not put back', '{ $st.Offset = [long]$r.Id - 1; break }', '{ break }'),
    @('written after gone kept (listener restarted)', '            if ($c.Gone -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $c.Gone) { return ''gone'' }', '            $null = 0'),
    @('the exit time ignored',     'if ($x -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $x) { return ''gone'' }', '$null = 0'),
    @('the listing verifies nothing', 'if (-not (Test-SoloProcess $p $world.Listener)) { continue }', 'continue'),
    @('gone never marked',         '{ $c.Gone = $nowTicks }', '{ }'),
    @('the exit never marks gone', 'elseif ($c.Gone -eq 0 -and [long]$p.Exited -gt 0) { $c.Gone = [long]$p.Exited }', 'elseif ($false) { }'),
    @('gone never forgotten',      '($nowTicks - $c.Gone) -gt $VerifiedLife', '$false'),
    @('a failure''s writer not checked', ('    if (-not $st.Conns.ContainsKey($p)) { return $none }' + "`n" + '    $v = Test-RecordProcess $world $rec'), ('    if (-not $st.Conns.ContainsKey($p)) { return $none }' + "`n" + '    $v = ''ok''')),
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
    $mcode = $region.Replace($tgt, $rep)
    $pt = $null; $pe = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($mcode, [ref]$pt, [ref]$pe)
    if ($pe.Count -gt 0) { Write-Host ("  mutant '" + $mu[0] + "': DOES NOT PARSE (" + $pe[0].Message + ') - it tests nothing'); $green++; continue }
    $mr = & $ruleRows $mcode $false $scratch $haveOpenSsh
    $red = $mr.Bad.Count -gt 0
    if (-not $red) { $green++ }
    Write-Host ("  mutant '" + $mu[0] + "': " + $(if ($red) { 'RED as it must be (' + $mr.Bad.Count + ' rows: ' + ($mr.Bad[0]) + ')' } else { 'STILL GREEN - the rows miss it' }))
}
Check ('every mutant went red (' + ($mutants.Count - $green) + ' of ' + $mutants.Count + ')') ($green -eq 0) ('green ' + $green)

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'sshguard units: ALL PASS'; exit 0 }
Write-Host "sshguard units: $fail FAILED"; exit 1
