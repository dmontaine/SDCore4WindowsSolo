# solo-sshguard.ps1 - the lockout in front of SD Core Solo's own sshd (port 4251).  From Linux Solo's
# gplbld/solo-sshguard.py (LSOLO 29; the owner, 2 Oct 2026, asked for the lockout), carried 17 Nov 2026 in the
# four-version audit (decision D1: "a feature parity needs; it tightens, so nothing ships looser").
#
#   -Serve                  (the SYSTEM task "SD Core Solo SSH Guard")  watch sshd's lines and keep the lock rules
#   -List                   (anyone)    who is locked, who has failures, what the guard has read
#   -Unlock <ADDRESS|all>   (ELEVATED)  forget one address, or every address, and take its lock rule away
# All with: powershell -NoProfile -ExecutionPolicy Bypass -File "%ProgramData%\SDCoreSolo\ssh\solo-sshguard.ps1" <switch>
#
# THE RULE, Linux Solo's, word for word: PER ADDRESS.  Three wrong passwords from one address within ten minutes,
# and that address is refused for ten minutes.  Only a failed PASSWORD counts (a client offering keys the server
# does not know fails publickey over and over and must not be punished for it).  A sign-in forgets that address's
# failures.  The Windows account is never locked by this, and the computer's own sshd (port 22) is not touched.
#
# THE SOURCE, WINDOWS' (17 Nov 2026, SOLO 77).  The first build tailed the -E file sshd.log and NEVER READ A LINE:
# Win32-OpenSSH holds its -E log open for writing without FILE_SHARE_READ, so every open by the guard failed with a
# sharing violation (measured on the installed Solo, 17 Nov 16:44 - 17:02: "pass failed: ... being used by another
# process" every 2 s, guard.state "offset -1").  No sshd_config option changes how that file is opened.  So Solo's
# sshd now runs WITHOUT -E and logs where Windows' sshd always logs, the event channel OpenSSH/Operational (payload
# = sshd's message, no prefix; System/ProcessID = the sshd process that wrote it - set by Windows, not by the
# writer), and this guard reads that channel from a record-number bookmark.  The computer's own sshd (port 22)
# logs to the same channel, so a line is Solo's only when the PROCESS that wrote it first wrote
#     Connection from <addr> port <n> on <laddr> port 4251
# (LogLevel VERBOSE in Solo's sshd_config; sshd writes it from the socket, before the client has sent a byte, in the
# per-connection process that later writes that connection's "Failed password" / "Accepted" lines - measured on the
# port-22 sshd: one pid per connection across "User ... not allowed", "Failed password" and "... [preauth]").
# That is Linux's per-connection view (its guard sits on the connection's own stderr) rebuilt from the log: a
# failure counts against the address of ITS CONNECTION's socket, and only when the "from <addr>" sshd appends at the
# END of the failure line is the same address (a user name cannot move the address a lock is put on).  A pid is
# Solo's connection until it writes "Disconnected from" / "Connection closed by" / "Connection reset by", a sign-in,
# a "Connection from" for another port, or $ConnLife seconds pass (Solo's sshd_config pins LoginGraceTime 120, and
# every password try of a connection falls inside it).
#
# THE MECHANISM: a locked address gets a Windows Firewall BLOCK rule on port 4251 for that address alone (named
# SD-Solo-SSH-Guard-<addr>, group "SD Core Solo ssh lock-out"), removed when the ten minutes are up; the connection
# that made the third wrong try is ended by stopping the sshd child that holds it.
#
# WHAT A SYSTEM PROCESS MAY NEVER DO: run a script a user can edit.  So the task runs THIS FILE from the admin-only
# machine folder, where solo-sshd.ps1 -Install copies it (and reads its permissions back); the copy in the user's
# Solo folder is only the source of that copy.  The state, guard.state, and this guard's own log, sshguard.log, are
# written there by SYSTEM; users may read them (-List works from an ordinary prompt), only an administrator may
# change them (-Unlock).
#
# WHAT IT DOES NOT DO (as on Linux): stop a guess spread over MANY addresses (each gets its three); and connections
# already open when the lock engages are each cut at their next wrong password.  WINDOWS ONLY: Windows Firewall does
# not filter LOOPBACK traffic, so a lock on 127.0.0.1 or ::1 cuts the connection but cannot refuse the next one -
# the person at the computer.  Windows' own account lockout policy (if the computer has one) still counts the same
# wrong passwords against the Windows ACCOUNT; this guard cuts an address off at three, before that policy's count.
# WHO MAY WRITE A RECORD THE GUARD BELIEVES.  The channel's own access list lets INTERACTIVE users write to it
# (channelAccess "(A;;0x3;;;IU)", read 17 Nov 2026), so any program the signed-in user runs can write sshd-shaped
# records - under ITS OWN pid, which Windows sets.  So a record that would change the state (a connection or listener
# start on 4251, a failure or sign-in of a Solo connection) is believed only when the process that had its pid AT
# THE RECORD'S TIME is Solo's sshd: the process that owns port 4251 (caught live: its full path is an sshd.exe /
# sshd-session.exe of System32\OpenSSH or Program Files\OpenSSH), or a process whose PARENT is that one, that started
# after it, whose program is sshd.exe / sshd-session.exe and whose account is the listener's.  A user cannot make the
# listener its parent or run a process as the listener's account.  A connection's process lives ~55 ms and is gone
# long before its records can be read (and before the channel's own subscription delivers them: 250 - 930 ms,
# measured), so the guard does not look at it at all: it keeps the history Windows' process START AND STOP TRACE
# gives it (pid, parent, program, account and start time captured as the process starts; the exit time as it stops;
# SoloSshWatch, at "the world" below), and judges a record by its pid and time against that history.  A record
# outside its writer's life, from a pid with no known life, or from a life that is not Solo's is dropped, with
# "unverified record from pid P dropped (...)" in sshguard.log once per pid.
#
# WHAT IT CANNOT SEE OR TRUST, after that: a start or stop event Windows does not deliver (WMI may drop events
# under load) leaves a connection with no known life, so its records are dropped and its wrong passwords are not
# counted - an under-count, never an over-count; so does a record whose writer started more than $TraceSlack after
# it.  Records are judged $TraceGrace after they are written, so a lock engages a few seconds after the third wrong
# password.  If the stop event of a Solo connection is lost and Windows gives its pid to a forger whose START event
# is ALSO lost, the forger's records would be read against the Solo life and believed; with either event delivered
# they are dropped.  If an administrator disables the channel the guard goes blind after the install's check; and
# a pid of a Solo connection killed without a closing line and reused within $ConnLife seconds by a port-22
# connection would be read as Solo's - except that the reused process's parent is the port-22 listener, so its
# records fail the check.
#
# NOT MEASURED (17 Nov 2026): the trace as SYSTEM (an unelevated subscription is refused, "Access denied" -
# measured); its delivery delay against $TraceGrace; whether TIME_CREATED is the kernel's moment or WMI's (hence
# $TraceSlack); that the per-connection sshd runs as the listener's account; that OpenProcess, QueryFullProcessImageName,
# NtQueryInformationProcess and the token read succeed as SYSTEM on the listener (unelevated they are refused, error
# 5; the second build's log, 17 Nov 19:43, shows the listener caught as SYSTEM); that the block rule refuses a NEW
# connection from the address; that stopping the child that owns the established connection ends only that one.
# MEASURED (17 Nov 2026 19:03 - 19:05): Solo's sshd writes "Connection from ... port 4251" (VERBOSE) to the channel,
# from the per-connection process (parent = the listener) that writes the connection's other records.
#
# OUTPUT: -List ends "SOLO SSH GUARD LOCKED <n>", -Unlock ends "SOLO SSH GUARD UNLOCKED <n>" (Linux's words); a
# refusal is "ERROR=<text>", exit 1.  -Serve writes "watching OpenSSH/Operational: ok, from record <n>" to
# sshguard.log after its FIRST successful read and "Solo's sshd is listening: pid <p> (...)" when it reads Solo's
# listener start - solo-machine.ps1 waits for both.  TEST HOOK, NOT A FEATURE: -TestDir <folder> uses that folder
# for the state, reads records from <folder>\events.txt ("<record> <pid> <message>" per line) in place of the
# channel and the sshd processes from <folder>\procs.txt in place of the live catch and the trace, honours SDSOLO_TEST_NOW (seconds since 1970) as the clock, makes -Serve do ONE pass, and never touches the
# firewall, a process or the machine folder; a real task never passes it.

param(
    [switch]$Serve,
    [switch]$List,
    [string]$Unlock = '',
    [string]$TestDir = ''
)

$ErrorActionPreference = 'Continue'
$env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules"

# BEGIN sshguard_logic  (test-sshguard-units.ps1 loads this region and its mutants; keep it free of side effects)
$MaxFails = 3        # wrong passwords from one address ...
$Window = 600        # ... within this many seconds lock it ...
$LockFor = 600       # ... for this many seconds
$ConnLife = 180      # a Solo connection's pid is trusted this long (LoginGraceTime 120 in Solo's sshd_config, + 60)
$SshPort = 4251      # SOLO_SSH_PORT - solo-sshd.ps1 carries the same number
$Channel = 'OpenSSH/Operational'
$Provider = 'OpenSSH'
$RulePrefix = 'SD-Solo-SSH-Guard-'
$RuleGroup = 'SD Core Solo ssh lock-out'

# One address as sshd writes it -> its canonical text, or '' when it is not an IP address.
function Get-Addr([string]$a) {
    if ($a.StartsWith('::ffff:')) { $a = $a.Substring(7) }
    $a = ($a -split '%')[0]
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($a, [ref]$ip)) { return '' }
    return $ip.ToString()
}

# One sshd message (the channel's payload: no prefix) -> $null, or one of
#   @{ Kind = 'conn';   Addr = <peer>; Port = <local port> }   "Connection from A port N on L port P"
#   @{ Kind = 'listen'; Port = <port> }                         "Server listening on L port P."
#   @{ Kind = 'end' }                                           the connection's closing lines
#   @{ Kind = 'fail' | 'accept'; Addr = <address> }             "Failed password ..." / "Accepted <method> ..."
# Every pattern is anchored at the START of the message, so a user name holding the words cannot make another
# message count.  The failure's address is the LAST "from <addr> port <n> ssh2" - the one sshd appends (a key
# sign-in adds ": <key type> <fingerprint>" after it) - and must parse as an IP address.
function Get-LineEvent([string]$line) {
    $m = [regex]::Match($line, '^(Failed password|Accepted \S+) for .* from (\S+) port \d+ ssh2(?:: .*)?\s*$')
    if ($m.Success) {
        $a = Get-Addr $m.Groups[2].Value
        if ($a -eq '') { return $null }
        $kind = if ($m.Groups[1].Value -eq 'Failed password') { 'fail' } else { 'accept' }
        return @{ Kind = $kind; Addr = $a }
    }
    $m = [regex]::Match($line, '^Connection from (\S+) port \d+ on \S+ port (\d+)(?: rdomain .*)?\s*$')
    if ($m.Success) {
        $a = Get-Addr $m.Groups[1].Value
        if ($a -eq '') { return $null }
        return @{ Kind = 'conn'; Addr = $a; Port = [int]$m.Groups[2].Value }
    }
    $m = [regex]::Match($line, '^Server listening on \S+ port (\d+)\.?\s*$')
    if ($m.Success) { return @{ Kind = 'listen'; Port = [int]$m.Groups[1].Value } }
    if ($line -match '^(Disconnected from|Connection closed by|Connection reset by) ') { return @{ Kind = 'end' } }
    return $null
}

function New-State { return @{ Offset = [long]-1; Addrs = @{}; Conns = @{} } }

# ---- WHO WROTE A RECORD (17 Nov 26, SOLO 77: the channel is writable by interactive users) ----------------------
# A "world" is what the guard knows of the processes that write to the channel: @{ Procs = @{ "<pid>" = @{ Pid;
# Parent; Image (full path); Sid; Created (UTC ticks); Exited (UTC ticks; 0 or absent while running) } } - processes
# caught LIVE (the listener); Lives = @{ "<pid>" = @( @{ Pid; Parent; Name (program, no path); Sid; Created; Exited
# } ... ) } - every life of an sshd process the start/stop trace reported, so a reused pid has two; Listener = <the
# Procs entry of the pid that owns port 4251, or $null>; Vc = the cache of verified pids, "<pid>" = @{ Created; Gone
# (UTC ticks: the exit time, or when first seen gone; 0 while alive) } }.  A record that would change the state is
# believed only when the process that had its pid AT THE RECORD'S TIME IS Solo's sshd: the listener itself, or a
# process whose parent is the listener, that started after it and runs Windows' sshd (Test-SoloProcess), and the
# record no later than that process's exit.  Measured on Solo's sshd (OpenSSH_for_Windows 9.5p2), 17 Nov 2026 19:03 and 19:05:
# listener 15772 -> per-connection sshd.exe (parent = the listener; it writes EVERY record of the connection, from
# "Connection from" to "Connection reset") -> its own child sshd.exe (the unprivileged one; it writes none).
$SshdImages = @(foreach ($d in @((Join-Path ([Environment]::SystemDirectory) 'OpenSSH'), (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenSSH'))) {
    foreach ($n in @('sshd.exe', 'sshd-session.exe')) { (Join-Path $d $n).ToLowerInvariant() } })
$VerifiedLife = [long]6000000000   # 10 minutes in ticks: a gone pid's verification is kept this long

$SshdNames = @('sshd.exe', 'sshd-session.exe')

# The listener is caught LIVE (it runs for as long as it listens), so its full image path and account are known.
# A per-connection process is usually known only from the process-start trace, which names its program (not its
# path) and its account: such a life passes when its program is sshd.exe / sshd-session.exe and it runs as the
# LISTENER's account.  The wall in both cases is the parent: only the listener itself can start a process whose
# parent is the listener, and nobody can give a running process another account.
function Test-SoloProcess($p, $listener) {
    if ($null -eq $p -or $null -eq $listener -or -not $listener.Image) { return $false }
    if ($SshdImages -notcontains ([string]$listener.Image).ToLowerInvariant()) { return $false }
    if ($p.Image) {
        if ($SshdImages -notcontains ([string]$p.Image).ToLowerInvariant()) { return $false }
    }
    elseif (-not ($SshdNames -contains ([string]$p.Name).ToLowerInvariant() -and $p.Sid -and $p.Sid -eq $listener.Sid)) { return $false }
    if ($p.Pid -eq $listener.Pid) { return $true }
    return ($p.Parent -eq $listener.Pid -and $p.Created -ge $listener.Created)
}

# The process that wrote $rec: the live entry when the record is no older than it, else the traced life of that
# pid that had started by the record's time (the latest such), else $null.  A record older than every process
# known under its pid has no writer the guard knows.  $TraceSlack: a traced start time may be stamped late (NOT
# MEASURED whether Win32_ProcessStartTrace's TIME_CREATED is the kernel's moment or WMI's), so a life counts as
# started up to that long after the record.
$TraceSlack = [long]20000000   # 2 s in ticks
function Get-Writer($world, $rec) {
    $k = [string]$rec.Pid
    $p = $world.Procs[$k]
    if ($null -ne $p -and ($null -eq $rec.Time -or $rec.Time -ge $p.Created)) { return $p }
    $best = $null
    if ($null -ne $world.Lives -and $world.Lives.ContainsKey($k)) {
        foreach ($l in @($world.Lives[$k])) {
            if ($null -ne $rec.Time -and $l.Created -gt ($rec.Time + $TraceSlack)) { continue }
            if ($null -eq $best -or $l.Created -gt $best.Created) { $best = $l }
        }
    }
    return $best
}

# The records old enough to judge: written no later than $cutoff (UTC ticks), so the trace has had time to deliver
# their writer's start and stop.  The bookmark is put back to just before the first record that is too new, and it
# and every later record are read again on the next pass.  A record with no time (the test hook's) is always ripe.
function Select-Ripe($st, $recs, [long]$cutoff) {
    $out = New-Object System.Collections.ArrayList
    foreach ($r in @($recs)) {
        if ($null -ne $r.Time -and $r.Time -gt $cutoff) { $st.Offset = [long]$r.Id - 1; break }
        [void]$out.Add($r)
    }
    return $out.ToArray()
}

# Every snapshot: a caught Solo sshd process is verified (with its creation time, and its exit time once it has
# exited); a verified pid no longer in the snapshot, or there with another creation time (reused), is marked gone;
# a gone one is forgotten after $VerifiedLife.
function Update-Verified($world, [long]$nowTicks) {
    foreach ($p in @($world.Procs.Values)) {
        $k = [string]$p.Pid
        if (-not (Test-SoloProcess $p $world.Listener)) { continue }
        $c = $world.Vc[$k]
        if ($null -eq $c -or $c.Created -ne $p.Created) { $world.Vc[$k] = @{ Created = $p.Created; Gone = [long]$p.Exited } }
    }
    foreach ($k in @($world.Vc.Keys)) {
        $c = $world.Vc[$k]
        $p = $world.Procs[$k]
        if ($c.Gone -eq 0 -and ($null -eq $p -or $p.Created -ne $c.Created)) { $c.Gone = $nowTicks }
        elseif ($c.Gone -eq 0 -and [long]$p.Exited -gt 0) { $c.Gone = [long]$p.Exited }
        if ($c.Gone -gt 0 -and ($nowTicks - $c.Gone) -gt $VerifiedLife) { $world.Vc.Remove($k) }
    }
}

# One record's writer -> 'ok' (caught, Solo's), 'cached' (verified earlier and the same process), or a reason to
# drop it: 'forged' (caught, not Solo's sshd, or a reused pid), 'unverified' (never caught), 'gone' (written after
# the verified process exited), 'nolistener'.
function Test-RecordProcess($world, $rec) {
    if ($null -eq $world -or $null -eq $world.Listener) { return 'nolistener' }
    $k = [string]$rec.Pid
    $p = Get-Writer $world $rec
    $c = $world.Vc[$k]
    if ($null -ne $p) {
        if (Test-SoloProcess $p $world.Listener) {
            $x = [long]$p.Exited
            if ($x -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $x) { return 'gone' }
            $world.Vc[$k] = @{ Created = $p.Created; Gone = $x }; return 'ok'
        }
        if ($null -ne $c -and $c.Created -eq $p.Created) {
            if ($c.Gone -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $c.Gone) { return 'gone' }
            return 'cached'
        }
        if ($null -ne $c) { $world.Vc.Remove($k) }
        return 'forged'
    }
    if ($null -eq $c) { return 'unverified' }
    if ($null -ne $rec.Time -and $rec.Time -lt $c.Created) { return 'unverified' }
    if ($c.Gone -gt 0 -and $null -ne $rec.Time -and $rec.Time -gt $c.Gone) { return 'gone' }
    return 'cached'
}

# Drops failures older than the window, locks that have ended and connections older than $ConnLife; an address
# with neither failures nor a lock is forgotten.
function Limit-State($st, [long]$now) {
    foreach ($a in @($st.Addrs.Keys)) {
        $e = $st.Addrs[$a]
        $e.Fails = @($e.Fails | Where-Object { ($now - $_) -lt $Window })
        if ($e.Until -le $now) { $e.Until = [long]0 }
        if ($e.Fails.Count -eq 0 -and $e.Until -eq 0) { $st.Addrs.Remove($a) }
    }
    foreach ($p in @($st.Conns.Keys)) {
        if (($now - $st.Conns[$p].Time) -ge $ConnLife) { $st.Conns.Remove($p) }
    }
}

# One counting event against the state -> 'LOCK' (this failure locked the address), 'COUNT' (a failure, not yet a
# lock), 'FORGET' (a sign-in), or ''.
function Add-Event($st, $ev, [long]$now) {
    if ($null -eq $ev) { return '' }
    if ($ev.Kind -eq 'accept') {
        if ($st.Addrs.ContainsKey($ev.Addr)) { $st.Addrs.Remove($ev.Addr) }
        return 'FORGET'
    }
    if ($ev.Kind -ne 'fail') { return '' }
    if (-not $st.Addrs.ContainsKey($ev.Addr)) { $st.Addrs[$ev.Addr] = @{ Fails = @(); Until = [long]0 } }
    $e = $st.Addrs[$ev.Addr]
    $e.Fails = @(@($e.Fails | Where-Object { ($now - $_) -lt $Window }) + $now)
    if ($e.Fails.Count -ge $MaxFails) { $e.Until = $now + $LockFor; return 'LOCK' }
    return 'COUNT'
}

# One channel record (@{ Id; Pid; Provider; Text; Time }) against the state: works out whether it is Solo's sshd's,
# and returns @{ R = <Add-Event's answer, or 'CONN' / 'LISTEN' / 'MISMATCH' / 'DROP' / ''>; Ev = <the event>;
# V = <Test-RecordProcess's answer when dropped> }.  Only a record that would CHANGE the state - a connection or a
# listener start on Solo's port, a failure or sign-in from a Solo connection's pid - has its writer checked, so the
# port-22 sshd's records are never looked at twice; a record that only takes a pid OFF the connections (a closing
# line, a connection on another port) is not checked, because it can only stop the writer's own pid counting.
function Add-Record($st, $rec, [long]$now, $world) {
    $none = @{ R = ''; Ev = $null; V = '' }
    if ($null -eq $rec -or $rec.Provider -ne $Provider -or $null -eq $rec.Pid) { return $none }
    $ev = Get-LineEvent $rec.Text
    if ($null -eq $ev) { return $none }
    $p = [string]$rec.Pid
    switch ($ev.Kind) {
        'conn' {
            if ($ev.Port -eq $SshPort) {
                $v = Test-RecordProcess $world $rec
                if ($v -ne 'ok' -and $v -ne 'cached') { return @{ R = 'DROP'; Ev = $ev; V = $v } }
                $st.Conns[$p] = @{ Addr = $ev.Addr; Time = $now }; return @{ R = 'CONN'; Ev = $ev; V = $v }
            }
            if ($st.Conns.ContainsKey($p)) { $st.Conns.Remove($p) }
            return $none
        }
        'listen' {
            if ($ev.Port -ne $SshPort) { return $none }
            $v = Test-RecordProcess $world $rec
            if ($v -ne 'ok' -and $v -ne 'cached') { return @{ R = 'DROP'; Ev = $ev; V = $v } }
            return @{ R = 'LISTEN'; Ev = $ev; V = $v }
        }
        'end' { if ($st.Conns.ContainsKey($p)) { $st.Conns.Remove($p) }; return $none }
    }
    # 'fail' / 'accept': only from a pid that opened a connection on Solo's port, and only for that socket's address.
    if (-not $st.Conns.ContainsKey($p)) { return $none }
    $v = Test-RecordProcess $world $rec
    if ($v -ne 'ok' -and $v -ne 'cached') { return @{ R = 'DROP'; Ev = $ev; V = $v } }
    if ($st.Conns[$p].Addr -ne $ev.Addr) { return @{ R = 'MISMATCH'; Ev = $ev } }
    if ($ev.Kind -eq 'accept') { $st.Conns.Remove($p) }
    return @{ R = (Add-Event $st $ev $now); Ev = $ev }
}

function Get-LockedAddrs($st, [long]$now) {
    return @($st.Addrs.Keys | Where-Object { $st.Addrs[$_].Until -gt $now } | Sort-Object)
}

# guard.state: "offset <record>" (-1: the source was never read), one "addr <address> <locked-until> <failure
# times...>" line per address, one "conn <pid> <address> <seen>" line per Solo connection in flight.
function Read-State([string]$path) {
    $st = New-State
    if (-not (Test-Path -LiteralPath $path)) { return $st }
    foreach ($l in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $f = @($l.Trim() -split '\s+')
        if ($f.Count -eq 2 -and $f[0] -eq 'offset') { $st.Offset = [long]$f[1] }
        elseif ($f.Count -ge 3 -and $f[0] -eq 'addr') {
            $a = Get-Addr $f[1]
            if ($a -eq '') { continue }
            $st.Addrs[$a] = @{ Until = [long]$f[2]; Fails = @($f | Select-Object -Skip 3 | ForEach-Object { [long]$_ }) }
        }
        elseif ($f.Count -eq 4 -and $f[0] -eq 'conn' -and $f[1] -match '^\d+$') {
            $a = Get-Addr $f[2]
            if ($a -eq '') { continue }
            $st.Conns[$f[1]] = @{ Addr = $a; Time = [long]$f[3] }
        }
    }
    return $st
}

function Write-State($st, [string]$path, [long]$now) {
    Limit-State $st $now
    $out = @('offset ' + $st.Offset)
    foreach ($a in @($st.Addrs.Keys | Sort-Object)) {
        $e = $st.Addrs[$a]
        $out += ('addr ' + $a + ' ' + $e.Until + ' ' + (@($e.Fails) -join ' ')).TrimEnd()
    }
    foreach ($p in @($st.Conns.Keys | Sort-Object)) { $out += ('conn ' + $p + ' ' + $st.Conns[$p].Addr + ' ' + $st.Conns[$p].Time) }
    $tmp = $path + '.tmp'
    [IO.File]::WriteAllLines($tmp, [string[]]$out, (New-Object Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value) } else { [IO.File]::Move($tmp, $path) }
}

# THE SOURCE.  $src is an event channel's name, or "file:<path>" (the test hook's recorded records, one
# "<record> <pid> <message>" per line, provider OpenSSH, no time).  Get-Records returns the records numbered above $after,
# oldest first, at most $max; Get-LastId the newest record's number (0 for an empty source).  A channel that does
# not exist or cannot be read THROWS - a pass that read nothing must never look like a pass that read the source.
function Get-Records([string]$src, [long]$after, [int]$max = 20000) {
    $out = New-Object System.Collections.ArrayList
    if ($src.StartsWith('file:')) {
        $fp = $src.Substring(5)
        if (-not (Test-Path -LiteralPath $fp)) { return @() }
        foreach ($l in @([IO.File]::ReadAllLines($fp))) {
            $m = [regex]::Match($l, '^(\d+) (\d+) (.*)$')
            if ($m.Success -and [long]$m.Groups[1].Value -gt $after -and $out.Count -lt $max) {
                [void]$out.Add(@{ Id = [long]$m.Groups[1].Value; Pid = [int]$m.Groups[2].Value; Provider = 'OpenSSH'; Text = $m.Groups[3].Value; Time = $null })
            }
        }
        return @($out | Sort-Object { $_.Id })
    }
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($src, [System.Diagnostics.Eventing.Reader.PathType]::LogName, ('*[System[EventRecordID > ' + $after + ']]'))
    $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    try {
        while ($out.Count -lt $max) {
            $r = $rd.ReadEvent()
            if ($null -eq $r) { break }
            try {
                $txt = ''
                if ($r.Properties.Count -ge 2) { $txt = [string]$r.Properties[1].Value }
                $tc = $null
                if ($null -ne $r.TimeCreated) { $tc = [long]$r.TimeCreated.ToUniversalTime().Ticks }
                [void]$out.Add(@{ Id = [long]$r.RecordId; Pid = $r.ProcessId; Provider = [string]$r.ProviderName; Text = $txt; Time = $tc })
            } finally { $r.Dispose() }
        }
    } finally { $rd.Dispose() }
    return @($out | Sort-Object { $_.Id })
}

function Get-LastId([string]$src) {
    if ($src.StartsWith('file:')) {
        $ids = @(Get-Records $src ([long]-1) | ForEach-Object { $_.Id })
        if ($ids.Count -eq 0) { return [long]0 }
        return [long]($ids | Measure-Object -Maximum).Maximum
    }
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($src, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
    $q.ReverseDirection = $true
    $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    try {
        $r = $rd.ReadEvent()
        if ($null -eq $r) { return [long]0 }
        try { return [long]$r.RecordId } finally { $r.Dispose() }
    } finally { $rd.Dispose() }
}

# The records added since the state's bookmark.  A first run ($st.Offset -1) starts at the END when $fromEnd (the
# real task: old lines are not counted again, at a time they did not happen); a source whose newest record is
# older than the bookmark was cleared, and is read from its start.
function Read-NewRecords($st, [string]$src, [bool]$fromEnd) {
    $last = Get-LastId $src
    if ($st.Offset -lt 0) { $st.Offset = $(if ($fromEnd) { $last } else { [long]0 }) }
    if ($last -lt $st.Offset) { $st.Offset = [long]0 }
    if ($last -eq $st.Offset) { return @() }
    $recs = @(Get-Records $src $st.Offset)
    if ($recs.Count -gt 0) { $st.Offset = [long]$recs[$recs.Count - 1].Id }
    return $recs
}

function Get-RuleName([string]$addr) { return $RulePrefix + ($addr -replace '[^0-9A-Za-z.]', '-') }
# END sshguard_logic

function Stop-With([string]$m) { Write-Output ('ERROR=' + $m); exit 1 }

function Get-Now {
    if ($TestDir -and $env:SDSOLO_TEST_NOW) { return [long]$env:SDSOLO_TEST_NOW }
    return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Format-Time([long]$t) { return [DateTimeOffset]::FromUnixTimeSeconds($t).ToLocalTime().ToString('HH:mm:ss') }

if (@($Serve, $List, ($Unlock -ne '') | Where-Object { $_ }).Count -ne 1) {
    Stop-With 'give exactly one of -Serve, -List or -Unlock <ADDRESS|all>'
}

# The folder: the admin-only machine folder, from the OS (never from an environment variable), or the test's.
if ($TestDir) { $dir = $TestDir }
else { $dir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SDCoreSolo\ssh' }
if (-not (Test-Path -LiteralPath $dir)) { Stop-With ($dir + ' does not exist: Solo''s ssh is not set up') }
$statePath = Join-Path $dir 'guard.state'
$ownLog = Join-Path $dir 'sshguard.log'
$source = $(if ($TestDir) { 'file:' + (Join-Path $dir 'events.txt') } else { $Channel })

function Test-Elevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Say([string]$m) {
    $line = (Get-Date -Format s) + ' sd-solo-sshguard: ' + $m
    if ($TestDir) { Write-Output $line; return }
    try {
        if ((Test-Path -LiteralPath $ownLog) -and (Get-Item -LiteralPath $ownLog).Length -gt 1MB) { Move-Item -LiteralPath $ownLog -Destination ($ownLog + '.old') -Force }
        [IO.File]::AppendAllText($ownLog, $line + "`r`n")
    } catch { }
}

# Changes to the state are made under one machine-wide lock, so -Unlock and the task cannot lose each other's work.
function Enter-Lock {
    if ($TestDir) { return $null }
    $m = New-Object Threading.Mutex($false, 'Global\SDCoreSoloSshGuard')
    try { [void]$m.WaitOne() } catch [Threading.AbandonedMutexException] { }
    return $m
}
function Exit-Lock($m) { if ($m) { $m.ReleaseMutex(); $m.Dispose() } }

# The block rules match the locked addresses exactly: one per locked address, none for anything else.
function Sync-Rules([string[]]$want) {
    if ($TestDir) { Write-Output ('RULES=' + ($want -join ',')); return }
    $have = @(Get-NetFirewallRule -Name ($RulePrefix + '*') -ErrorAction SilentlyContinue)
    $wantNames = @{}
    foreach ($a in $want) { $wantNames[(Get-RuleName $a)] = $a }
    foreach ($r in $have) {
        if (-not $wantNames.ContainsKey($r.Name)) { Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue; Say ('lock rule removed: ' + $r.Name) }
    }
    foreach ($n in $wantNames.Keys) {
        if (@($have | Where-Object { $_.Name -eq $n }).Count -gt 0) { continue }
        $a = $wantNames[$n]
        $null = New-NetFirewallRule -Name $n -DisplayName ('SD Core Solo ssh lock-out ' + $a) -Group $RuleGroup `
                    -Direction Inbound -Action Block -Protocol TCP -LocalPort $SshPort -RemoteAddress $a -Profile Any -ErrorAction SilentlyContinue
        if (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) { Say ('lock rule made: ' + $n + ' blocks ' + $a + ' on port ' + $SshPort) }
        else { Say ('FAILED to make the lock rule ' + $n + ' for ' + $a) }
    }
}

# Ends the connection(s) from $addr that are open now: the sshd child that holds each, never the listener.
function Stop-Connections([string]$addr) {
    if ($TestDir) { Write-Output ('CUT=' + $addr); return }
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $SshPort -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess })
    $holders = @(Get-NetTCPConnection -State Established -LocalPort $SshPort -RemoteAddress $addr -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess } | Sort-Object -Unique)
    foreach ($p in $holders) {
        if ($listeners -contains $p) { continue }
        $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
        if ($proc -and ($proc.Name -eq 'sshd' -or $proc.Name -eq 'sshd-session')) {
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
            Say ('ended pid ' + $p + ' (' + $proc.Name + '), the connection from ' + $addr)
        }
    }
}

# ---- the world: the processes that write to the channel, caught by SYSTEM (17 Nov 26, SOLO 77) -------------------
# WHY NOT A LISTING (measured 17 Nov 2026 on the installed Solo, 18:51 - 19:05): a per-connection sshd that makes one
# wrong password and is refused LIVES ABOUT 65 ms ("Connection from" 19:05:51.170, "Connection reset" .235; the
# process seen 19:05:51.171 - .233 by a 2 ms Toolhelp loop), while the first build listed sshd every ~105 ms and then
# spent 65 - 95 ms on Get-CimInstance Win32_Process before it could look at the new pid - so every refused connection
# (pids 24044, 20968, 7688, 15824, 15768) was dropped "unverified", and only the 2 s key sign-in of pid 19768 was
# caught.  A listing fast enough to catch them costs ~27% of a core (a Toolhelp snapshot is 4 ms; measured).
# NOR BEING TOLD OF THE RECORD (the second build, installed 17 Nov 19:40, also dropped every refused connection):
# the channel's subscription (EventLogWatcher) delivers a record 250 - 930 ms after it was written, and every time
# the writer had already exited (measured unelevated 17 Nov 19:54, two bare TCP connections to 127.0.0.1:4251, no
# sign-in attempted: delays 552, 251, 933, 933 ms; OpenProcess on the writer in the callback answered 87, "no such
# process", for all four).  ANY DESIGN THAT NEEDS THE WRITER ALIVE WHEN ITS RECORD ARRIVES LOSES THIS RACE.
# SO THE GUARD KEEPS A HISTORY OF THE sshd PROCESSES and judges each record against it by pid AND TIME: SoloSshWatch
# (below) takes Windows' process start and stop trace (WMI Win32_ProcessStartTrace / Win32_ProcessStopTrace, which
# needs an administrator - SYSTEM here), filtered to sshd.exe and sshd-session.exe.  Each start event carries the
# pid, the PARENT pid, the program name, the account (Sid) and the time, captured by the kernel as the process
# starts; each stop event the time it exited.  So a 55 ms process is fully described long after it has gone, and a
# reused pid has two lives, each with its own times.  A record is judged only once it is $TraceGrace old
# (Select-Ripe), so the start and stop events of its writer have had time to arrive; it is then believed only if the
# life of its pid that had started by the record's time is Solo's (Test-SoloProcess) and had not yet exited.  The
# listener is still caught LIVE (Catch: it runs for as long as it listens), which gives its full image path and its
# account, the two things a traced child is compared with.
# -TestDir: from <folder>\procs.txt, "proc <pid> <parent> <created ticks> [exited <ticks> ]<image>" (live) and
# "life <pid> <parent> <created ticks> <exited ticks or 0> <name> <sid>" (traced) and "listener <pid>" lines, read
# fresh on each run; a "sid <pid> <sid>" line gives a live process its account.
$HoldTicks = [long]600000000   # 60 s in ticks: a caught process's handle, or an exited traced life, is kept this long
$TraceGrace = [long]50000000   # 5 s in ticks: a record is judged only when it is this old
# BEGIN sshguard_native  (test-sshguard-units.ps1 compiles this and drives it on its own child process)
$NativeSource = @'
using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public sealed class SoloProcInfo { public int Pid; public int Parent; public string Image; public string Name; public string Sid; public long Created; public long Exited; }
public static class SoloSshWatch {
    [StructLayout(LayoutKind.Sequential)]
    struct PBI { public IntPtr ExitStatus, PebBaseAddress, AffinityMask, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder name, ref uint size);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int infoClass, ref PBI info, int size, out int ret);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    sealed class Entry { public SoloProcInfo I; public IntPtr H; }
    static readonly object Gate = new object();
    static readonly Dictionary<int, Entry> Map = new Dictionary<int, Entry>();
    static readonly Dictionary<int, List<SoloProcInfo>> Lives = new Dictionary<int, List<SoloProcInfo>>();
    static ManagementEventWatcher startW, stopW;
    public const int Cap = 4096;
    public static int Starts, Stops;
    public static string LastError = "";
    public const string Filter = " WHERE ProcessName='sshd.exe' OR ProcessName='sshd-session.exe'";

    // THE TRACE: every sshd start and stop, with the data the kernel captured.  Throws when it cannot subscribe
    // (it needs an administrator).
    public static void StartTrace() {
        var a = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace" + Filter));
        a.EventArrived += OnStart;
        a.Start();
        var b = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace" + Filter));
        b.EventArrived += OnStop;
        try { b.Start(); } catch { a.Stop(); a.Dispose(); throw; }
        startW = a; stopW = b;
    }
    public static void StopTrace() {
        if (startW != null) { startW.Stop(); startW.Dispose(); startW = null; }
        if (stopW != null) { stopW.Stop(); stopW.Dispose(); stopW = null; }
    }
    static long Ticks(object v) { return DateTime.FromFileTimeUtc(Convert.ToInt64(v)).Ticks; }
    static void OnStart(object s, EventArrivedEventArgs e) {
        try {
            var o = e.NewEvent;
            string sid = "";
            var sb = o["Sid"] as byte[];
            if (sb != null && sb.Length > 0) sid = new SecurityIdentifier(sb, 0).Value;
            AddStart(Convert.ToInt32(o["ProcessID"]), Convert.ToInt32(o["ParentProcessID"]), Convert.ToString(o["ProcessName"]), sid, Ticks(o["TIME_CREATED"]));
        } catch (Exception x) { LastError = "start event: " + x.Message; }
    }
    static void OnStop(object s, EventArrivedEventArgs e) {
        try { var o = e.NewEvent; AddStop(Convert.ToInt32(o["ProcessID"]), Ticks(o["TIME_CREATED"])); }
        catch (Exception x) { LastError = "stop event: " + x.Message; }
    }
    // A new life of $pid (the trace's start event).  Public so the guard's test can feed recorded events.
    public static void AddStart(int pid, int parent, string name, string sid, long created) {
        lock (Gate) {
            Starts++;
            List<SoloProcInfo> l;
            if (!Lives.TryGetValue(pid, out l)) { l = new List<SoloProcInfo>(); Lives[pid] = l; }
            l.Add(new SoloProcInfo { Pid = pid, Parent = parent, Image = "", Name = name ?? "", Sid = sid ?? "", Created = created });
            Trim();
        }
    }
    // The latest life of $pid that started by $exited and has no exit yet ends at $exited (the stop event).
    public static void AddStop(int pid, long exited) {
        lock (Gate) {
            Stops++;
            List<SoloProcInfo> l;
            if (!Lives.TryGetValue(pid, out l)) return;
            SoloProcInfo best = null;
            foreach (var i in l) if (i.Exited == 0 && i.Created <= exited && (best == null || i.Created > best.Created)) best = i;
            if (best != null) best.Exited = exited;
        }
    }
    // Copies of every traced life; an exited life older than $holdTicks is forgotten.
    public static SoloProcInfo[] LivesSnapshot(long holdTicks) {
        var o = new List<SoloProcInfo>();
        long now = DateTime.UtcNow.Ticks;
        lock (Gate) {
            var empty = new List<int>();
            foreach (var kv in Lives) {
                kv.Value.RemoveAll(i => i.Exited != 0 && now - i.Exited > holdTicks);
                if (kv.Value.Count == 0) empty.Add(kv.Key);
                foreach (var i in kv.Value) o.Add(new SoloProcInfo { Pid = i.Pid, Parent = i.Parent, Image = "", Name = i.Name, Sid = i.Sid, Created = i.Created, Exited = i.Exited });
            }
            foreach (int p in empty) Lives.Remove(p);
        }
        return o.ToArray();
    }
    // More than Cap lives: the oldest are forgotten (a record of a forgotten life is then dropped - an under-count).
    static void Trim() {
        int n = 0;
        foreach (var l in Lives.Values) n += l.Count;
        while (n > Cap) {
            int op = 0; SoloProcInfo oi = null;
            foreach (var kv in Lives) foreach (var i in kv.Value) if (oi == null || i.Created < oi.Created) { oi = i; op = kv.Key; }
            Lives[op].Remove(oi); if (Lives[op].Count == 0) Lives.Remove(op);
            n--;
        }
    }
    static string TokenSid(IntPtr h) {
        IntPtr t;
        if (!OpenProcessToken(h, 0x0008, out t)) return "";
        try { using (var id = new WindowsIdentity(t)) return id.User == null ? "" : id.User.Value; }
        catch { return ""; }
        finally { CloseHandle(t); }
    }
    // THE LIVE CATCH (the listener): true when it is caught now or was already; false when it cannot be opened.
    public static bool Catch(int pid) {
        if (pid <= 0) return false;
        lock (Gate) {
            if (Map.ContainsKey(pid)) return true;
            if (Map.Count >= Cap) DropExited(0, true);
            if (Map.Count >= Cap) return false;
        }
        IntPtr h = OpenProcess(0x101000, false, pid);
        if (h == IntPtr.Zero) return false;
        var i = new SoloProcInfo { Pid = pid, Image = "", Name = "", Sid = "" };
        long c, x, k, u;
        if (GetProcessTimes(h, out c, out x, out k, out u)) { i.Created = DateTime.FromFileTimeUtc(c).Ticks; if (x != 0 && WaitForSingleObject(h, 0) == 0) i.Exited = DateTime.FromFileTimeUtc(x).Ticks; }
        var sb = new StringBuilder(1024); uint n = (uint)sb.Capacity;
        if (QueryFullProcessImageNameW(h, 0, sb, ref n)) i.Image = sb.ToString(0, (int)n);
        var b = new PBI(); int ret;
        if (NtQueryInformationProcess(h, 0, ref b, Marshal.SizeOf(typeof(PBI)), out ret) == 0) i.Parent = (int)b.InheritedFromUniqueProcessId.ToInt64();
        i.Sid = TokenSid(h);
        if (i.Created == 0) { CloseHandle(h); return false; }
        lock (Gate) {
            if (Map.ContainsKey(pid)) { CloseHandle(h); return true; }
            Map[pid] = new Entry { I = i, H = h };
        }
        return true;
    }
    // Every caught process (copies), with the exit time of those that have exited; a handle held $HoldTicks past its
    // process's exit is closed and the process forgotten.
    public static SoloProcInfo[] Snapshot(long holdTicks) {
        var o = new List<SoloProcInfo>();
        lock (Gate) {
            foreach (var en in Map.Values) {
                // The exit time means something only once the process has exited (signalled).
                if (en.I.Exited == 0 && WaitForSingleObject(en.H, 0) == 0) { long c, x, k, u; if (GetProcessTimes(en.H, out c, out x, out k, out u) && x != 0) en.I.Exited = DateTime.FromFileTimeUtc(x).Ticks; }
            }
            DropExited(holdTicks, false);
            foreach (var en in Map.Values) o.Add(new SoloProcInfo { Pid = en.I.Pid, Parent = en.I.Parent, Image = en.I.Image, Name = "", Sid = en.I.Sid, Created = en.I.Created, Exited = en.I.Exited });
        }
        return o.ToArray();
    }
    static void DropExited(long holdTicks, bool all) {
        long now = DateTime.UtcNow.Ticks;
        var gone = new List<int>();
        foreach (var kv in Map) { if (kv.Value.I.Exited != 0 && (all || now - kv.Value.I.Exited > holdTicks)) gone.Add(kv.Key); }
        foreach (int p in gone) { CloseHandle(Map[p].H); Map.Remove(p); }
    }
}
'@
# END sshguard_native
$script:World = @{ Procs = @{}; Listener = $null; Vc = @{} }
$script:dropSaid = @{}
$script:listenerPids = @()

function Get-NowTicks {
    if ($TestDir -and $env:SDSOLO_TEST_NOW) { return [DateTimeOffset]::FromUnixTimeSeconds([long]$env:SDSOLO_TEST_NOW).UtcTicks }
    return [DateTime]::UtcNow.Ticks
}

# $askPort: also ask which pid owns port 4251 (~90 ms; once a pass).  (Not $listener: that name holds the listener
# below, and a [bool] parameter would turn it into $true.)
function Update-World([bool]$askPort) {
    $procs = @{}
    $lives = @{}
    $lp = @()
    if ($TestDir) {
        $pf = Join-Path $dir 'procs.txt'
        $sids = @{}
        foreach ($l in @(Get-Content -LiteralPath $pf -ErrorAction SilentlyContinue)) {
            $m = [regex]::Match($l, '^proc (\d+) (\d+) (\d+) (?:exited (\d+) )?(.+)$')
            if ($m.Success) {
                $x = $(if ($m.Groups[4].Success) { [long]$m.Groups[4].Value } else { [long]0 })
                $procs[$m.Groups[1].Value] = @{ Pid = [int]$m.Groups[1].Value; Parent = [int]$m.Groups[2].Value; Created = [long]$m.Groups[3].Value; Exited = $x; Image = $m.Groups[5].Value.Trim(); Sid = '' }
            }
            $m = [regex]::Match($l, '^life (\d+) (\d+) (\d+) (\d+) (\S+) (\S+)\s*$')
            if ($m.Success) {
                $k = $m.Groups[1].Value
                if (-not $lives.ContainsKey($k)) { $lives[$k] = @() }
                $lives[$k] += @{ Pid = [int]$k; Parent = [int]$m.Groups[2].Value; Created = [long]$m.Groups[3].Value; Exited = [long]$m.Groups[4].Value; Image = ''; Name = $m.Groups[5].Value; Sid = $m.Groups[6].Value }
            }
            $m = [regex]::Match($l, '^sid (\d+) (\S+)\s*$')
            if ($m.Success) { $sids[$m.Groups[1].Value] = $m.Groups[2].Value }
            $m = [regex]::Match($l, '^listener (\d+)\s*$')
            if ($m.Success) { $lp += $m.Groups[1].Value }
        }
        foreach ($k in $sids.Keys) { if ($procs.ContainsKey($k)) { $procs[$k].Sid = $sids[$k] } }
    }
    else {
        if ($askPort) {
            $script:listenerPids = @(Get-NetTCPConnection -State Listen -LocalPort $SshPort -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.OwningProcess } | Sort-Object -Unique)
            foreach ($x in $script:listenerPids) { $null = [SoloSshWatch]::Catch([int]$x) }
        }
        $lp = $script:listenerPids
        foreach ($i in @([SoloSshWatch]::Snapshot($HoldTicks))) {
            $procs[[string]$i.Pid] = @{ Pid = $i.Pid; Parent = $i.Parent; Image = $i.Image; Sid = $i.Sid; Created = $i.Created; Exited = $i.Exited }
        }
        foreach ($i in @([SoloSshWatch]::LivesSnapshot($HoldTicks))) {
            $k = [string]$i.Pid
            if (-not $lives.ContainsKey($k)) { $lives[$k] = @() }
            $lives[$k] += @{ Pid = $i.Pid; Parent = $i.Parent; Image = ''; Name = $i.Name; Sid = $i.Sid; Created = $i.Created; Exited = $i.Exited }
        }
    }
    $script:World.Lives = $lives
    $lp = @($lp | Sort-Object -Unique)
    $listener = $null
    if ($lp.Count -eq 1 -and $procs.ContainsKey($lp[0])) { $listener = $procs[$lp[0]] }
    elseif ($lp.Count -gt 1 -and -not $script:dropSaid.ContainsKey('listeners')) { $script:dropSaid['listeners'] = 1; Say ('more than one process listens on ' + $SshPort + ' (pid ' + ($lp -join ', ') + '): no record is believed until one does') }
    $script:World.Procs = $procs
    $script:World.Listener = $listener
    Update-Verified $script:World (Get-NowTicks)
}

function Invoke-Pass([bool]$fromEnd) {
    Update-World $true
    $mx = Enter-Lock
    try {
        $now = Get-Now
        $st = Read-State $statePath
        # The task's first pass starts at the END of the source: records written while no guard ran are not
        # counted now, at a time they did not happen.
        if ($fromEnd) { $st.Offset = -1 }
        $cut = @()
        # Only records $TraceGrace old are judged: their writer's start and stop events have had time to arrive.
        $recs = @(Read-NewRecords $st $source $fromEnd)
        $ripe = @(Select-Ripe $st $recs ((Get-NowTicks) - $TraceGrace))
        foreach ($rec in $ripe) {
            $a = Add-Record $st $rec $now $script:World
            $ev = $a.Ev
            if ($a.R -eq 'DROP') {
                $dk = [string]$rec.Pid
                if ($script:dropSaid.Count -gt 1000) { $script:dropSaid = @{} }
                if (-not $script:dropSaid.ContainsKey($dk)) {
                    $script:dropSaid[$dk] = 1
                    $tr = $(if ($TestDir) { '' } else { ', trace starts ' + [SoloSshWatch]::Starts + ' stops ' + [SoloSshWatch]::Stops })
                    Say ('unverified record from pid ' + $rec.Pid + ' dropped (' + $a.V + ', listener pid ' + $(if ($script:World.Listener) { $script:World.Listener.Pid } else { 'none' }) + $tr + '): ' + $rec.Text)
                }
            }
            elseif ($a.R -eq 'LOCK') {
                Say ('locking ' + $ev.Addr + ' for ' + ($LockFor / 60) + ' minutes: ' + $MaxFails + ' wrong passwords within ' + ($Window / 60) + ' minutes')
                $cut += $ev.Addr
            }
            elseif ($a.R -eq 'COUNT') { Say ('a wrong password from ' + $ev.Addr + ' (pid ' + $rec.Pid + ')') }
            elseif ($a.R -eq 'FORGET') { Say ('a sign-in from ' + $ev.Addr + ': its failures are forgotten') }
            elseif ($a.R -eq 'LISTEN') { Say ('Solo''s sshd is listening: pid ' + $rec.Pid + ' (' + $rec.Text + ')') }
            elseif ($a.R -eq 'MISMATCH') { Say ('NOT counted: pid ' + $rec.Pid + ' wrote "' + $rec.Text + '" for a connection from ' + $st.Conns[[string]$rec.Pid].Addr) }
        }
        Write-State $st $statePath $now
        $locked = Get-LockedAddrs $st $now
    } finally { Exit-Lock $mx }
    if (-not $script:readOnce) { $script:readOnce = $true; Say ('watching ' + $source + ': ok, from record ' + $st.Offset) }
    # The firewall is asked only when the locked set changed, or once a minute (a rule removed by hand comes back).
    $key = ($locked -join ',')
    if ($TestDir -or $key -ne $script:lastKey -or ($now - $script:lastSync) -ge 60) {
        Sync-Rules $locked
        $script:lastKey = $key; $script:lastSync = $now
    }
    foreach ($x in ($cut | Sort-Object -Unique)) { Stop-Connections $x }
}
$script:lastKey = $null; $script:lastSync = [long]0; $script:readOnce = $false

if ($List) {
    $now = Get-Now
    $st = Read-State $statePath
    Limit-State $st $now
    if ($st.Offset -lt 0) { Write-Output ('source ' + $source + ': NEVER READ (guard.state offset -1, or no guard.state)') }
    else { Write-Output ('source ' + $source + ': read up to record ' + $st.Offset + ', ' + $st.Conns.Count + ' Solo connection(s) in flight') }
    $n = 0
    foreach ($a in @($st.Addrs.Keys | Sort-Object)) {
        $e = $st.Addrs[$a]
        if ($e.Until -gt $now) { $n++; Write-Output ($a + '  LOCKED until ' + (Format-Time $e.Until) + '  (' + @($e.Fails).Count + ' wrong passwords)') }
        else { Write-Output ($a + '  ' + @($e.Fails).Count + ' wrong password(s), not locked') }
    }
    Write-Output ('SOLO SSH GUARD LOCKED ' + $n)
    exit 0
}

if ($Unlock -ne '') {
    if (-not $TestDir -and -not (Test-Elevated)) { Stop-With 'this needs an ELEVATED PowerShell - the lock-out state and its firewall rules are the administrator''s' }
    $target = $Unlock
    if ($target -ne 'all') {
        $target = Get-Addr $target
        if ($target -eq '') { Stop-With ('not an address: ' + $Unlock + ' (give an IP address, or all)') }
    }
    $mx = Enter-Lock
    try {
        $now = Get-Now
        $st = Read-State $statePath
        Limit-State $st $now
        if ($target -eq 'all') { $n = $st.Addrs.Count; $st.Addrs = @{} }
        elseif ($st.Addrs.ContainsKey($target)) { $st.Addrs.Remove($target); $n = 1 }
        else { $n = 0 }
        Write-State $st $statePath $now
        $locked = Get-LockedAddrs $st $now
    } finally { Exit-Lock $mx }
    Sync-Rules $locked
    if ($n -gt 0) { Say ('unlocked ' + $target + ' by hand') }
    Write-Output ('SOLO SSH GUARD UNLOCKED ' + $n)
    exit 0
}

# -Serve.  The task's: a pass every two seconds, for as long as it runs.  With -TestDir: one pass, the source
# read from its start.
if ($TestDir) { Invoke-Pass $false; exit 0 }
Say ('started: watching ' + $source + ' for Solo''s sshd on port ' + $SshPort + ' (' + $MaxFails + ' wrong passwords in ' + ($Window / 60) + ' minutes lock an address for ' + ($LockFor / 60) + ' minutes)')
# The watcher's code is compiled with TEMP pointed at the admin-only machine folder, so the C# source and the
# compiled DLL are never in a folder a user can write to (C:\Windows\Temp lets users create files).
$env:TMP = $dir; $env:TEMP = $dir
try {
    if (-not ('SoloSshWatch' -as [type])) { Add-Type -TypeDefinition $NativeSource -ReferencedAssemblies 'System.Management' -ErrorAction Stop }
} catch { Say ('process watch: cannot compile (' + $_.Exception.Message + '): no record can be verified'); exit 1 }
try {
    [SoloSshWatch]::StartTrace()
    Say 'process trace: subscribed to Win32_ProcessStartTrace and Win32_ProcessStopTrace for sshd.exe and sshd-session.exe'
} catch {
    Say ('process trace FAILED: ' + $_.Exception.Message + ' - only the listener''s own records can be verified; every connection''s are dropped')
}
$first = $true
$saidErr = ''
while ($true) {
    try { Invoke-Pass $first; $first = $false } catch { Say ('pass failed: ' + $_.Exception.Message) }
    $we = [SoloSshWatch]::LastError
    if ($we -and $we -ne $saidErr) { $saidErr = $we; Say ('process trace: ' + $we) }
    Start-Sleep -Milliseconds 2000
}
