# solo-sshguard.ps1 - the lockout in front of SD Core Solo's own sshd (port 4251).  From Linux Solo's
# gplbld/solo-sshguard.py (LSOLO 29; the owner, 2 Oct 2026, asked for the lockout), carried 17 Nov 2026 in the
# four-version audit (decision D1: "a feature parity needs; it tightens, so nothing ships looser").
#
#   -Serve                  (the SYSTEM task "SD Core Solo SSH Guard")  watch sshd.log and keep the lock rules
#   -List                   (anyone)    who is locked, who has failures
#   -Unlock <ADDRESS|all>   (ELEVATED)  forget one address, or every address, and take its lock rule away
# All with: powershell -NoProfile -ExecutionPolicy Bypass -File "%ProgramData%\SDCoreSolo\ssh\solo-sshguard.ps1" <switch>
#
# THE RULE, Linux Solo's, word for word: PER ADDRESS.  Three wrong passwords from one address within ten minutes,
# and that address is refused for ten minutes.  Only a failed PASSWORD counts (a client offering keys the server
# does not know fails publickey over and over and must not be punished for it).  A sign-in forgets that address's
# failures.  The Windows account is never locked by this, and the computer's own sshd (port 22) is not touched.
#
# THE MECHANISM, WINDOWS' (the OS decides it; one line for the record): a SYSTEM task tails the log Solo's sshd
# writes (-E %ProgramData%\SDCoreSolo\ssh\sshd.log, LogLevel INFO), counts "Failed password for ... from <addr>"
# per address, and refuses a locked address with a Windows Firewall BLOCK rule on port 4251 for that address alone
# (named SD-Solo-SSH-Guard-<addr>, group "SD Core Solo ssh lock-out"), removed when the ten minutes are up; the
# connection that made the third wrong try is ended by stopping the sshd child that holds it.  Linux runs the guard
# per connection in front of sshd (systemd socket activation, the address from the socket); Windows' sshd has no
# per-connection launcher, so the address is read from sshd's own log line, anchored on the END of the line, where
# sshd puts the peer address after the user name (a user name cannot move the address a lock is put on).
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
#
# NOT MEASURED (written 17 Nov 2026, nothing here has run against a real sshd or the real firewall - the guard
# test-sshguard-units.ps1 drives the logic on recorded log lines): the exact prefix Windows' sshd puts before each
# line in a -E log (the match allows a prefix of digits, dates, times and an "sshd...:" tag, and nothing else); that
# OpenSSH's sshd-session.exe children log to the same file; that the block rule refuses a NEW connection from the
# address; that stopping the child that owns the established connection ends only that connection.
#
# OUTPUT: -List ends "SOLO SSH GUARD LOCKED <n>", -Unlock ends "SOLO SSH GUARD UNLOCKED <n>" (Linux's words); a
# refusal is "ERROR=<text>", exit 1.  TEST HOOK, NOT A FEATURE: -TestDir <folder> uses that folder for the log and
# the state, honours SDSOLO_TEST_NOW (seconds since 1970) as the clock, makes -Serve do ONE pass, and never touches
# the firewall, a process or the machine folder; a real task never passes it.

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
$SshPort = 4251      # SOLO_SSH_PORT - solo-sshd.ps1 carries the same number
$RulePrefix = 'SD-Solo-SSH-Guard-'
$RuleGroup = 'SD Core Solo ssh lock-out'

# One sshd log line -> $null, or @{ Kind = 'fail' | 'accept'; Addr = <address> }.  The line may carry a prefix
# of digits, dates and times (a pid, a time stamp) and an "sshd...:" tag; the message must START after it, so a
# user name that contains the words cannot make another message count.  The address is the LAST
# "from <addr> port <n> ssh2" - the one sshd appends (a key sign-in adds ": <key type> <fingerprint>" after it) -
# and must parse as an IP address.
function Get-LineEvent([string]$line) {
    $m = [regex]::Match($line, '^[0-9 :./T+-]*(?:sshd[^ :]*:\s*)?(Failed password|Accepted \S+) for .* from (\S+) port \d+ ssh2(?:: .*)?\s*$')
    if (-not $m.Success) { return $null }
    $a = $m.Groups[2].Value
    if ($a.StartsWith('::ffff:')) { $a = $a.Substring(7) }
    $a = ($a -split '%')[0]
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($a, [ref]$ip)) { return $null }
    $kind = if ($m.Groups[1].Value -eq 'Failed password') { 'fail' } else { 'accept' }
    return @{ Kind = $kind; Addr = $ip.ToString() }
}

function New-State { return @{ Offset = [long]-1; Addrs = @{} } }

# Drops failures older than the window and locks that have ended; an address with neither is forgotten.
function Limit-State($st, [long]$now) {
    foreach ($a in @($st.Addrs.Keys)) {
        $e = $st.Addrs[$a]
        $e.Fails = @($e.Fails | Where-Object { ($now - $_) -lt $Window })
        if ($e.Until -le $now) { $e.Until = [long]0 }
        if ($e.Fails.Count -eq 0 -and $e.Until -eq 0) { $st.Addrs.Remove($a) }
    }
}

# One event against the state -> 'LOCK' (this failure locked the address), 'COUNT' (a failure, not yet a lock),
# 'FORGET' (a sign-in), or ''.
function Add-Event($st, $ev, [long]$now) {
    if ($null -eq $ev) { return '' }
    if ($ev.Kind -eq 'accept') {
        if ($st.Addrs.ContainsKey($ev.Addr)) { $st.Addrs.Remove($ev.Addr) }
        return 'FORGET'
    }
    if (-not $st.Addrs.ContainsKey($ev.Addr)) { $st.Addrs[$ev.Addr] = @{ Fails = @(); Until = [long]0 } }
    $e = $st.Addrs[$ev.Addr]
    $e.Fails = @(@($e.Fails | Where-Object { ($now - $_) -lt $Window }) + $now)
    if ($e.Fails.Count -ge $MaxFails) { $e.Until = $now + $LockFor; return 'LOCK' }
    return 'COUNT'
}

function Get-LockedAddrs($st, [long]$now) {
    return @($st.Addrs.Keys | Where-Object { $st.Addrs[$_].Until -gt $now } | Sort-Object)
}

# guard.state: "offset <n>" then one "addr <address> <locked-until> <failure times...>" line per address.
function Read-State([string]$path) {
    $st = New-State
    if (-not (Test-Path -LiteralPath $path)) { return $st }
    foreach ($l in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $f = @($l.Trim() -split '\s+')
        if ($f.Count -eq 2 -and $f[0] -eq 'offset') { $st.Offset = [long]$f[1] }
        elseif ($f.Count -ge 3 -and $f[0] -eq 'addr') {
            $ip = $null
            if (-not [Net.IPAddress]::TryParse($f[1], [ref]$ip)) { continue }
            $st.Addrs[$ip.ToString()] = @{ Until = [long]$f[2]; Fails = @($f | Select-Object -Skip 3 | ForEach-Object { [long]$_ }) }
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
    $tmp = $path + '.tmp'
    [IO.File]::WriteAllLines($tmp, [string[]]$out, (New-Object Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value) } else { [IO.File]::Move($tmp, $path) }
}

# The complete lines added to the log since the state's offset.  A first run ($st.Offset -1) starts at the END
# when $fromEnd (the real task: old failures are not counted again); a log shorter than the offset was replaced,
# and is read from its start.  An incomplete last line is left for the next pass.
function Read-NewLines($st, [string]$log, [bool]$fromEnd) {
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $len = $fs.Length
        if ($st.Offset -lt 0) { $st.Offset = $(if ($fromEnd) { $len } else { 0 }) }
        if ($len -lt $st.Offset) { $st.Offset = 0 }
        if ($len -eq $st.Offset) { return @() }
        $fs.Position = $st.Offset
        $buf = New-Object byte[] ($len - $st.Offset)
        $n = $fs.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return @() }
        $last = [Array]::LastIndexOf($buf, [byte]10, $n - 1)
        if ($last -lt 0) { return @() }
        $st.Offset += ($last + 1)
        return @([Text.Encoding]::UTF8.GetString($buf, 0, $last + 1) -split "`r?`n" | Where-Object { $_ -ne '' })
    } finally { $fs.Dispose() }
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
$logPath = Join-Path $dir 'sshd.log'
$ownLog = Join-Path $dir 'sshguard.log'

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

function Invoke-Pass([bool]$fromEnd) {
    $mx = Enter-Lock
    try {
        $now = Get-Now
        $st = Read-State $statePath
        # The task's first pass starts at the END of the log: lines written while no guard ran are not counted
        # now, at a time they did not happen.
        if ($fromEnd) { $st.Offset = -1 }
        $cut = @()
        foreach ($l in (Read-NewLines $st $logPath $fromEnd)) {
            $ev = Get-LineEvent $l
            $r = Add-Event $st $ev $now
            if ($r -eq 'LOCK') {
                Say ('locking ' + $ev.Addr + ' for ' + ($LockFor / 60) + ' minutes: ' + $MaxFails + ' wrong passwords within ' + ($Window / 60) + ' minutes')
                $cut += $ev.Addr
            }
            elseif ($r -eq 'FORGET') { Say ('a sign-in from ' + $ev.Addr + ': its failures are forgotten') }
        }
        Write-State $st $statePath $now
        $locked = Get-LockedAddrs $st $now
    } finally { Exit-Lock $mx }
    # The firewall is asked only when the locked set changed, or once a minute (a rule removed by hand comes back).
    $key = ($locked -join ',')
    if ($TestDir -or $key -ne $script:lastKey -or ($now - $script:lastSync) -ge 60) {
        Sync-Rules $locked
        $script:lastKey = $key; $script:lastSync = $now
    }
    foreach ($a in ($cut | Sort-Object -Unique)) { Stop-Connections $a }
}
$script:lastKey = $null; $script:lastSync = [long]0

if ($List) {
    $now = Get-Now
    $st = Read-State $statePath
    Limit-State $st $now
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
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($target, [ref]$ip)) { Stop-With ('not an address: ' + $target + ' (give an IP address, or all)') }
        $target = $ip.ToString()
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

# -Serve.  The task's: a pass every two seconds, for as long as it runs.  With -TestDir: one pass, the log read
# from its start.
if ($TestDir) { Invoke-Pass $false; exit 0 }
Say ('started: watching ' + $logPath + ' (' + $MaxFails + ' wrong passwords in ' + ($Window / 60) + ' minutes lock an address for ' + ($LockFor / 60) + ' minutes)')
$first = $true
while ($true) {
    try { Invoke-Pass $first; $first = $false } catch { Say ('pass failed: ' + $_.Exception.Message) }
    Start-Sleep -Seconds 2
}
