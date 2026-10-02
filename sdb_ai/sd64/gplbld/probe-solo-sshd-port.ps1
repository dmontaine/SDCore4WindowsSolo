# probe-solo-sshd-port.ps1 - can Win32-OpenSSH run a SECOND sshd, as the ordinary
# (unelevated) installing user, on its own port, and log that user in by key with a
# ForceCommand?  Linux asked (mail T3320, Q1-Q2); this is the Windows measurement.
#
#   powershell -ExecutionPolicy Bypass -File <this file>        ORDINARY UNELEVATED prompt
#
# LOOPBACK ONLY, SCRATCH ONLY (a folder under %TEMP%): it does not read or write the live
# sshd_config, touch the sshd service, or touch any firewall rule.  It starts one sshd it
# created itself, kills exactly that process and its children, and checks the port is
# closed afterwards.  It REFUSES an elevated shell: that is a different measurement.
#
# MEASURED 2 Oct 2026, OpenSSH_for_Windows_9.5p2, ordinary user ace\Don, port 4251:
# the private sshd listened, key login for that user was Accepted, ForceCommand (whoami as a
# stand-in) ran as ace\don and exited 0, a stranger key was refused (exit 255), the system
# sshd on 22 was untouched (listeners 2 before and after), known_hosts keyed [127.0.0.1]:4251.
# NOT measured: a login as a DIFFERENT user than the one running this sshd (the 14 Aug
# trap in PROJECT_STATUS 6 - "sshd must run as SYSTEM to build a user token" - is too broad:
# it does not hold for key login of the user who started it), a non-loopback bind, a
# firewall rule, a logon-task start, StrictModes yes, and a real sd-solo.exe as the command.
#
# Two traps this script already paid for: native stderr under $ErrorActionPreference
# 'Stop', and a function that both prints and returns (see the comments below).
# 'Continue', NOT 'Stop': under Stop, Windows PowerShell 5.1 turns a native command's
# stderr (ssh -V prints its version there) into a terminating error even on success -
# PROJECT_STATUS 6, "never redirect native stderr inline".  Every native call below is
# checked by its own exit code and output instead.
$ErrorActionPreference = 'Continue'
$ssh   = Join-Path $env:SystemRoot 'System32\OpenSSH'
$sshd  = Join-Path $ssh 'sshd.exe'
$keygn = Join-Path $ssh 'ssh-keygen.exe'
$sshc  = Join-Path $ssh 'ssh.exe'
foreach ($f in @($sshd, $keygn, $sshc)) { if (-not (Test-Path $f)) { Write-Output "REFUSED: not found: $f"; exit 2 } }

# ---- 0. the real inputs -----------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elev = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output ("user={0}  elevated(admin role enabled in this token)={1}" -f $id.Name, $elev)
if ($elev) { Write-Output 'REFUSED: this measures the UNELEVATED case; run it from an ordinary prompt.'; exit 2 }
Write-Output ("ssh -V: " + ((& $sshc -V 2>&1 | ForEach-Object { "$_" }) -join ' '))
$sysd = Get-Service -Name sshd -ErrorAction SilentlyContinue
Write-Output ("system sshd service: " + $(if ($sysd) { $sysd.Status } else { 'not installed' }))
$l22 = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)
Write-Output ("listeners on 22 before: " + $l22.Count)

# ---- 1. are the fixed port numbers usable on THIS Windows? -------------------------
$ex = & netsh int ipv4 show excludedportrange protocol=tcp 2>&1 | ForEach-Object { "$_" }
$ranges = @()
foreach ($line in $ex) { if ($line -match '^\s*(\d+)\s+(\d+)') { $ranges += ,@([int]$Matches[1], [int]$Matches[2]) } }
Write-Output ("excluded TCP port ranges read: " + $ranges.Count)
foreach ($p in @(4247, 4249, 4251)) {
    $hit = @($ranges | Where-Object { $p -ge $_[0] -and $p -le $_[1] })
    $busy = @(Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue).Count
    Write-Output ("  port {0}: inside an excluded range={1}  already in use={2}" -f $p, ($hit.Count -gt 0), ($busy -gt 0))
}
$port = 4251
if (@($ranges | Where-Object { $port -ge $_[0] -and $port -le $_[1] }).Count -gt 0 -or @(Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0) { $port = 24251 }
Write-Output "port used for the test: $port"

# ---- 2. scratch material ----------------------------------------------------------
$scratch = Join-Path $env:TEMP 'sshd-solo-port'
if ($scratch -notmatch '[\\/]sshd-solo-port$') { Write-Output "REFUSED: unexpected scratch path '$scratch'"; exit 2 }
if (Test-Path $scratch) { Remove-Item -Recurse -Force $scratch }
New-Item -ItemType Directory -Force $scratch | Out-Null
$hostkey = Join-Path $scratch 'hostkey'
$ukey    = Join-Path $scratch 'userkey'
$skey    = Join-Path $scratch 'strangerkey'
foreach ($k in @($hostkey, $ukey, $skey)) { & $keygn -q -t ed25519 -N '""' -f $k | Out-Null; if (-not (Test-Path $k)) { Write-Output "REFUSED: no key made: $k"; exit 2 } }
$ak = Join-Path $scratch 'authorized_keys'
[IO.File]::WriteAllText($ak, ((Get-Content ($ukey + '.pub') -Raw).Trim() + "`n"), (New-Object Text.UTF8Encoding $false))
$log = Join-Path $scratch 'sshd.log'
$cfg = Join-Path $scratch 'sshd_config'
$fwd = { param($p) ($p -replace '\\', '/') }
$cfgText = @(
    "Port $port", 'ListenAddress 127.0.0.1',
    ('HostKey ' + (& $fwd $hostkey)),
    'PasswordAuthentication no', 'PubkeyAuthentication yes', 'StrictModes no',
    ('AuthorizedKeysFile ' + (& $fwd $ak)),
    ('PidFile ' + (& $fwd (Join-Path $scratch 'sshd.pid'))),
    'LogLevel DEBUG1',
    ('AllowUsers ' + $env:USERNAME),
    ('ForceCommand "' + (Join-Path $env:SystemRoot 'System32\whoami.exe') + '"')
) -join "`n"
[IO.File]::WriteAllText($cfg, $cfgText + "`n", (New-Object Text.UTF8Encoding $false))
Write-Output ('--- the private sshd_config:' + "`n" + $cfgText)
$t = & $sshd -t -f $cfg 2>&1 | ForEach-Object { "$_" }
Write-Output ("sshd -t on it: exit=$LASTEXITCODE " + ($t -join ' '))

# ---- 3. start it unelevated, try the logins ---------------------------------------
$before = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'sshd*' } | ForEach-Object { $_.Id })
Write-Output ("sshd* pids before: " + ($before -join ','))
$srv = $null
try {
    $srv = Start-Process -FilePath $sshd -ArgumentList @('-D', '-f', $cfg, '-E', $log) -PassThru -WindowStyle Hidden
    $up = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        if (@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0) { $up = $true; break }
        if ($srv.HasExited) { break }
    }
    Write-Output ("sshd started pid={0} listening on {1}={2} exited={3}" -f $srv.Id, $port, $up, $srv.HasExited)
    if (-not $up) {
        Write-Output 'NO MEASUREMENT of a login: the private sshd never listened. Its log:'
        if (Test-Path $log) { Get-Content $log -Tail 12 | ForEach-Object { Write-Output ("  " + $_) } }
    } else {
        $empty = Join-Path $scratch 'empty.txt'; [IO.File]::WriteAllText($empty, '')
        function Try-Login([string]$label, [string]$key) {
            $o = Join-Path $scratch ('out-' + $label + '.txt'); $e = Join-Path $scratch ('err-' + $label + '.txt')
            $args2 = @('-i', $key, '-p', "$port", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                       '-o', ('UserKnownHostsFile=' + (Join-Path $scratch 'known_hosts')), '-o', 'IdentitiesOnly=yes',
                       '-o', 'ConnectTimeout=10', ($env:USERNAME + '@127.0.0.1'), 'sd-solo')
            # Write-Host, NOT Write-Output, in here: a function that prints with Write-Output
            # AND returns a value folds the printed lines into the return value (the
            # caller got System.Object[] and the screen got nothing) - memory
            # ps-function-output-trap, third occurrence.  Only the exit code is returned.
            Write-Host ("  ssh " + ($args2 -join ' '))
            $p = Start-Process -FilePath $sshc -ArgumentList $args2 -PassThru -Wait -NoNewWindow `
                 -RedirectStandardOutput $o -RedirectStandardError $e -RedirectStandardInput $empty
            Write-Host ("  [$label] exit=" + $p.ExitCode)
            Write-Host ("  [$label] stdout: " + ((Get-Content $o -ErrorAction SilentlyContinue) -join ' | '))
            Write-Host ("  [$label] stderr: " + ((Get-Content $e -ErrorAction SilentlyContinue) -join ' | '))
            return [int]$p.ExitCode
        }
        Write-Output '=== login with the AUTHORISED key'
        $rc1 = Try-Login 'authorised' $ukey
        Write-Output '=== control: login with a STRANGER key (must be refused, or the first result proves nothing)'
        $rc2 = Try-Login 'stranger' $skey
        Write-Output ("RESULT authorised exit={0}  stranger exit={1}" -f $rc1, $rc2)
        $kh = Join-Path $scratch 'known_hosts'
        if (Test-Path $kh) { Write-Output ('known_hosts line shape: ' + ((Get-Content $kh | ForEach-Object { ($_ -split ' ')[0] }) -join ' ')) }
    }
}
finally {
    if ($srv -and -not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 800
    $after = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'sshd*' } | ForEach-Object { $_.Id })
    $stray = @($after | Where-Object { $before -notcontains $_ })
    foreach ($s in $stray) { Stop-Process -Id $s -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    $still = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count
    Write-Output ("cleanup: stray sshd* pids killed=" + ($stray -join ',') + "  port $port still listening=" + ($still -gt 0))
    $l22b = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)
    Write-Output ("listeners on 22 after: " + $l22b.Count + " (before: " + $l22.Count + ")")
}
Write-Output '--- decisive lines of the private sshd log:'
if (Test-Path $log) {
    Get-Content $log | Where-Object { $_ -match '(?i)accepted|failed|logon|fatal|error|not allowed|privilege|token|session|authenticat|refus|denied|force' } |
        Select-Object -First 25 | ForEach-Object { Write-Output ("  " + $_) }
} else { Write-Output '  (no log was written)' }
