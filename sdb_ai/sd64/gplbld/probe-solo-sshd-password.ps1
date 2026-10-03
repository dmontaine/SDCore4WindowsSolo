# probe-solo-sshd-password.ps1 - can a PER-USER sshd (no admin, not SYSTEM) accept a WINDOWS PASSWORD?  SOLO 28.
#
#   powershell -ExecutionPolicy Bypass -File <repo>\sdb_ai\sd64\gplbld\probe-solo-sshd-password.ps1            the real measurement
#   powershell -ExecutionPolicy Bypass -File <repo>\sdb_ai\sd64\gplbld\probe-solo-sshd-password.ps1 -Control   a refused try, no real password
#
# Run from an ORDINARY UNELEVATED PowerShell (it refuses an elevated one: an elevated sshd would measure
# something else).  Touches nothing of Solo's: a scratch folder under %TEMP%, its own host key, port 4252,
# bound to 127.0.0.1 only - no firewall rule, nothing reachable from the network.
#
# WHY IT EXISTS.  The owner (2 Oct 2026): ssh to Solo "is supposed to require account name and password, not a
# shared key".  Solo's sshd is a per-user process so that it needs no administrator, and a KEY login was
# measured to work there.  Whether such a process can check a Windows PASSWORD is NOT measured - the system
# sshd could because it runs as SYSTEM.  Nobody may type the owner's password into a test that an agent can
# see, so THIS SCRIPT NEVER SEES IT: the owner types it at ssh's own prompt in a second window, and the script
# reads only the server's log, which does not carry a password.
#
# WHAT IT DOES: makes a scratch sshd_config (Port 4252, ListenAddress 127.0.0.1, PasswordAuthentication yes,
# AuthenticationMethods password, AllowUsers <you>, ForceCommand whoami, LogLevel DEBUG2), starts sshd as a
# hidden child, prints the one ssh command to type, waits (Enter, or the time limit), stops ITS OWN sshd by the
# pid it started (never by name), and prints the log lines that decide it.
#   ACCEPTED   "Accepted password for <you>" AND no session-start failure in the log - a per-user sshd can
#              give a password login a session.  The ssh window should also have printed your account name.
#   PASSWORD CHECKED, SESSION NOT STARTED   "Accepted password" followed by "CreateProcessAsUserW failed
#              error:1314" - the password is checked but the session cannot start.  THIS WAS THE FIRST REAL
#              RESULT (owner, 2 Oct 2026 21:11); the ssh window said "Connection reset".
#   -EvaluateLog <file>   print only the verdict for a saved server log (used to test the verdict itself).
#   REFUSED    "Failed password" and no "Accepted" - wrong password typed, OR the server cannot check it; the
#              log lines below it say which kind of failure it logged.
#   NO ATTEMPT no password attempt reached the server.
# -Control makes ONE ssh try itself with a made-up string through SSH_ASKPASS, to show the log does record a
# refusal.  It is one failed logon against your account (the lockout threshold here is 10 in 10 minutes).
#
# Exit 0 = ran to a verdict (ACCEPTED or REFUSED printed), 1 = NO ATTEMPT, 2 = could not run.

param(
    [switch]$Control,
    [int]$Port = 4252,
    [int]$WaitSeconds = 300,
    [string]$EvaluateLog = ''     # read a saved server log and print only the verdict - no sshd, no ssh
)

$ErrorActionPreference = 'Continue'

function Say([string]$s) { Write-Host $s }
function Quit([string]$why, [int]$code) { Say ('COULD NOT RUN: ' + $why); exit $code }

# THE VERDICT, from the server log alone.  "Accepted password" is NOT "let the user in": the first real
# run (owner, 2 Oct 2026 21:11) logged "Accepted password for don" and then "CreateProcessAsUserW failed
# error:1314 / fork of unprivileged child failed", and the ssh window said "Connection reset".  So the
# session-start failure is looked for separately, and "ACCEPTED" is only claimed when none was logged.
function Write-Verdict([string[]]$lines) {
    $accepted = @($lines | Where-Object { $_ -match '(?i)Accepted password for ' }).Count
    $failed = @($lines | Where-Object { $_ -match '(?i)Failed password for ' }).Count
    $startFail = @($lines | Where-Object { $_ -match 'CreateProcessAsUserW failed|fork of unprivileged child failed' })
    Say ''
    Say ('counts: Accepted password = ' + $accepted + '   Failed password = ' + $failed + '   session-start failures = ' + $startFail.Count)
    if ($accepted -gt 0 -and $startFail.Count -gt 0) {
        Say ('VERDICT: PASSWORD CHECKED, SESSION NOT STARTED - sshd ACCEPTED the Windows password, so a per-user sshd CAN check it, but then failed to start the session: ' + (($startFail | Select-Object -First 2) -join ' / '))
        Say '         error 1314 = ERROR_PRIVILEGE_NOT_HELD: the process lacks the privilege to start a process under the logon token the password check made.'
        Say '         So a per-user sshd, no administrator and not SYSTEM, CANNOT give a PASSWORD login a session (a KEY login can - it uses the sshd''s own token).'
        return 0
    }
    if ($accepted -gt 0) { Say 'VERDICT: ACCEPTED - the password was accepted and no session-start failure was logged.  Confirm the ssh window printed your account name (the forced command is whoami).'; return 0 }
    if ($failed -gt 0) { Say 'VERDICT: REFUSED - the password was refused.  If it was typed right, read the log lines above for the kind of failure.'; return 0 }
    Say 'VERDICT: NO ATTEMPT - no password attempt reached the probe sshd.'
    return 1
}

if ($EvaluateLog -ne '') {
    if (-not (Test-Path -LiteralPath $EvaluateLog)) { Quit ('no such log: ' + $EvaluateLog) 2 }
    $evl = @(Get-Content -LiteralPath $EvaluateLog)
    Say ('evaluating ' + $EvaluateLog + ': ' + $evl.Count + ' lines')
    $evc = Write-Verdict $evl
    exit $evc
}

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Quit 'this is ELEVATED - run it from an ordinary unelevated PowerShell' 2
}
$ossh = Join-Path $env:SystemRoot 'System32\OpenSSH'
$sshd = Join-Path $ossh 'sshd.exe'; $keygen = Join-Path $ossh 'ssh-keygen.exe'; $ssh = Join-Path $ossh 'ssh.exe'
foreach ($f in @($sshd, $keygen, $ssh)) { if (-not (Test-Path -LiteralPath $f)) { Quit ('missing ' + $f) 2 } }
if (@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue).Count -gt 0) { Quit ('port ' + $Port + ' is already in use') 2 }

# The name sshd matches this user by - the same rule solo-sshd.ps1 uses.
$n = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$u = $n.Split('\'); $user = $u[$u.Count - 1]
if ($u.Count -gt 1 -and $u[0] -ine $env:COMPUTERNAME) { $user = $user + '@' + $u[0] }
$user = $user.ToLower()

$root = Join-Path $env:TEMP ('sdsolo-pwprobe-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $root | Out-Null
$hostKey = Join-Path $root 'host_key'; $cfg = Join-Path $root 'sshd_config'; $log = Join-Path $root 'sshd.log'; $pidf = Join-Path $root 'sshd.pid'
$fwd = { param($p) ($p -replace '\\', '/') }
& $keygen -q -t ed25519 -N '""' -f $hostKey | Out-Null
if (-not (Test-Path -LiteralPath $hostKey)) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue; Quit 'ssh-keygen made no host key' 2 }

$text = (@(
    ('Port ' + $Port),
    'ListenAddress 127.0.0.1',
    ('HostKey ' + (& $fwd $hostKey)),
    ('PidFile ' + (& $fwd $pidf)),
    'PasswordAuthentication yes',
    'PubkeyAuthentication no',
    'KbdInteractiveAuthentication no',
    'AuthenticationMethods password',
    ('AllowUsers ' + $user),
    'LogLevel DEBUG2',
    'ForceCommand whoami'
) -join "`n") + "`n"
[IO.File]::WriteAllText($cfg, $text, (New-Object Text.UTF8Encoding($false)))

Say ('probe-solo-sshd-password: user ' + $user + '   port ' + $Port + ' (127.0.0.1 only)   scratch ' + $root)
Say ('config written:')
foreach ($l in ($text -split "`n")) { if ($l) { Say ('    ' + $l) } }

$t = Start-Process -FilePath $sshd -ArgumentList @('-t', '-f', ('"' + $cfg + '"')) -NoNewWindow -Wait -PassThru -RedirectStandardError (Join-Path $root 't.err') -RedirectStandardOutput (Join-Path $root 't.out')
if ($t.ExitCode -ne 0) { Quit ('sshd -t rejected the configuration: ' + ((Get-Content -LiteralPath (Join-Path $root 't.err') -ErrorAction SilentlyContinue) -join ' | ')) 2 }

$proc = Start-Process -FilePath $sshd -ArgumentList @('-D', '-f', ('"' + $cfg + '"'), '-E', ('"' + $log + '"')) -WindowStyle Hidden -PassThru
$up = $false
for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 250; if (@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue).Count -gt 0) { $up = $true; break } }
Say ('sshd started as a hidden child, pid ' + $proc.Id + ', listening: ' + $up)
if (-not $up) { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null; Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue; Quit 'the probe sshd never listened' 2 }

$kh = Join-Path $root 'known_hosts'
$sshArgs = @('-p', [string]$Port, '-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password', '-o', 'StrictHostKeyChecking=no',
             '-o', ('UserKnownHostsFile=' + $kh), '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=10', ($user + '@127.0.0.1'))
# 127.0.0.1, NOT localhost: Windows' ssh resolves localhost to ::1 first and does not fall back, and this
# probe listens on IPv4 only (measured 2 Oct 2026: "kex_exchange_identification: write: Connection refused").

try {
    if ($Control) {
        $askpass = Join-Path $root 'askpass.cmd'
        [IO.File]::WriteAllText($askpass, "@echo not-a-real-password`r`n", (New-Object Text.ASCIIEncoding))
        $env:SSH_ASKPASS = $askpass; $env:SSH_ASKPASS_REQUIRE = 'force'; $env:DISPLAY = 'probe'
        Say ''
        Say ('CONTROL: one ssh try with a made-up password string (not yours):  ssh ' + ($sshArgs -join ' '))
        $so = Join-Path $root 'c.out'; $se = Join-Path $root 'c.err'
        $cp = Start-Process -FilePath $ssh -ArgumentList $sshArgs -NoNewWindow -PassThru -RedirectStandardOutput $so -RedirectStandardError $se
        if (-not $cp.WaitForExit(30000)) { & taskkill.exe /PID $cp.Id /T /F 2>&1 | Out-Null; Say '  (ssh timed out after 30 s - killed)' }
        Remove-Item Env:\SSH_ASKPASS, Env:\SSH_ASKPASS_REQUIRE, Env:\DISPLAY -ErrorAction SilentlyContinue
        foreach ($f in @($so, $se)) { foreach ($l in @(Get-Content -LiteralPath $f -ErrorAction SilentlyContinue)) { if ($l.Trim()) { Say ('  ssh | ' + $l) } } }
    }
    else {
        Say ''
        Say '=================================================================================='
        Say 'OPEN A SECOND WINDOW (an ordinary PowerShell) and type this one line:'
        Say ''
        Say ('    ssh ' + ($sshArgs -join ' '))
        Say ''
        Say ('It asks for a password: type YOUR WINDOWS password for ' + $user + ' THERE, in that window.')
        Say 'This window never sees it.  If it works, the other window prints your account name and closes.'
        Say ('Come back here and press ENTER (or wait ' + $WaitSeconds + ' s).')
        Say '=================================================================================='
        $deadline = (Get-Date).AddSeconds($WaitSeconds)
        $pressed = $false
        try {
            while ((Get-Date) -lt $deadline -and -not $pressed) {
                Start-Sleep -Milliseconds 500
                if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); $pressed = $true }
            }
        } catch { Start-Sleep -Seconds $WaitSeconds }
    }
}
finally {
    & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
}

Say ''
Say ('probe sshd stopped (pid ' + $proc.Id + '); still listening on ' + $Port + ': ' + (@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue).Count -gt 0))
$lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)
Say ('server log: ' + $lines.Count + ' lines.  The ones that decide it:')
$rx = '(?i)accepted password|failed password|authentication failure|authentication error|invalid user|not allowed|logon|1314|1326|privilege|token|CreateProcess|password.*(fail|refus|denied)|Connection (closed|reset)|user .* (not allowed|denied)|session opened|Starting session|forced command|ForceCommand'
$hits = @($lines | Where-Object { $_ -match $rx } | Select-Object -First 60)
foreach ($l in $hits) { Say ('    | ' + $l) }
if ($hits.Count -eq 0) {
    Say '    (none matched - the raw log follows, first 60 lines)'
    foreach ($l in @($lines | Select-Object -First 60)) { Say ('    | ' + $l) }
}

$code = Write-Verdict $lines
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
exit $code
