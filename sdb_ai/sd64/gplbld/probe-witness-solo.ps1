# probe-witness-solo.ps1 - what an installed SD Core Solo looks like RIGHT NOW, for the fresh-VM sittings.
# Ordinary UNELEVATED prompt.  Read-only: it changes nothing and starts nothing.
#   powershell -ExecutionPolicy Bypass -File <this file> -Label <name> [-Root <Solo folder>] [-TimeConnect]
#
# WHY IT EXISTS.  SOLO 33 (the API line in sd.conf follows the Tasks-page box; Allow at the Windows alert leaves no extra
# sdwind rules), SOLO 37 (keep and reload cases c, d, e, f, g) and SOLO 32 (the first API connection after a fresh install
# takes over 30 s) each need the same few facts read off an install, before and after a step.  Running this with a label
# at each point gives the sitting its before/after record in one log, instead of the owner reading registry and netstat
# output by eye.  It states FACTS, not verdicts: the sitting sheet (.claude/sittings.md) says what each value must be.
#
# WHAT IT PRINTS (and the instrument rule: the real inputs first, and a refusal of the null case).
#   inputs     the label, the resolved Solo folder, whether it exists - and it STOPS (exit 2) if the folder is not there.
#   sd.conf    every line that names APIPORT, STARTUP or a listener, with its line number and whether it is active or
#              commented, plus the file's length and last-write time.
#   folder     the top-level entries of the Solo folder, and whether the kept-data stamp (.sdcore-kept) is present.
#   sdwind     every sdwind process whose EXECUTABLE is under the Solo folder (Core's, same name, is not counted), its
#              id and the TCP endpoints it LISTENS on - a listener on 0.0.0.0 is open to the network, 127.0.0.1 is not.
#   firewall   every inbound rule whose program path is under the Solo folder: name, enabled, action, profile, remote
#              address.  (Allow at the Windows alert used to leave extra rules open to any address on Public.)
#   timing     with -TimeConnect: five TLS connections to 127.0.0.1:4249, each timed in milliseconds from connect start
#              to a finished handshake.  A 30 s client fails the first if it takes over 30000.
# Everything also goes to %LOCALAPPDATA%\SD-verify\witness-solo-<label>-<time>.log, a path it prints.

param(
    [Parameter(Mandatory = $true)][string]$Label,
    [string]$Root = '',
    [switch]$TimeConnect,
    [int]$ApiPort = 4249
)

$ErrorActionPreference = 'Continue'
if ($Root -eq '') { $Root = Join-Path $env:USERPROFILE 'SDCoreSolo' }
$logDir = Join-Path $env:LOCALAPPDATA 'SD-verify'
$null = New-Item -ItemType Directory -Force -Path $logDir
$log = Join-Path $logDir ('witness-solo-' + ($Label -replace '[^A-Za-z0-9._-]', '_') + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')

function Say([string]$t) { Write-Output $t; Add-Content -LiteralPath $log -Value $t -Encoding ASCII }

Say ('witness-solo  label=' + $Label + '  ' + (Get-Date -Format 's'))
Say ('  user      : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ('  elevated  : ' + $isAdmin + '   (this should be False)')
Say ('  root      : ' + $Root + '   exists=' + (Test-Path -LiteralPath $Root))
Say ('  log       : ' + $log)
if (-not (Test-Path -LiteralPath $Root)) {
    Say 'REFUSED: the Solo folder is not there, so nothing below would be measuring an install.  Pass -Root if it is elsewhere.'
    exit 2
}
$rootFull = ([IO.Path]::GetFullPath($Root)).TrimEnd('\')

# ---- sd.conf
Say ''
Say '--- sd.conf'
$conf = Join-Path $rootFull 'sd.conf'
if (Test-Path -LiteralPath $conf) {
    $ci = Get-Item -LiteralPath $conf
    Say ('  ' + $conf + '  length=' + $ci.Length + '  written=' + $ci.LastWriteTime.ToString('s'))
    $n = 0; $shown = 0
    foreach ($l in [IO.File]::ReadAllLines($conf)) {
        $n++
        if ($l -match '(?i)APIPORT|STARTUP|LISTEN|SSHPORT') {
            $state = if ($l.TrimStart().StartsWith('#')) { 'COMMENTED' } else { 'ACTIVE' }
            Say ('  line ' + $n + ' ' + $state + ' : ' + $l)
            $shown++
        }
    }
    if ($shown -eq 0) { Say '  (no line names APIPORT, STARTUP, LISTEN or SSHPORT)' }
} else {
    Say ('  NO sd.conf at ' + $conf)
}

# ---- folder
Say ''
Say '--- folder (top level)'
foreach ($e in @(Get-ChildItem -LiteralPath $rootFull -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
    Say ('  ' + $(if ($e.PSIsContainer) { '<dir> ' } else { '      ' }) + $e.Name)
}
$stamp = Join-Path $rootFull '.sdcore-kept'
Say ('  kept-data stamp .sdcore-kept present: ' + (Test-Path -LiteralPath $stamp))

# ---- sdwind of THIS Solo, and what it listens on
Say ''
Say '--- sdwind running from the Solo folder'
$mine = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and (([IO.Path]::GetFullPath($_.Path)).StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase))
})
$all = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue)
Say ('  sdwind processes on this machine: ' + $all.Count + '   from the Solo folder: ' + $mine.Count)
foreach ($p in $mine) {
    Say ('  pid ' + $p.Id + '  ' + $p.Path)
    $lis = @(Get-NetTCPConnection -OwningProcess $p.Id -State Listen -ErrorAction SilentlyContinue)
    if ($lis.Count -eq 0) { Say '    listens on: nothing' }
    foreach ($c in $lis) { Say ('    listens on: ' + $c.LocalAddress + ':' + $c.LocalPort + $(if ($c.LocalAddress -in '0.0.0.0', '::') { '   <- OPEN TO THE NETWORK' } else { '' })) }
}
if ($mine.Count -eq 0) { Say '  (none: SD Solo is not running, or its path is unreadable from this shell)' }

# ---- firewall rules for programs in the Solo folder
Say ''
Say '--- inbound firewall rules whose program is under the Solo folder'
$found = 0
foreach ($f in @(Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)) {
    if ($f.Program -and ($f.Program -ne 'Any') -and ([IO.Path]::GetFullPath($f.Program)).StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        $r = $f | Get-NetFirewallRule -ErrorAction SilentlyContinue
        if ($r -and $r.Direction -eq 'Inbound') {
            $found++
            $a = $r | Get-NetFirewallAddressFilter
            Say ('  ' + $r.DisplayName + '  enabled=' + $r.Enabled + '  action=' + $r.Action + '  profile=' + $r.Profile + '  remote=' + $a.RemoteAddress + '  program=' + $f.Program)
        }
    }
}
if ($found -eq 0) { Say '  (none)' }
Say ('  count: ' + $found)

# ---- first-connection timing
if ($TimeConnect) {
    Say ''
    # The real wire client (scram-probe.py: TLS 1.3 + SCRAM through UCRT64's libssl; .NET's SslStream cannot do the
    # channel binding and measured "A call to SSPI failed" here).  It logs in as an account that does not exist with a
    # dummy password, so the whole path - TCP, TLS, SCRAM first message - runs and the server REFUSES; nothing real
    # can be locked out.  The time is to the end of that refused exchange.  The verdict line is printed so a run that
    # never reached SCRAM (client missing, port closed) cannot read as a fast connection.
    $probe = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'scram-probe.py'
    if (-not (Test-Path -LiteralPath $probe)) { $probe = Join-Path $rootFull 'gplbld\scram-probe.py' }
    Say ('--- timing: 5 SCRAM exchanges to 127.0.0.1:' + $ApiPort + ' with scram-probe.py (' + $probe + ')')
    if (-not (Test-Path -LiteralPath $probe)) {
        Say '  REFUSED: scram-probe.py was not found, so no timing was taken.'
    } else {
        $env:SD_SCRAM_PASSWORD = 'witness-dummy-not-a-password'
        for ($i = 1; $i -le 5; $i++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $out = & py -3 $probe --user zz-timing-probe --port $ApiPort 2>&1 | Out-String
            $sw.Stop()
            $verdict = (($out -split "`r?`n") | Where-Object { $_ -match '^SCRAM:' } | Select-Object -First 1)
            if (-not $verdict) { $verdict = 'NO SCRAM VERDICT LINE - first output: ' + (($out -split "`r?`n" | Select-Object -First 2) -join ' | ') }
            Say ('  try ' + $i + ': ' + [int]$sw.Elapsed.TotalMilliseconds + ' ms  ' + $verdict)
        }
        Remove-Item Env:\SD_SCRAM_PASSWORD -ErrorAction SilentlyContinue
        Say '  (a REFUSED verdict is the expected answer: it proves the exchange reached SCRAM)'
    }
}

Say ''
Say ('witness-solo  label=' + $Label + '  done.  Log: ' + $log)
exit 0
