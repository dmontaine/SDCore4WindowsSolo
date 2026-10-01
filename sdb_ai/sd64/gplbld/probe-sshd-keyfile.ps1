# probe-sshd-keyfile.ps1 - which key file does Win32-OpenSSH read for THIS user?
#
# Answers the Windows half of the managed-mode ssh-key design (SOLO ssh-key,
# 30 Sep 2026, agreed with the Linux Solo agent).  The question: for an
# administrator Solo user, does sshd read %USERPROFILE%\.ssh\authorized_keys
# (which the unelevated API session could write) or only
# %ProgramData%\ssh\administrators_authorized_keys (which it cannot)?  And does
# an "AuthorizedKeysFile .ssh/authorized_keys" placed BEFORE the stock
# "Match Group administrators" block change the answer?
#
# RUN ELEVATED.  It starts a PRIVATE sshd on port 2222 from a scratch copy of
# the installed config.  It does not touch the live sshd_config, the live sshd
# service, or any firewall rule.  It puts a throwaway key in the user's own
# authorized_keys for the length of one login and removes it in a finally block;
# it REFUSES to run if that file already exists.
#
# Each case prints its real inputs, the ssh result, and the sshd log lines that
# decide it.  A case that never reached sshd is reported as NO MEASUREMENT.

param(
    [string]$ForUser = '',
    [int]$Port = 2222
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH'
$sshd = Join-Path $ssh 'sshd.exe'
$keygen = Join-Path $ssh 'ssh-keygen.exe'
$sshc = Join-Path $ssh 'ssh.exe'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdm = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdm) { Write-Host 'REFUSED: run this from an ELEVATED PowerShell.'; exit 2 }
foreach ($f in @($sshd, $keygen, $sshc)) { if (-not (Test-Path $f)) { Write-Host "REFUSED: not found: $f"; exit 2 } }

if ($ForUser -eq '') { $ForUser = $env:USERNAME }
$lname = $ForUser.ToLower()
$home1 = $env:USERPROFILE
$ak = Join-Path $home1 '.ssh\authorized_keys'
$live = Join-Path $env:ProgramData 'ssh\sshd_config'
$work = Join-Path $env:TEMP 'sdssh-probe'

Write-Host "user            : $ForUser (matched as `"$lname`")"
Write-Host "user key file   : $ak"
Write-Host "live config     : $live (read only)"
Write-Host "scratch dir     : $work"
Write-Host "private port    : $Port"
if (Test-Path $ak) { Write-Host "REFUSED: $ak already exists; not touching it."; exit 2 }
if (-not (Test-Path $live)) { Write-Host "REFUSED: no live config at $live"; exit 2 }
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Path $work | Out-Null

$hk = Join-Path $work 'hostkey'
$ck = Join-Path $work 'clientkey'
& $keygen -q -t ed25519 -N '""' -f $hk
& $keygen -q -t ed25519 -N '""' -f $ck
if (-not ((Test-Path "$ck.pub") -and (Test-Path $hk))) { Write-Host 'REFUSED: key generation did not produce files'; exit 2 }

$liveText = [IO.File]::ReadAllText($live)
$marker = 'Match Group administrators'
if ($liveText.IndexOf($marker) -lt 0) { Write-Host "REFUSED: live config has no '$marker' line; the test would measure nothing."; exit 2 }

$head = "Port $Port`r`nHostKey $($hk -replace '\\','/')`r`nPidFile $($work -replace '\\','/')/sshd.pid`r`nLogLevel DEBUG3`r`n"
$override = "Match User `"$lname`"`r`n    AuthorizedKeysFile .ssh/authorized_keys`r`n"

# Case A = the installed config as it stands.  Case B = the override first.
# Global directives must precede any Match block, so the scratch directives go
# at the top and the rest of the file follows unchanged.
$cases = @(
    @{ Name = 'A-as-installed';      Text = $head + $liveText },
    @{ Name = 'B-override-first';    Text = $head + $liveText.Replace($marker, $override + $marker) }
)

$sdexe = ''
foreach ($line in ($liveText -split "`r?`n")) { if ($line -match 'ForceCommand\s+"?([^"]+)"?') { $sdexe = $Matches[1] } }
Write-Host "forced command  : $sdexe"

$results = @()
foreach ($c in $cases) {
    Write-Host ''
    Write-Host "=== CASE $($c.Name)"
    $cfg = Join-Path $work "$($c.Name).conf"
    $log = Join-Path $work "$($c.Name).sshd.log"
    $out = Join-Path $work "$($c.Name).ssh.out"
    $err = Join-Path $work "$($c.Name).ssh.err"
    [IO.File]::WriteAllText($cfg, $c.Text, (New-Object Text.UTF8Encoding($false)))
    & $sshd -t -f $cfg
    if ($LASTEXITCODE -ne 0) { Write-Host "  sshd -t REJECTED $cfg - NO MEASUREMENT"; $results += "$($c.Name): NO MEASUREMENT (config rejected)"; continue }
    Write-Host "  config accepted by sshd -t: $cfg"
    $proc = $null
    try {
        Copy-Item "$ck.pub" $ak
        $proc = Start-Process -FilePath $sshd -ArgumentList @('-D', '-f', $cfg, '-E', $log) -PassThru -WindowStyle Hidden
        $up = $false
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 500
            if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { $up = $true; break }
        }
        if (-not $up) { Write-Host "  private sshd never listened on $Port - NO MEASUREMENT"; $results += "$($c.Name): NO MEASUREMENT (sshd did not start)"; continue }
        $sargs = @('-p', "$Port", '-i', $ck, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                   '-o', "UserKnownHostsFile=$(Join-Path $work 'kh')", '-o', 'ConnectTimeout=10', "$lname@localhost", 'echo SHELL-RAN')
        Write-Host "  ssh $($sargs -join ' ')"
        $p2 = Start-Process -FilePath $sshc -ArgumentList $sargs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
        Write-Host "  ssh exit code: $($p2.ExitCode)"
        Write-Host '  ssh stdout:'; Get-Content $out | ForEach-Object { "    $_" }
        Write-Host '  ssh stderr:'; Get-Content $err | ForEach-Object { "    $_" }
        Start-Sleep -Milliseconds 800
        # sshd keeps the log locked while it runs: stop OUR private sshd (and only its children) first.
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1000
        Write-Host '  sshd log lines that decide it:'
        $hit = @()
        # sshd holds the log open for writing: read it with a shared-read open (Get-Content throws).
        $lines = @()
        if (Test-Path $log) {
            $fs = New-Object IO.FileStream($log, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $sr = New-Object IO.StreamReader($fs)
            $lines = ($sr.ReadToEnd()) -split "`r?`n"
            $sr.Close()
        }
        if ($lines.Count -gt 0) { $hit = $lines | Where-Object { $_ -match 'authorized_keys|Authentication refused|Accepted publickey|Failed publickey|bad ownership|bad permissions|Match (User|Group)|trying public key|matched' } }
        $hit | Select-Object -First 25 | ForEach-Object { "    $_" }
        $accepted = [bool]($hit | Where-Object { $_ -match 'Accepted publickey' })
        $refused  = [bool]($hit | Where-Object { $_ -match 'Authentication refused|Failed publickey|bad ownership|bad permissions' })
        if ($hit.Count -eq 0) { $results += "$($c.Name): NO MEASUREMENT (no sshd log lines)" }
        elseif ($accepted -and -not $refused) { $results += "$($c.Name): KEY ACCEPTED from the user's own authorized_keys" }
        elseif ($refused -or -not $accepted) { $results += "$($c.Name): KEY NOT ACCEPTED (see log lines above)" }
    } finally {
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        if (Test-Path $ak) { Remove-Item $ak -Force }
        Write-Host "  user authorized_keys removed: $(-not (Test-Path $ak))"
    }
}

Write-Host ''
Write-Host '=== RESULT'
$results | ForEach-Object { Write-Host "  $_" }
Write-Host "ACL of the user's .ssh folder, for the StrictModes question:"
& icacls (Join-Path $home1 '.ssh') | Select-Object -First 8 | ForEach-Object { "  $_" }
Write-Host "Logs are in $work - leave them for the agent to read."
Write-Host 'The live sshd service and sshd_config were not touched.'
