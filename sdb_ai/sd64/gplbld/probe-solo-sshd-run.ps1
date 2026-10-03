# probe-solo-sshd-run.ps1 - does the REAL solo-sshd.ps1 -Run give Solo a working, key-only sshd?
# SOLO 28.  End to end through the shipped script, minus only the S4U startup task (registering one
# needs elevation; the cycle's verify-solo ssh leg is that witness).
#
#   powershell -ExecutionPolicy Bypass -File <this file>        ORDINARY UNELEVATED prompt
#
# LOOPBACK CLIENT, SCRATCH APP FOLDER under %USERPROFILE% (StrictModes yes wants the key file under the
# profile - measured 2 Oct 2026), a SCRATCH profile for the helper so its migration step cannot reach the
# real ~\.ssh\authorized_keys.  The command sshd forces is a copy of whoami.exe named sd-solo.exe, so the
# probe prints WHO the forced command ran as.  It starts one sshd (through solo-sshd.ps1 -Run), stops it
# with solo-sshd.ps1 -Stop, checks the port is closed and the system sshd untouched.  It touches no firewall
# rule, no service and no live sshd_config.  It REFUSES an elevated shell and an occupied port 4251.
#
# What each row is, and why the controls are there:
#   authorised key  -> logs in, the forced command answers as the user           (the thing wanted)
#   stranger key    -> refused                                                   (else row 1 proves nothing)
#   password only   -> refused, and the server offers ONLY publickey             (key-only, measured not assumed)
#   -Stop           -> RESULT=STOPPED, port closed, same sshd* processes as before (never the system sshd)
$ErrorActionPreference = 'Continue'   # 'Stop' turns native stderr into a terminating error (PROJECT_STATUS 6)
$ssh   = Join-Path $env:SystemRoot 'System32\OpenSSH'
$keygn = Join-Path $ssh 'ssh-keygen.exe'
$sshc  = Join-Path $ssh 'ssh.exe'
$helperSrc = Join-Path $PSScriptRoot 'solo-sshd.ps1'
foreach ($f in @($keygn, $sshc, $helperSrc, (Join-Path $ssh 'sshd.exe'), (Join-Path $env:SystemRoot 'System32\whoami.exe'))) {
    if (-not (Test-Path $f)) { Write-Output "REFUSED: not found: $f"; exit 2 }
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'REFUSED: unelevated measurement only.'; exit 2
}
$port = 4251
if (@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0) { Write-Output "REFUSED: port $port is in use"; exit 2 }
Write-Output ("user={0}  port={1}" -f $id.Name, $port)

$origProfile = $env:USERPROFILE     # restored in the finally block; the helper runs against a scratch one
$app = Join-Path $env:USERPROFILE 'sdsolo-run-probe'
if ($app -notmatch 'sdsolo-run-probe$') { Write-Output 'REFUSED: odd scratch path'; exit 2 }
if (Test-Path $app) { Remove-Item -Recurse -Force $app }
$prof = Join-Path $app 'profile'; $keys = Join-Path $app 'keys'
New-Item -ItemType Directory -Force (Join-Path $app 'usr\bin'), $prof, $keys | Out-Null
Copy-Item $helperSrc (Join-Path $app 'solo-sshd.ps1')
Copy-Item (Join-Path $env:SystemRoot 'System32\whoami.exe') (Join-Path $app 'usr\bin\sd-solo.exe')
$helper = Join-Path $app 'solo-sshd.ps1'
$ukey = Join-Path $keys 'userkey'; $skey = Join-Path $keys 'strangerkey'
foreach ($k in @($ukey, $skey)) { & $keygn -q -t ed25519 -N '""' -f $k | Out-Null }

$before = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'sshd*' } | ForEach-Object { $_.Id })
Write-Output ("sshd* pids before (the system service): " + ($before -join ','))

# Write-Host inside, return only the exit code (the function-output trap, memory ps-function-output-trap).
function Try-Login([string]$label, [string]$key, [string[]]$extra) {
    $o = Join-Path $keys ('out-' + $label + '.txt'); $e = Join-Path $keys ('err-' + $label + '.txt')
    $empty = Join-Path $keys 'empty.txt'; if (-not (Test-Path $empty)) { [IO.File]::WriteAllText($empty, '') }
    $a = @('-i', $key, '-p', "$port", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
           '-o', ('UserKnownHostsFile=' + (Join-Path $keys 'known_hosts')), '-o', 'IdentitiesOnly=yes',
           '-o', 'ConnectTimeout=10') + $extra + @(($env:USERNAME + '@127.0.0.1'), 'sd-solo')
    $p = Start-Process -FilePath $sshc -ArgumentList $a -PassThru -Wait -NoNewWindow `
         -RedirectStandardOutput $o -RedirectStandardError $e -RedirectStandardInput $empty
    $so = ((Get-Content $o -ErrorAction SilentlyContinue) -join ' | ')
    $se = ((Get-Content $e -ErrorAction SilentlyContinue) | Where-Object { $_ -notmatch 'Permanently added' }) -join ' | '
    Write-Host ("    [{0}] exit={1}  stdout='{2}'  stderr='{3}'" -f $label, $p.ExitCode, $so, $se)
    return [int]$p.ExitCode
}

$runner = $null
try {
    # Prepare first, as a child with a SCRATCH profile, so the key file exists to put the key into.
    $env:USERPROFILE = $prof
    Write-Output '=== solo-sshd.ps1 -Prepare'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $helper -Prepare | ForEach-Object { Write-Output ("  " + $_) }
    $akFile = Join-Path $app 'ssh\authorized_keys'
    [IO.File]::AppendAllText($akFile, ((Get-Content ($ukey + '.pub') -Raw).Trim() + "`n"))

    Write-Output '=== solo-sshd.ps1 -Run  (started hidden, as the startup task will start it)'
    $runner = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
              -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', ('"' + $helper + '"'), '-Run') `
              -PassThru -WindowStyle Hidden
    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if (@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0) { $up = $true; break }
        if ($runner.HasExited) { break }
    }
    Write-Output ("  runner pid={0} listening on {1}={2} runner exited={3}" -f $runner.Id, $port, $up, $runner.HasExited)
    if (-not $up) {
        Write-Output '  NO MEASUREMENT: nothing listened.  The sshd log, if any:'
        $lg = Join-Path $app 'ssh\sshd.log'; if (Test-Path $lg) { Get-Content $lg -Tail 10 | ForEach-Object { Write-Output ("    " + $_) } }
    } else {
        Write-Output '=== authorised key (the forced command is whoami.exe renamed sd-solo.exe)'
        $a = Try-Login 'authorised' $ukey @()
        Write-Output '=== control: a stranger key'
        $b = Try-Login 'stranger' $skey @()
        Write-Output '=== key-only: ask for PASSWORD authentication only (no key offered)'
        $c = Try-Login 'passwordonly' $ukey @('-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no')
        Write-Output ("RESULT authorised={0} stranger={1} passwordonly={2}   (want 0, 255, 255)" -f $a, $b, $c)
        $env:USERPROFILE = $prof
        Write-Output '=== solo-sshd.ps1 -Stop'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $helper -Stop | ForEach-Object { Write-Output ("  " + $_) }
        Start-Sleep -Seconds 2
        Write-Output ("  port $port still listening=" + (@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0) + "  runner exited=" + $runner.HasExited)
    }
}
finally {
    $env:USERPROFILE = $origProfile
    if ($runner -and -not $runner.HasExited) { Stop-Process -Id $runner.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    $after = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'sshd*' } | ForEach-Object { $_.Id })
    $stray = @($after | Where-Object { $before -notcontains $_ })
    foreach ($s in $stray) { Stop-Process -Id $s -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 400
    $final = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'sshd*' } | ForEach-Object { $_.Id })
    Write-Output ("cleanup: stray sshd* killed=" + ($stray -join ',') + "  sshd* now=" + ($final -join ',') + "  before=" + ($before -join ',') +
                  "  port $port listening=" + (@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0))
    if ((Test-Path $app) -and $app -match 'sdsolo-run-probe$') { Remove-Item -Recurse -Force $app -ErrorAction SilentlyContinue }
    Write-Output ("scratch removed: " + (-not (Test-Path $app)))
}
