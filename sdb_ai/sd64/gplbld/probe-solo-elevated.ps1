# probe-solo-elevated.ps1 - SOLO 1(c): the ONE elevated step a per-user Solo
# installer would raise.  Started by probe-solo-installer.iss through a UAC
# prompt, never by hand.  Everything it changes it removes again.
#
# THE USER IS PASSED IN, NOT READ HERE.  This process runs as whoever approved
# the UAC prompt.  When that is the same person, $env:USERNAME is the user; when
# a DIFFERENT administrator approved it ("over the shoulder"), $env:USERNAME and
# $env:USERPROFILE are THAT administrator's.  So the installer - which runs
# unelevated, as the real user - passes -ForUser and -ForProfile, and every
# action here is for them.  The report says which case this was.

param(
    [Parameter(Mandatory = $true)] [string] $ForUser,
    [Parameter(Mandatory = $true)] [string] $ForProfile,
    [Parameter(Mandatory = $true)] [string] $AppDir,
    [int] $Port = 47432
)

$ErrorActionPreference = 'Stop'
$Spike   = Join-Path $ForProfile 'SDCoreSoloSpike'
$Result  = Join-Path $Spike 'elevated-result.txt'
$Out     = Join-Path $Spike 'task-report.txt'
$Payload = Join-Path $AppDir 'probe-solo-s4u-payload.ps1'
$Ps      = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Task    = 'SDCoreSolo-spike-install'
$Rule    = 'SDCoreSolo-spike'

$lines = New-Object System.Collections.ArrayList
function Note([string] $s) { [void]$lines.Add($s) }

$pass = $true
try {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $elev = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Note ('=== probe-solo-elevated ' + (Get-Date -Format s))
    Note ('this process     : ' + $me.Name + '   elevated: ' + $elev + '   USERPROFILE ' + $env:USERPROFILE)
    Note ('acting for       : ' + $ForUser + '   profile ' + $ForProfile)
    Note ('app dir          : ' + $AppDir + '   payload exists: ' + (Test-Path -LiteralPath $Payload))
    if ($me.Name -ieq $ForUser) { Note 'approved by      : the user themselves' }
    else { Note ('approved by      : A DIFFERENT ACCOUNT (' + $me.Name + ') - the over-the-shoulder case') }
    if (-not $elev) { Note 'REFUSED          : not elevated - the UAC step did not give an administrator token'; $pass = $false; throw 'not elevated' }

    # 1. S4U task for the user, with the at-startup trigger the product would use.
    Remove-Item -LiteralPath $Out, ($Out + '.ready') -ErrorAction SilentlyContinue
    if (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $Task -Confirm:$false }
    $targs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Payload + '" -Out "' + $Out + '" -Port ' + $Port
    try {
        Register-ScheduledTask -TaskName $Task `
            -Action (New-ScheduledTaskAction -Execute $Ps -Argument $targs) `
            -Principal (New-ScheduledTaskPrincipal -UserId $ForUser -LogonType S4U -RunLevel Limited) `
            -Trigger (New-ScheduledTaskTrigger -AtStartup) `
            -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)) | Out-Null
        Note ('task register    : ACCEPTED for ' + $ForUser + ' (S4U, at startup)')
        Start-ScheduledTask -TaskName $Task
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -LiteralPath ($Out + '.ready')) -and -not (Test-Path -LiteralPath $Out) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (Test-Path -LiteralPath ($Out + '.ready')) {
            $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $Port)
            $s = $c.GetStream(); $w = New-Object IO.StreamWriter($s); $r = New-Object IO.StreamReader($s)
            $w.WriteLine('hello-from-probe'); $w.Flush(); $reply = $r.ReadLine(); $c.Close()
            Note ('task reply       : ' + $reply)
            if ($reply -ne 'hello-from-s4u-task') { $pass = $false }
        } else { Note 'task reply       : NONE - it never said it was listening'; $pass = $false }
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -LiteralPath $Out) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (Test-Path -LiteralPath $Out) {
            $rep = @(Get-Content -LiteralPath $Out)
            $rep | Where-Object { $_ -match '^(user|session|logon sids|USERPROFILE|write in profile|ERROR)' } | ForEach-Object { Note ('  task ' + $_) }
            if (-not ($rep -match ('^user\s+: ' + [regex]::Escape($ForUser) + '$'))) { Note 'task identity    : NOT the user it was registered for'; $pass = $false }
        } else { Note 'task report      : NONE'; $pass = $false }
    } catch {
        Note ('task             : FAILED - ' + $_.Exception.Message); $pass = $false
    } finally {
        Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
        Note ('task cleanup     : present afterwards = ' + [bool](Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue))
    }

    # 2. A firewall rule - created DISABLED so it opens nothing, then removed.
    try {
        New-NetFirewallRule -Name $Rule -DisplayName 'SD Core Solo spike (probe, removed at once)' -Direction Inbound `
            -Protocol TCP -LocalPort $Port -Action Allow -Enabled False | Out-Null
        Note ('firewall rule    : created = ' + [bool](Get-NetFirewallRule -Name $Rule -ErrorAction SilentlyContinue))
    } catch { Note ('firewall rule    : FAILED - ' + $_.Exception.Message); $pass = $false }
    finally {
        Remove-NetFirewallRule -Name $Rule -ErrorAction SilentlyContinue
        Note ('firewall cleanup : present afterwards = ' + [bool](Get-NetFirewallRule -Name $Rule -ErrorAction SilentlyContinue))
    }

    # 3. The ssh configuration SOLO 7 would edit - READ ONLY here.
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    Note ('sshd_config      : ' + $cfg + '   present: ' + (Test-Path -LiteralPath $cfg) + '   (not changed)')
} catch {
    if ($_.Exception.Message -ne 'not elevated') { Note ('ERROR            : ' + $_.Exception.Message); $pass = $false }
}
if ($pass) { Note 'VERDICT          : PASS'; $code = 0 } else { Note 'VERDICT          : FAIL'; $code = 1 }
New-Item -ItemType Directory -Force -Path $Spike | Out-Null
[IO.File]::WriteAllLines($Result, [string[]]$lines.ToArray())
exit $code
