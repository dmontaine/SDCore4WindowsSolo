# solo-machine.ps1 - SD Core Solo's ONE elevated step.  SOLO 8 (with SOLO 3 and 7).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-machine.ps1
#       -Action Install|Upgrade|Remove -ForUser <DOMAIN\user> -AppDir <dir>
#       -Result <file> [-Api] [-ApiNetwork] [-SshScope open|restrict|leave]
#       [-SshIntoSd]
#
# Started by sd-solo.iss through ONE UAC prompt (ShellExec 'runas'), never by
# hand.  Exit 0 every step passed, 1 a step failed, 2 refused (not elevated, or
# an input missing).  The report goes to -Result, which the installer shows.
#
# THE USER IS PASSED IN, NOT READ HERE (probe-solo-elevated.ps1, SOLO 1): this
# process is whoever approved the prompt, which in the over-the-shoulder case
# is a different administrator.  Every action is for -ForUser.
#
#   Install  the startup task (registered and started), the API firewall rule,
#            the ssh firewall scope, the sshd_config block.
#   Upgrade  the startup task only - an upgrade does not revisit the choices.
#   Remove   the task, the API rule and the sshd_config block.  The ssh
#            firewall rule is Microsoft's and is left as it is.
#
# THE STARTUP TASK (SOLO 3, SOLO 1's measurement): an S4U task for the user, at
# startup, running "sd.exe -start" - so SD runs while nobody is signed in
# (ruling 2).  It holds the full administrator token for an administrator user
# whatever -RunLevel says (measured 25 Sep 2026); sd.exe drops it itself
# (ruling 16, win32token.c).  No time limit: whether Task Scheduler leaves the
# daemon running after "sd -start" returns is NOT YET MEASURED, and a limit
# would be one more thing that could stop it.  This script reports it.
#
# THE ssh FIREWALL (ruling 8): Solo installs no ssh server but still offers to
# open or close the ssh port.  ssh-firewall.ps1 refuses to change a server it
# did not install unless told -Installed; ruling 8 is that telling, so it is
# passed here.  "leave" is what the installer sends when there is no rule.
#
# THE sshd_config BLOCK (ruling 5, SOLO 7): appended LAST, between markers, so
# -Action Remove can take exactly it away:
#     Match User <name>
#         ForceCommand "<app>\usr\bin\sd.exe"
#         DisableForwarding yes
# DisableForwarding for the reason allow-ssh-groups.ps1 gives: ForceCommand
# does not constrain port forwarding.  Checked with "sshd -t" and put back if
# rejected.  NOT MEASURED: that Win32-OpenSSH matches the user by the name
# written here (lower-case, no domain for a local account; user@domain for a
# domain one).

param(
    [ValidateSet('Install', 'Upgrade', 'Remove')] [string]$Action = 'Install',
    [string]$ForUser = '',
    [string]$AppDir = '',
    [string]$Result = '',
    [switch]$Api,
    [switch]$ApiNetwork,
    [ValidateSet('open', 'restrict', 'leave')] [string]$SshScope = 'leave',
    [switch]$SshIntoSd
)

$ErrorActionPreference = 'Stop'
$TaskName = 'SD Core Solo'
$Begin = '# BEGIN SD Core Solo - added by its installer, removed by its uninstaller'
$End   = '# END SD Core Solo'
$Ps    = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$lines = New-Object System.Collections.ArrayList
function Note([string]$s) { [void]$lines.Add($s) }
$fails = New-Object System.Collections.ArrayList
function Fail([string]$s) { Note ('  FAIL  ' + $s); [void]$fails.Add($s) }
function Save-Report {
    if ($Result) {
        try { [IO.File]::WriteAllLines($Result, [string[]]$lines.ToArray(), (New-Object Text.UTF8Encoding($false))) }
        catch { }
    }
}

# Runs one of the shipped scripts in its own process and records its output.
function Invoke-Shipped([string]$Script, [string[]]$ScriptArgs) {
    $path = Join-Path $AppDir $Script
    Note ('$ ' + $Script + ' ' + ($ScriptArgs -join ' '))
    if (-not (Test-Path -LiteralPath $path)) { Note '  not found'; return 99 }
    $out = & $Ps -NoProfile -ExecutionPolicy Bypass -File $path @ScriptArgs 2>&1
    $code = $LASTEXITCODE
    foreach ($o in @($out)) { Note ('  | ' + $o) }
    Note ('  exit ' + $code)
    return $code
}

$sdexe = Join-Path $AppDir 'usr\bin\sd.exe'
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$elev = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Note ('=== solo-machine ' + $Action + ' ' + (Get-Date -Format s))
Note ('this process : ' + $me.Name + '   elevated: ' + $elev)
Note ('for user     : ' + $ForUser + $(if ($me.Name -ieq $ForUser) { '   (approved by the user)' } else { '   (approved by ' + $me.Name + ')' }))
Note ('app dir      : ' + $AppDir)
Note ('sd.exe       : ' + $sdexe + '   exists: ' + (Test-Path -LiteralPath $sdexe))
Note ('choices      : api=' + [bool]$Api + ' apinetwork=' + [bool]$ApiNetwork + ' sshscope=' + $SshScope + ' sshintosd=' + [bool]$SshIntoSd)

$refuse = @()
if (-not $elev) { $refuse += 'not elevated' }
if (-not $ForUser) { $refuse += 'no -ForUser' }
if (-not $AppDir) { $refuse += 'no -AppDir' }
if ($Action -ne 'Remove' -and -not (Test-Path -LiteralPath $sdexe)) { $refuse += 'no sd.exe to start' }
if ($refuse.Count -gt 0) {
    foreach ($r in $refuse) { Note ('REFUSED      : ' + $r) }
    Note 'VERDICT      : REFUSED - nothing was changed'
    Save-Report
    exit 2
}

# ---- the sshd_config block -------------------------------------------------
function Find-Sshd {
    foreach ($p in @((Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'),
                     (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return ''
}

function Remove-OurBlock([string[]]$in) {
    $keep = New-Object System.Collections.ArrayList
    $inside = $false
    foreach ($l in $in) {
        if ($l -eq $Begin) { $inside = $true; continue }
        if ($inside -and $l -eq $End) { $inside = $false; continue }
        if (-not $inside) { [void]$keep.Add($l) }
    }
    return , [string[]]$keep.ToArray()
}

function Set-SshBlock([bool]$Want) {
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    $sshd = Find-Sshd
    Note ('sshd.exe     : ' + $(if ($sshd) { $sshd } else { 'none found' }))
    Note ('sshd_config  : ' + $cfg + '   exists: ' + (Test-Path -LiteralPath $cfg))
    if (-not (Test-Path -LiteralPath $cfg)) {
        if ($Want) { Fail 'ssh into SD: there is no sshd_config (has sshd ever started?)' }
        else { Note '  no sshd_config, nothing to remove' }
        return
    }
    $original = [IO.File]::ReadAllLines($cfg)
    $new = Remove-OurBlock $original
    if ($Want) {
        $u = $ForUser.Split('\')
        $dom = $u[0]; $name = $u[$u.Count - 1]
        if ($u.Count -gt 1 -and $dom -ine $env:COMPUTERNAME) { $name = $name + '@' + $dom }
        $new = [string[]]($new + @($Begin, ('Match User "' + $name.ToLower() + '"'),
                                   ('    ForceCommand "' + $sdexe + '"'),
                                   '    DisableForwarding yes', $End))
    }
    elseif ($new.Count -eq $original.Count) {
        Note '  no SD Core Solo block present, nothing removed'
        return
    }
    $backup = $cfg + '.sdcoresolo-backup'
    if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $cfg -Destination $backup }
    [IO.File]::WriteAllLines($cfg, $new, (New-Object Text.UTF8Encoding($false)))
    if ($sshd) {
        $p = Start-Process -FilePath $sshd -ArgumentList '-t' -NoNewWindow -Wait -PassThru `
                 -RedirectStandardError (Join-Path $env:TEMP 'sd-solo-sshd-t.err') `
                 -RedirectStandardOutput (Join-Path $env:TEMP 'sd-solo-sshd-t.out')
        if ($p.ExitCode -ne 0) {
            [IO.File]::WriteAllLines($cfg, $original, (New-Object Text.UTF8Encoding($false)))
            Get-Content (Join-Path $env:TEMP 'sd-solo-sshd-t.err') -ErrorAction SilentlyContinue |
                ForEach-Object { Note ('  | ' + $_) }
            Fail 'sshd -t rejected the new sshd_config; the original was put back'
            return
        }
        Note '  sshd -t accepted it'
    }
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { Restart-Service sshd; Note '  sshd restarted' }
    $after = [IO.File]::ReadAllLines($cfg)
    $present = [bool]($after -contains $Begin)
    if ($present -eq $Want) { Note ('  PASS  SD Core Solo block ' + $(if ($Want) { 'present' } else { 'absent' }) + ' in sshd_config (backup ' + $backup + ')') }
    else { Fail ('sshd_config block present=' + $present + ', wanted ' + $Want) }
}

# ---- the startup task ---------------------------------------------------------
function Register-SoloTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Note '  the previous task was removed first'
    }
    Register-ScheduledTask -TaskName $TaskName `
        -Action (New-ScheduledTaskAction -Execute $sdexe -Argument '-start' -WorkingDirectory (Split-Path $sdexe)) `
        -Principal (New-ScheduledTaskPrincipal -UserId $ForUser -LogonType S4U -RunLevel Limited) `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                       -ExecutionTimeLimit ([TimeSpan]::Zero)) | Out-Null
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { Fail 'the startup task was not registered'; return }
    Note ('  task registered: "' + $TaskName + '" as ' + $t.Principal.UserId + ', ' + $t.Principal.LogonType + ', at startup, runs ' + $t.Actions[0].Execute + ' ' + $t.Actions[0].Arguments)

    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Milliseconds 500; $state = (Get-ScheduledTask -TaskName $TaskName).State }
    while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    Start-Sleep -Seconds 1
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    Note ('  task state ' + $state + ', last result 0x' + ('{0:X}' -f $info.LastTaskResult) + ', last run ' + $info.LastRunTime)
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'sd.exe'" |
               Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -ieq $sdexe) })
    foreach ($p in $procs) {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
        Note ('  sd.exe pid ' + $p.ProcessId + ' session ' + $p.SessionId + ' owner ' + $o.Domain + '\' + $o.User + '   ' + $p.CommandLine)
    }
    $mine = @($procs | Where-Object { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; ($o.Domain + '\' + $o.User) -ieq $ForUser })
    if ($info.LastTaskResult -ne 0) { Fail ('the task''s "sd -start" exited 0x' + ('{0:X}' -f $info.LastTaskResult)) }
    elseif ($mine.Count -eq 0) { Fail 'the task ran and exited 0, but no sd.exe from this install is running as the user afterwards' }
    else { Note ('  PASS  SD is running as ' + $ForUser + ', started by the task') }
}

function Remove-SoloTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Fail 'the startup task is still registered' }
    else { Note '  PASS  no startup task' }
}

try {
    Note ''
    Note '--- startup task'
    if ($Action -eq 'Remove') { Remove-SoloTask } else { Register-SoloTask }

    if ($Action -ne 'Upgrade') {
        Note ''
        Note '--- API firewall rule'
        if ($Action -eq 'Install' -and $Api -and $ApiNetwork) { $c = Invoke-Shipped 'api-firewall.ps1' @('-Open') }
        elseif ($Action -eq 'Install' -and $Api) { $c = Invoke-Shipped 'api-firewall.ps1' @('-Restrict') }
        else { $c = Invoke-Shipped 'api-firewall.ps1' @('-Remove') }
        if ($c -ne 0) { Fail ('api-firewall.ps1 exited ' + $c) }
    }

    if ($Action -eq 'Install') {
        Note ''
        Note '--- ssh firewall scope'
        if ($SshScope -eq 'leave') { Note '  left as it is' }
        else {
            $c = Invoke-Shipped 'ssh-firewall.ps1' @('-Installed', $(if ($SshScope -eq 'open') { '-Open' } else { '-Restrict' }))
            if ($c -ne 0) { Fail ('ssh-firewall.ps1 exited ' + $c) }
        }
    }

    if ($Action -ne 'Upgrade') {
        Note ''
        Note '--- sshd_config'
        Set-SshBlock ($Action -eq 'Install' -and [bool]$SshIntoSd)
    }
}
catch {
    Fail ('ERROR ' + $_.Exception.Message)
    Note $_.ScriptStackTrace
}

Note ''
if ($fails.Count -eq 0) { Note 'VERDICT      : PASS'; $code = 0 }
else { Note ('VERDICT      : FAIL - ' + ($fails -join '; ')); $code = 1 }
Save-Report
exit $code
