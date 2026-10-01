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
# THE sshd_config BLOCK (ruling 5, SOLO 7): between markers, so -Action Remove can
# take exactly it away.  Since 30 Sep 2026 (SOLO 24) it is written BEFORE the
# first Match line (appended last only when the file has none) and carries
# AuthorizedKeysFile - see the note where it is written:
#     Match User <name>
#         ForceCommand "<app>\usr\bin\sd.exe"
#         AuthorizedKeysFile .ssh/authorized_keys
#         DisableForwarding yes
# Written wherever OpenSSH is found - not a choice (ruling 5) - and sshd is
# then set to start at boot, so ssh works with nobody signed in (owner, 25 Sep
# 2026).  Only this user is matched; sign-in is sshd's own, the Windows password.
# DisableForwarding because ForceCommand does not constrain port forwarding.  Checked with "sshd -t" and put back if
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
    [switch]$SshIntoSd,
    # SOLO 24: managed mode only - the block carries AuthorizedKeysFile and goes
    # ahead of the other Match blocks, so the SD Core server can install its key.
    [switch]$Managed,
    # Ruling 17: Microsoft's OpenSSH MSI from the release folder, installed
    # first so the ssh steps below have a server to work on.  Install only.
    [string]$SshMsi = ''
)

$ErrorActionPreference = 'Stop'

# THE INSTALLER CAN ONLY START THE 32-BIT POWERSHELL (sd-solo.iss PowerShellExe
# records the measurement), which sees System32 as SysWOW64.  So a 32-bit copy
# of this script re-launches itself in the 64-bit PowerShell - Sysnative is
# visible to a 32-bit process - with the same arguments, and passes its exit
# code back.  The elevated token is inherited.  If that is impossible, the
# refusal below says so rather than measuring through the redirection.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $ps64) {
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($k in $PSBoundParameters.Keys) {
            $v = $PSBoundParameters[$k]
            if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $relaunch += ('-' + $k) } }
            else { $relaunch += @(('-' + $k), [string]$v) }
        }
        & $ps64 @relaunch
        exit $LASTEXITCODE
    }
}

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
Note ('this process : ' + $me.Name + '   elevated: ' + $elev + '   64-bit: ' + [Environment]::Is64BitProcess)
Note ('for user     : ' + $ForUser + $(if ($me.Name -ieq $ForUser) { '   (approved by the user)' } else { '   (approved by ' + $me.Name + ')' }))
Note ('app dir      : ' + $AppDir)
Note ('sd.exe       : ' + $sdexe + '   exists: ' + (Test-Path -LiteralPath $sdexe))
Note ('choices      : api=' + [bool]$Api + ' apinetwork=' + [bool]$ApiNetwork + ' sshscope=' + $SshScope + ' sshintosd=' + [bool]$SshIntoSd + ' managed=' + [bool]$Managed)
Note ('ssh msi      : ' + $(if ($SshMsi) { $SshMsi + '   exists: ' + (Test-Path -LiteralPath $SshMsi) } else { 'none - not installing an ssh server' }))

$refuse = @()
if (-not $elev) { $refuse += 'not elevated' }
# A 32-bit PowerShell sees C:\Windows\System32 as SysWOW64, so sshd.exe is
# "not found" and sshd -t is skipped - the owner's first install, 25 Sep 2026.
if (-not [Environment]::Is64BitProcess) { $refuse += 'a 32-bit PowerShell - System32 is redirected; start the 64-bit one' }
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
        # 30 Sep 26 - SOLO 24: THE BLOCK GOES BEFORE THE FIRST Match LINE, NOT LAST.
        # sshd takes the first value it sees per keyword, and the stock
        # "Match Group administrators" sets AuthorizedKeysFile to a ProgramData file
        # an unelevated process cannot write, so for an administrator (the usual
        # Solo user) a block placed after it never wins.  MEASURED 30 Sep 2026 with
        # probe-sshd-keyfile.ps1: as appended last the key in ~/.ssh/authorized_keys
        # was refused; with this block first it was accepted and ran the forced
        # sd.exe.  AuthorizedKeysFile is what lets the API session (the user,
        # unelevated) install the master's key itself - gpl.bp/apisrvr request 49.
        # UNMANAGED (standalone) KEEPS THE OLD BLOCK AND POSITION: no global password
        # exists, so nothing can install a key and nothing changes for the user.
        $blockLines = [string[]]@($Begin, ('Match User "' + $name.ToLower() + '"'),
                                  ('    ForceCommand "' + $sdexe + '"'))
        if ($Managed) { $blockLines += '    AuthorizedKeysFile .ssh/authorized_keys' }
        $blockLines += @('    DisableForwarding yes', $End)
        $at = -1
        if ($Managed) {
            for ($i = 0; $i -lt $new.Count; $i++) { if ($new[$i] -match '^\s*Match\s') { $at = $i; break } }
        }
        if ($at -lt 0) { $new = [string[]]($new + $blockLines) }
        else {
            $pre = [string[]]@(); if ($at -gt 0) { $pre = [string[]]$new[0..($at - 1)] }
            $new = [string[]]($pre + $blockLines + $new[$at..($new.Count - 1)])
        }
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
    # 30 Sep 26 - SOLO 24: request 49's reply carries sshd's ed25519 host-key
    # fingerprint so the master can pin it.  The key's .pub sits in ProgramData\ssh,
    # which an unelevated user cannot read (measured 30 Sep: access denied), so this
    # elevated step records the fingerprint where the user's own process can.
    # Managed only.  The key is unchanged until sshd's host keys are regenerated.
    if ($Want -and $Managed -and $AppDir) {
        try {
            $pub = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub'
            $t = ([IO.File]::ReadAllText($pub).Trim() -split '\s+')
            $sha = [Security.Cryptography.SHA256]::Create()
            $fp = 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash([Convert]::FromBase64String($t[1]))).TrimEnd('=')
            $dest = Join-Path $AppDir 'sdsys\ssh-hostkey'
            [IO.File]::WriteAllText($dest, $fp + "`r`n", (New-Object Text.UTF8Encoding($false)))
            Note ('  sshd host key fingerprint recorded in ' + $dest + ': ' + $fp)
        } catch {
            Note ('  could not record the sshd host-key fingerprint: ' + $_.Exception.Message)
        }
    }
    # Owner, 25 Sep 2026: ssh must be reachable unattended, from boot, with
    # nobody signed in - so sshd itself is set to start at boot.  Only when the
    # block is wanted; -Action Remove leaves the startup type as it finds it.
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($Want) {
        if (-not $svc) { Fail 'there is no sshd service to start at boot' }
        else {
            Note ('  sshd before: ' + $svc.Status + ', ' + $svc.StartType)
            if ($svc.StartType -ne 'Automatic') { Set-Service sshd -StartupType Automatic }
            if ($svc.Status -eq 'Running') { Restart-Service sshd } else { Start-Service sshd }
            $svc = Get-Service sshd
            Note ('  sshd after : ' + $svc.Status + ', ' + $svc.StartType)
            if ($svc.Status -ne 'Running' -or $svc.StartType -ne 'Automatic') { Fail 'sshd is not running and set to start at boot' }
        }
    }
    elseif ($svc -and $svc.Status -eq 'Running') { Restart-Service sshd; Note '  sshd restarted' }
    $after = [IO.File]::ReadAllLines($cfg)
    $present = [bool]($after -contains $Begin)
    if ($present -eq $Want) { Note ('  PASS  SD Core Solo block ' + $(if ($Want) { 'present' } else { 'absent' }) + ' in sshd_config (backup ' + $backup + ')') }
    else { Fail ('sshd_config block present=' + $present + ', wanted ' + $Want) }
}

# ---- the OpenSSH MSI (ruling 17) ------------------------------------------------
# msiexec /qn is Windows Installer's own quiet switch; ADDLOCAL=Server is from
# Microsoft's Win32-OpenSSH MSI page.  NOT MEASURED, so each is checked and
# reported rather than assumed: whether the MSI makes the firewall rule (made
# here, under Microsoft's name, when it did not - ssh-firewall.ps1 then finds
# it), and whether sshd_config exists before sshd first starts (sshd writes it
# on first start, so it is started and waited for).
function Install-SshMsi([string]$Msi) {
    if (-not (Test-Path -LiteralPath $Msi)) { Fail ('the OpenSSH MSI is not at ' + $Msi); return }
    $existing = Find-Sshd
    if ($existing) { Note ('  an ssh server is already here (' + $existing + '); the MSI was not run'); return }
    Note ('  msi sha256 : ' + (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash + '   ' + (Get-Item -LiteralPath $Msi).Length + ' bytes')
    $log = Join-Path $env:TEMP 'sd-solo-openssh-msi.log'
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $margs = @('/i', ('"' + $Msi + '"'), '/qn', 'ADDLOCAL=Server', '/l*v', ('"' + $log + '"'))
    Note ('$ msiexec ' + ($margs -join ' '))
    $p = Start-Process -FilePath $msiexec -ArgumentList $margs -Wait -PassThru
    Note ('  exit ' + $p.ExitCode + '   (0 done, 3010 done and a restart wanted; log ' + $log + ')')
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { Fail ('the OpenSSH MSI exited ' + $p.ExitCode); return }
    $sshd = Find-Sshd
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    Note ('  after      : sshd.exe ' + $(if ($sshd) { $sshd } else { 'NOT FOUND' }) + '   service ' + $(if ($svc) { [string]$svc.Status + ', ' + $svc.StartType } else { 'NONE' }))
    if (-not $sshd -or -not $svc) { Fail 'the OpenSSH MSI reported success but left no sshd.exe or sshd service'; return }
    $rule = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue) +
            @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'OpenSSH SSH Server*' -and $_.Direction -eq 'Inbound' })
    if ($rule.Count -gt 0) { Note ('  firewall   : the MSI made ' + $rule[0].Name) }
    else {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server (sshd)' -Direction Inbound `
            -Protocol TCP -LocalPort 22 -Action Allow -Enabled True | Out-Null
        Note '  firewall   : the MSI made no rule; OpenSSH-Server-In-TCP created for port 22'
    }
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    if (-not (Test-Path -LiteralPath $cfg)) {
        Start-Service sshd
        $deadline = (Get-Date).AddSeconds(15)
        while (-not (Test-Path -LiteralPath $cfg) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    }
    Note ('  sshd_config: ' + $cfg + '   exists: ' + (Test-Path -LiteralPath $cfg))
    if (-not (Test-Path -LiteralPath $cfg)) { Fail 'sshd started but wrote no sshd_config within 15 s' }
    else { Note '  PASS  OpenSSH server installed' }
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

    # 30 Sep 26 - THE TASK CAN BE STARTED AND NEVER RUN.  A cycle at 18:52 registered
    # the task, Start-ScheduledTask returned without error, and the task then sat at
    # "Ready", last run 11/30/1999, last result 0x41303 ("has not yet run") - for
    # minutes, and again on a second Start-ScheduledTask and on schtasks /run - so
    # the old check below, which only waited while the state was Running, read the
    # 0x41303 at once and failed the install.  (Run directly, "sd -start" worked.)
    # So: start it, and wait for EVIDENCE that it ran (a last-run time after the
    # start, or the Running state); ask again once at 10 s; and say so.
    $startedAt = Get-Date
    Start-ScheduledTask -TaskName $TaskName
    $ran = $false
    $ranDeadline = (Get-Date).AddSeconds(30)
    $asked2 = $false
    while (-not $ran -and (Get-Date) -lt $ranDeadline) {
        Start-Sleep -Milliseconds 500
        $ti = Get-ScheduledTaskInfo -TaskName $TaskName
        if ($ti.LastRunTime -gt $startedAt.AddSeconds(-2) -or (Get-ScheduledTask -TaskName $TaskName).State -eq 'Running') { $ran = $true }
        elseif (-not $asked2 -and ((Get-Date) - $startedAt).TotalSeconds -gt 10) {
            Note '  the task has not run after 10 s - starting it again'
            Start-ScheduledTask -TaskName $TaskName
            $asked2 = $true
        }
    }
    Note ('  task ran: ' + $ran + $(if ($asked2) { ' (after a second start)' } else { '' }))
    $deadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Milliseconds 500; $state = (Get-ScheduledTask -TaskName $TaskName).State }
    while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    Start-Sleep -Seconds 1
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    Note ('  task state ' + $state + ', last result 0x' + ('{0:X}' -f $info.LastTaskResult) + ', last run ' + $info.LastRunTime)
    # THE SERVER IS sdwind.exe (SDWIND_NAME, sddefs.h), NOT sd.exe.  The first
    # owner's install (25 Sep 2026) looked for sd.exe here and reported FAIL
    # over a server that was running - sdwind.exe, session 0, started by the
    # task.  Every sd*.exe from this install is listed, so a wrong name shows.
    $bin = Split-Path $sdexe
    $procs = @(Get-CimInstance Win32_Process -Filter "Name LIKE 'sd%'" |
               Where-Object { $_.ExecutablePath -and ((Split-Path $_.ExecutablePath) -ieq $bin) })
    Note ('  processes from ' + $bin + ': ' + $procs.Count)
    $mine = @()
    foreach ($p in $procs) {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
        $who = $o.Domain + '\' + $o.User
        Note ('  ' + $p.Name + ' pid ' + $p.ProcessId + ' session ' + $p.SessionId + ' owner ' + $who)
        if ($p.Name -ieq 'sdwind.exe' -and $who -ieq $ForUser) { $mine += $p }
    }
    if ($info.LastTaskResult -ne 0) { Fail ('the task''s "sd -start" exited 0x' + ('{0:X}' -f $info.LastTaskResult)) }
    elseif ($mine.Count -eq 0) { Fail 'the task ran and exited 0, but no sdwind.exe from this install is running as the user afterwards' }
    else { Note ('  PASS  the SD server (sdwind.exe) is running as ' + $ForUser + ', session ' + $mine[0].SessionId) }
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

    if ($Action -eq 'Install' -and $SshMsi) {
        Note ''
        Note '--- OpenSSH server (MSI)'
        Install-SshMsi $SshMsi
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
