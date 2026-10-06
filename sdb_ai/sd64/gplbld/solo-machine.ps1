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
#            Solo's own ssh server (a second startup task, its firewall rule) and
#            the removal of any old system-sshd block an earlier build wrote.
#   Upgrade  the startup tasks only, plus the removal of that old block - an
#            upgrade does not revisit the choices (the API and ssh firewall
#            rules are left as they are; the API one only has its port moved).
#   Remove   both tasks, the sshd it started, both firewall rules, and any old
#            system-sshd block.  Microsoft's own OpenSSH rule for port 22 is
#            never touched: it is the full product's.
#
# THE STARTUP TASK (SOLO 3, SOLO 1's measurement): an S4U task for the user, at
# startup, running "sd.exe -start" - so SD runs while nobody is signed in
# (ruling 2).  It holds the full administrator token for an administrator user
# whatever -RunLevel says (measured 25 Sep 2026); sd.exe drops it itself
# (ruling 16, win32token.c).  No time limit: whether Task Scheduler leaves the
# daemon running after "sd -start" returns is NOT YET MEASURED, and a limit
# would be one more thing that could stop it.  This script reports it.
#
# SOLO'S SSH IS ITS OWN SSHD, ON ITS OWN PORT (SOLO 28, the owner's ruling of 2 Oct 2026, put
# to him by the Linux agent - mail T3410).  "Separate port for sd-solo": fixed 4251, not
# adjustable; routing by PORT, not login name; the full product keeps the system sshd on 22.
# What this script does for it:
#   - has solo-sshd.ps1 -Install make the ADMIN-ONLY machine folder, %ProgramData%\SDCoreSolo\ssh
#     (sshd_config, host key; permissions read back - a SYSTEM process must not trust a file a
#     user can write), then registers a SECOND startup task, "SD Core Solo SSH": SYSTEM, at
#     startup, no time limit, restarted on failure, running sshd.exe ITSELF against that config -
#     never a script of the user's - so ssh is reachable from boot with nobody signed in (owner,
#     25 Sep 2026).  WHY SYSTEM: the owner ruled (2 Oct 2026) that ssh takes the Windows ACCOUNT
#     NAME AND PASSWORD, never a key to set up first, and a per-user sshd verifies that password
#     but cannot start the session (CreateProcessAsUserW 1314 - measured, solo-sshd.ps1's header).
#   - checks it: the task ran, 4251 listens, the sshd that answers was made from the machine
#     config and runs as SYSTEM, and ssh-keyscan's host key is the .pub in the machine folder.
#   - the firewall rule SD-Solo-SSH-In-TCP for 4251 (solo-ssh-firewall.ps1): -SshScope open (other
#     computers) or restrict (this machine only).  "leave" makes none.
#   - REMOVES the old route: the "Match User" block an earlier build wrote into the SYSTEM
#     sshd_config (between the markers below), on Install, Upgrade and Remove.  It never sets or
#     changes the system sshd's startup type; an earlier build set it to Automatic and that is
#     left as it is, because the full product may be using it.
# -SshIntoSd means "set up Solo's own ssh server" (the name is kept so the installer's call is
# unchanged); -Managed changes nothing here except the upgrade case noted at its parameter.
# NOT MEASURED: a Windows PASSWORD login through the SYSTEM sshd (the owner types his own; the
# cycle's verify-solo leg uses a key, which stays possible as an extra), and that Windows
# Firewall admits a remote client through the rule (WITNESSED 2 Oct 2026 for the first build).

param(
    [ValidateSet('Install', 'Upgrade', 'Remove')] [string]$Action = 'Install',
    [string]$ForUser = '',
    [string]$AppDir = '',
    [string]$Result = '',
    [switch]$Api,
    [switch]$ApiNetwork,
    [ValidateSet('open', 'restrict', 'leave')] [string]$SshScope = 'leave',
    [switch]$SshIntoSd,
    # SOLO 24 made this change the sshd_config block.  SOLO 28: Solo's own sshd reads Solo's own key
    # file in every mode, so it no longer changes the sshd; the one thing it does now is on an UPGRADE
    # of a managed computer that has no rule for 4251 yet (an earlier build opened Microsoft's port-22
    # rule instead): the rule is made open, because the master has to reach the computer.
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
$SshTaskName = 'SD Core Solo SSH'
$SshPort = 4251        # SOLO_SSH_PORT - solo-sshd.ps1 and solo-ssh-firewall.ps1 carry the same number
# The markers of the block an EARLIER build wrote into the system sshd_config.  They are only ever
# used to take it OUT now (Remove-OldSshBlock), on Install, Upgrade and Remove.
$Begin = '# BEGIN SD Core Solo - added by its installer, removed by its uninstaller'
$End   = '# END SD Core Solo'
$Ps    = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$lines = New-Object System.Collections.ArrayList
# 06 Oct 26 (SOLO 31) - THE INSTALLER'S DIALOG NAMES ONLY WHAT FAILED.  It used to say "startup task, firewall
# and ssh" whenever this script exited 1, even when the task, the rule and the sshd all passed and one check
# failed.  Each "--- " heading below names a section; Fail records the short name of the section it happened
# in, and the report ends with one line, "FAILED STEPS : a, b", which sd-solo.iss reads.  A failure before
# any heading, or under a heading this table does not know, is called "setup" - never left out.
$script:section = 'setup'
$script:failedSteps = New-Object System.Collections.ArrayList
function Get-SectionLabel([string]$heading) {
    if ($heading -like '--- startup task*')           { return 'startup task' }
    if ($heading -like '--- API firewall*')           { return 'API firewall rule' }
    if ($heading -like '--- OpenSSH server*')         { return 'ssh server install' }
    if ($heading -like '--- the old ssh route*')      { return 'ssh' }
    if ($heading -like '--- ssh:*')                   { return 'ssh' }
    return 'setup'
}
function Note([string]$s) {
    if ($s.StartsWith('--- ')) { $script:section = Get-SectionLabel $s }
    [void]$lines.Add($s)
}
$fails = New-Object System.Collections.ArrayList
function Fail([string]$s) {
    Note ('  FAIL  ' + $s); [void]$fails.Add($s)
    if (-not $script:failedSteps.Contains($script:section)) { [void]$script:failedSteps.Add($script:section) }
}
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

$sdexe = Join-Path $AppDir 'usr\bin\sd-solo.exe'
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$elev = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Note ('=== solo-machine ' + $Action + ' ' + (Get-Date -Format s))
Note ('this process : ' + $me.Name + '   elevated: ' + $elev + '   64-bit: ' + [Environment]::Is64BitProcess)
Note ('for user     : ' + $ForUser + $(if ($me.Name -ieq $ForUser) { '   (approved by the user)' } else { '   (approved by ' + $me.Name + ')' }))
Note ('app dir      : ' + $AppDir)
Note ('sd-solo.exe  : ' + $sdexe + '   exists: ' + (Test-Path -LiteralPath $sdexe))
Note ('choices      : api=' + [bool]$Api + ' apinetwork=' + [bool]$ApiNetwork + ' sshscope=' + $SshScope + ' sshintosd=' + [bool]$SshIntoSd + ' managed=' + [bool]$Managed)
Note ('ssh msi      : ' + $(if ($SshMsi) { $SshMsi + '   exists: ' + (Test-Path -LiteralPath $SshMsi) } else { 'none - not installing an ssh server' }))

$refuse = @()
if (-not $elev) { $refuse += 'not elevated' }
# A 32-bit PowerShell sees C:\Windows\System32 as SysWOW64, so sshd.exe is
# "not found" and sshd -t is skipped - the owner's first install, 25 Sep 2026.
if (-not [Environment]::Is64BitProcess) { $refuse += 'a 32-bit PowerShell - System32 is redirected; start the 64-bit one' }
if (-not $ForUser) { $refuse += 'no -ForUser' }
if (-not $AppDir) { $refuse += 'no -AppDir' }
if ($Action -ne 'Remove' -and -not (Test-Path -LiteralPath $sdexe)) { $refuse += 'no sd-solo.exe to start' }
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

# SOLO 28 - WHAT THIS IS NOW: THE REMOVAL OF THE OLD ROUTE, AND NOTHING ELSE.  Until 2 Oct 2026 this
# function (Set-SshBlock) WROTE a "Match User" block into the system sshd_config - before the first
# Match line in managed mode, so the master's key in ~\.ssh\authorized_keys could win over the stock
# "Match Group administrators" (probe-sshd-keyfile.ps1, 30 Sep) - recorded the system sshd's host-key
# fingerprint where the user could read it, and set the system sshd to start at boot.  Solo's ssh is
# its own sshd on its own port now (solo-sshd.ps1), so what is left is taking the old block OUT of a
# machine an earlier build touched.  On a new install there is none and it says so.
#
# IT NEVER CHANGES THE SYSTEM sshd's STARTUP TYPE.  An earlier build set it to Automatic and that is
# left as found: the full product may be using that sshd.  It restarts the system sshd only when it
# really removed a block and the service is running (an open ssh session of the full product's is
# dropped by a restart - the same cost the old code paid on every install).
function Remove-OldSshBlock {
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    $sshd = Find-Sshd
    Note ('sshd.exe     : ' + $(if ($sshd) { $sshd } else { 'none found' }))
    Note ('sshd_config  : ' + $cfg + '   exists: ' + (Test-Path -LiteralPath $cfg))
    if (-not (Test-Path -LiteralPath $cfg)) {
        Note '  no sshd_config, no old block to remove'
        return
    }
    $original = [IO.File]::ReadAllLines($cfg)
    $new = Remove-OurBlock $original
    if ($new.Count -eq $original.Count) {
        Note '  no SD Core Solo block in the system sshd_config - nothing to remove'
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
    if ($svc -and $svc.Status -eq 'Running') { Restart-Service sshd; Note '  the system sshd was restarted so it re-reads its configuration' }
    $after = [IO.File]::ReadAllLines($cfg)
    if (-not ($after -contains $Begin)) { Note ('  PASS  the old SD Core Solo block is gone from the system sshd_config (backup ' + $backup + ')') }
    else { Fail 'the old SD Core Solo block is still in the system sshd_config' }
}

# ---- the OpenSSH MSI (ruling 17) ------------------------------------------------
# msiexec /qn is Windows Installer's own quiet switch; ADDLOCAL=Server is from
# Microsoft's Win32-OpenSSH MSI page.  SOLO 28: all Solo needs from it is sshd.exe and
# ssh-keygen.exe - its own sshd runs from them (solo-sshd.ps1).  It does NOT need the system sshd
# SERVICE, a rule for port 22 or a system sshd_config, so this no longer starts the service to wait
# for a config, and no longer makes Microsoft's rule when the MSI did not; what the MSI did is
# reported, not changed.  (Port 22 and that sshd are the full product's.)
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
    if (-not $sshd) { Fail 'the OpenSSH MSI reported success but left no sshd.exe'; return }
    $keygen = Join-Path (Split-Path $sshd) 'ssh-keygen.exe'
    Note ('  ssh-keygen : ' + $keygen + '   exists: ' + (Test-Path -LiteralPath $keygen))
    if (-not (Test-Path -LiteralPath $keygen)) { Fail 'the OpenSSH MSI left no ssh-keygen.exe beside sshd.exe, which Solo needs to make its host key'; return }
    $rule = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue) +
            @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'OpenSSH SSH Server*' -and $_.Direction -eq 'Inbound' })
    if ($rule.Count -gt 0) { Note ('  firewall   : the MSI made ' + $rule[0].Name + ' for port 22 - left as it is, Solo does not use port 22') }
    else { Note '  firewall   : the MSI made no rule for port 22, and none was made - Solo does not use port 22' }
    Note '  the system sshd service is not used by Solo; it was left as the MSI left it'
    Note '  PASS  OpenSSH server programs installed'
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

# ---- Solo's own ssh server: the second startup task -----------------------------------------
# SOLO 28.  Solo's sshd is run as SYSTEM, so that the owner's Windows ACCOUNT NAME AND PASSWORD can sign in: a
# per-user sshd VERIFIES the password and then fails to start the session (CreateProcessAsUserW error 1314 -
# measured, solo-sshd.ps1's header).  What this step can do, because it is elevated, is have solo-sshd.ps1
# -Install make the ADMIN-ONLY machine folder (%ProgramData%\SDCoreSolo\ssh: config, host key, permissions READ
# BACK), register a task that runs sshd.exe ITSELF against that config as SYSTEM - never a script of the user's,
# which a SYSTEM task must not run - and CHECK THE RESULT instead of trusting the registration, as
# Register-SoloTask does for SD itself.  The evidence, each on its own line:
#   - the task ran (a last-run time after the start, or the Running state; asked again once at 10 s);
#   - 4251 is LISTENING;
#   - an sshd.exe whose command line names the machine sshd_config is running, and its OWNER is SYSTEM
#     (the system sshd service is also sshd.exe: never matched by name alone);
#   - ssh-keyscan against 127.0.0.1:4251 returns the ed25519 key that is in the machine folder's .pub - so
#     the thing answering is Solo's sshd and not whatever else holds the port.
# WITNESSED on the first (per-user, S4U) build: a key login and the start at boot.  NOT MEASURED for this SYSTEM
# build: a Windows PASSWORD login through it - the owner types his own password; nobody else may.
function Find-Keyscan {
    foreach ($p in @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keyscan.exe'),
                     (Join-Path $env:ProgramFiles 'OpenSSH\ssh-keyscan.exe'))) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return ''
}

# The admin-only folder solo-sshd.ps1 -Install makes.  From the OS, not from an environment variable.
$MachineSshDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SDCoreSolo\ssh'

# The login name sshd is to allow: lower case, no domain for a local account, user@domain for a domain one.
# Worked out from -ForUser, because this elevated process may belong to a different administrator.
function Get-SshLoginName {
    $u = $ForUser.Split('\')
    $name = $u[$u.Count - 1]
    if ($u.Count -gt 1 -and $u[0] -ine $env:COMPUTERNAME) { $name = $name + '@' + $u[0] }
    return $name.ToLower()
}

# Solo's sshd processes: started from the machine config, or from the per-user config the first build of
# SOLO 28 used (<app>\ssh\sshd_config) - by command line, never by name alone.
function Get-SoloSshd {
    $needles = @((Join-Path $MachineSshDir 'sshd_config').ToLower(), (Join-Path $AppDir 'ssh\sshd_config').ToLower())
    return @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction SilentlyContinue |
             Where-Object { $c = $_.CommandLine; $c -and (@($needles | Where-Object { $c.ToLower().Contains($_) }).Count -gt 0) })
}

function Test-SshPortListening {
    return (@(Get-NetTCPConnection -State Listen -LocalPort $SshPort -ErrorAction SilentlyContinue).Count -gt 0)
}

function Register-SshTask {
    $script = Join-Path $AppDir 'solo-sshd.ps1'
    if (-not (Test-Path -LiteralPath $script)) { Fail ('solo-sshd.ps1 is not at ' + $script); return }
    $sshd = Find-Sshd
    if (-not $sshd) { Fail 'there is no sshd.exe to run Solo''s own ssh server'; return }
    $login = Get-SshLoginName
    if (-not $login) { Fail 'no login name could be worked out for the ssh server'; return }
    Note ('  sshd.exe: ' + $sshd + '   login name sshd will allow: ' + $login)
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SshTaskName -Confirm:$false
        Note '  the previous ssh task was removed first'
    }
    # An sshd left by the previous build or run (this one's, or the first per-user build's) still holds the
    # port; stopping the task need not take its child.  Solo's only, found by command line.
    $null = Invoke-Shipped 'solo-sshd.ps1' @('-Stop')

    # The admin-only folder: config, host key, permissions - and the permissions READ BACK, which -Install
    # refuses to pass unless nobody but SYSTEM and Administrators can write there.
    $c = Invoke-Shipped 'solo-sshd.ps1' @('-Install', '-OsUser', $login, '-AppDir', $AppDir)
    if ($c -ne 0) { Fail ('solo-sshd.ps1 -Install exited ' + $c + ' - the ssh task was not registered'); return }

    # The task runs sshd.exe ITSELF, as SYSTEM, against the admin-only config.  Never a script of the user's.
    $cfgPath = Join-Path $MachineSshDir 'sshd_config'
    $logPath = Join-Path $MachineSshDir 'sshd.log'
    $arg = '-D -f "' + $cfgPath + '" -E "' + $logPath + '"'
    Register-ScheduledTask -TaskName $SshTaskName `
        -Action (New-ScheduledTaskAction -Execute $sshd -Argument $arg -WorkingDirectory (Split-Path -Parent $sshd)) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                       -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                       -MultipleInstances IgnoreNew) | Out-Null
    $t = Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue
    if (-not $t) { Fail 'the ssh startup task was not registered'; return }
    Note ('  task registered: "' + $SshTaskName + '" as ' + $t.Principal.UserId + ', ' + $t.Principal.LogonType + ', at startup, runs ' + $t.Actions[0].Execute + ' ' + $t.Actions[0].Arguments)

    $startedAt = Get-Date
    Start-ScheduledTask -TaskName $SshTaskName
    $ran = $false
    $asked2 = $false
    $deadline = (Get-Date).AddSeconds(30)
    while (-not $ran -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $ti = Get-ScheduledTaskInfo -TaskName $SshTaskName
        if ($ti.LastRunTime -gt $startedAt.AddSeconds(-2) -or (Get-ScheduledTask -TaskName $SshTaskName).State -eq 'Running') { $ran = $true }
        elseif (-not $asked2 -and ((Get-Date) - $startedAt).TotalSeconds -gt 10) {
            Note '  the ssh task has not run after 10 s - starting it again'
            Start-ScheduledTask -TaskName $SshTaskName
            $asked2 = $true
        }
    }
    Note ('  ssh task ran: ' + $ran + $(if ($asked2) { ' (after a second start)' } else { '' }))
    $listening = $false
    $deadline = (Get-Date).AddSeconds(30)
    while (-not $listening -and (Get-Date) -lt $deadline) {
        if (Test-SshPortListening) { $listening = $true } else { Start-Sleep -Milliseconds 500 }
    }
    $info = Get-ScheduledTaskInfo -TaskName $SshTaskName
    Note ('  ssh task state ' + (Get-ScheduledTask -TaskName $SshTaskName).State + ', last result 0x' + ('{0:X}' -f $info.LastTaskResult) + ', port ' + $SshPort + ' listening: ' + $listening)
    if (-not $listening) {
        if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Tail 8 -ErrorAction SilentlyContinue | ForEach-Object { Note ('  | sshd.log: ' + $_) } }
        else { Note ('  no ' + $logPath + ' - sshd did not start from the task') }
        Fail ('nothing is listening on port ' + $SshPort + ' after the ssh task was started')
        return
    }
    $mine = @()
    foreach ($p in (Get-SoloSshd)) {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
        $who = $o.Domain + '\' + $o.User
        Note ('  sshd.exe pid ' + $p.ProcessId + ' session ' + $p.SessionId + ' owner ' + $who)
        if ($who -ieq 'NT AUTHORITY\SYSTEM') { $mine += $p }
    }
    if ($mine.Count -eq 0) { Fail ('port ' + $SshPort + ' listens, but no sshd.exe made from ' + $cfgPath + ' is running as SYSTEM'); return }
    Note ('  PASS  Solo''s own sshd is running as SYSTEM (session ' + $mine[0].SessionId + ') and listening on ' + $SshPort)

    # The thing answering is Solo's: its ed25519 host key is the one on disk.
    $keyscan = Find-Keyscan
    $pubFile = Join-Path $MachineSshDir 'ssh_host_ed25519_key.pub'
    if ($keyscan -eq '' -or -not (Test-Path -LiteralPath $pubFile)) {
        Note '  host key not compared (no ssh-keyscan.exe, or no host key file)'
        return
    }
    $ko = Join-Path $env:TEMP 'sd-solo-keyscan.out'
    $ke = Join-Path $env:TEMP 'sd-solo-keyscan.err'
    $null = Start-Process -FilePath $keyscan -ArgumentList @('-t', 'ed25519', '-p', "$SshPort", '127.0.0.1') -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $ko -RedirectStandardError $ke
    $seen = ''
    foreach ($l in @(Get-Content -LiteralPath $ko -ErrorAction SilentlyContinue)) {
        $f = $l -split '\s+'
        if ($f.Count -ge 3 -and $f[1] -eq 'ssh-ed25519') { $seen = $f[2] }
    }
    $disk = ((Get-Content -LiteralPath $pubFile -Raw).Trim() -split '\s+')
    if ($seen -ne '' -and $disk.Count -ge 2 -and $seen -eq $disk[1]) { Note '  PASS  the host key ssh-keyscan reads on 127.0.0.1:4251 is the one in the machine ssh folder'; return }
    # 05 Oct 26 (SOLO 31) - A KEYSCAN THAT CANNOT NEGOTIATE MEASURED NOTHING, AND NOTHING IS WHAT IT READ.  Found on
    # a fresh Windows 11 clone: the inbox System32 ssh-keyscan (OpenSSH_9.5p2) cannot talk to the 10.0 server this
    # installer installs - "choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com", exit 1, no
    # output - so every install on a stock Windows 11 reported "startup task, firewall and ssh did not complete"
    # with the task running, the rule made and the port listening.  That is a check that could not run, so it must
    # not FAIL the install.  What the host key was there to prove - that the thing answering on the port is
    # Solo's sshd - is measured directly instead: the process that owns the listening socket is one of the
    # sshd.exe processes already found above (their command line names Solo's config, owner SYSTEM).  ANY OTHER
    # empty read still fails: only a key-exchange refusal, which the stderr names, takes this path.
    $errText = ((Get-Content -LiteralPath $ke -ErrorAction SilentlyContinue) -join ' ')
    if ($seen -eq '' -and $errText -match 'choose_kex|unsupported KEX') {
        $owners = @(Get-NetTCPConnection -State Listen -LocalPort $SshPort -ErrorAction SilentlyContinue | ForEach-Object { $_.OwningProcess } | Sort-Object -Unique)
        $mineIds = @($mine | ForEach-Object { [int]$_.ProcessId })
        $foreign = @($owners | Where-Object { $mineIds -notcontains [int]$_ })
        Note ('  host key NOT compared: this ssh-keyscan cannot negotiate with this sshd (' + $errText.Trim() + ')')
        if ($owners.Count -gt 0 -and $foreign.Count -eq 0) {
            Note ('  PASS  every process listening on ' + $SshPort + ' is Solo''s sshd (pid ' + ($owners -join ', ') + ')')
            return
        }
        Fail ('port ' + $SshPort + ' is held by pid ' + ($foreign -join ', ') + ', which is not Solo''s sshd (listeners found: ' + $owners.Count + ')')
        return
    }
    Fail ('the host key served on port ' + $SshPort + ' is not Solo''s (ssh-keyscan read "' + $seen + '")')
}

function Remove-SshTask {
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue
    }
    # Stopping the task need not end the sshd it started; -Uninstall ends Solo's, by command line (never the
    # system sshd), and deletes the admin-only machine folder with its host key and config.
    $null = Invoke-Shipped 'solo-sshd.ps1' @('-Uninstall')
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $SshTaskName -Confirm:$false
    }
    $left = Split-Path -Parent $MachineSshDir
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) { Fail 'the ssh startup task is still registered' }
    elseif ((Get-SoloSshd).Count -gt 0) { Fail 'Solo''s sshd is still running after the ssh task was removed' }
    elseif (Test-Path -LiteralPath $left) { Fail ('the machine ssh folder ' + $left + ' is still there') }
    else { Note '  PASS  no ssh task, no sshd of Solo''s running and no machine ssh folder' }
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
    else {
        # 01 Oct 26 - AN UPGRADE MOVES THE RULE'S PORT AND NOTHING ELSE.  The API
        # port is fixed at 4249 now (it was 4243); an upgrade keeps sd.conf, whose
        # APIPORT line still reads as ON, so the listener moves by itself while a
        # rule an earlier build made still names 4243.  -Retarget changes that one
        # field and checks the scope did not move; it does nothing where there is
        # no rule, the rule is already right, or it is on another port.  -Open and
        # -Restrict are not run: they would choose a scope no one was asked about.
        Note ''
        Note '--- API firewall rule port'
        $c = Invoke-Shipped 'api-firewall.ps1' @('-Retarget')
        if ($c -ne 0) { Fail ('api-firewall.ps1 -Retarget exited ' + $c) }
    }

    if ($Action -eq 'Install' -and $SshMsi) {
        Note ''
        Note '--- OpenSSH server (MSI)'
        Install-SshMsi $SshMsi
    }

    # SOLO 28.  The OLD route first, on every action: an earlier build's "Match User" block in the
    # SYSTEM sshd_config comes OUT (it is a no-op where there is none - every new install).
    Note ''
    Note '--- the old ssh route (a block an earlier build wrote into the system sshd_config)'
    Remove-OldSshBlock

    Note ''
    Note ('--- ssh: SD Core Solo''s own sshd, port ' + $SshPort)
    if ($Action -eq 'Remove') {
        Remove-SshTask
        $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @('-Remove')
        if ($c -ne 0) { Fail ('solo-ssh-firewall.ps1 -Remove exited ' + $c) }
    }
    else {
        # Install: wherever OpenSSH is found or was just installed (ruling 5, "not a choice"); Upgrade: wherever
        # sshd.exe is, so a Solo upgraded from the old model is moved to its own sshd without a question.
        $wantSsh = ($Action -eq 'Install' -and [bool]$SshIntoSd) -or ($Action -eq 'Upgrade' -and ((Find-Sshd) -ne ''))
        if ($wantSsh) {
            Register-SshTask
            if ($Action -eq 'Install' -and $SshScope -ne 'leave') {
                # The one admin step Solo's ssh still has.
                $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @($(if ($SshScope -eq 'open') { '-Open' } else { '-Restrict' }))
                if ($c -ne 0) { Fail ('solo-ssh-firewall.ps1 exited ' + $c) }
            }
            elseif ($Action -eq 'Upgrade') {
                # An upgrade does not revisit a rule that is there, and no rule means this computer only,
                # which is what -Restrict would make.  The exception is a MANAGED computer that has no
                # rule yet: the master reached it over Microsoft's port 22 before, and that route is gone.
                $haveRule = @(Get-NetFirewallRule -Name 'SD-Solo-SSH-In-TCP' -ErrorAction SilentlyContinue).Count -gt 0
                Note ('  firewall   : rule SD-Solo-SSH-In-TCP present=' + $haveRule + '  managed=' + [bool]$Managed)
                if ($Managed -and -not $haveRule) {
                    $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @('-Open')
                    if ($c -ne 0) { Fail ('solo-ssh-firewall.ps1 -Open exited ' + $c) }
                }
            }
        }
        else { Note '  not set up: no OpenSSH server was found or chosen' }
    }
}
catch {
    Fail ('ERROR ' + $_.Exception.Message)
    Note $_.ScriptStackTrace
}

Note ''
if ($fails.Count -eq 0) { Note 'VERDICT      : PASS'; $code = 0 }
else {
    Note ('VERDICT      : FAIL - ' + ($fails -join '; '))
    Note ('FAILED STEPS : ' + (($script:failedSteps.ToArray()) -join ', '))
    $code = 1
}
Save-Report
exit $code
