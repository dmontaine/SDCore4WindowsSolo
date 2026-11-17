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
# unchanged).  06 Oct 26 - SOLO 36: it is a CHOICE now (the owner reversed SOLO 28's "not a
# choice"), so an Install without -SshIntoSd sets up nothing for ssh; and an UPGRADE sets Solo's
# sshd up again only where it is already set up (its task is registered, or the old route's block
# was just taken out) - it never turns ssh on for a computer whose user chose otherwise.  The
# -Managed switch is gone: it only opened the ssh port on upgrading a managed computer.
# NOT MEASURED: a Windows PASSWORD login through the SYSTEM sshd (the owner types his own; the
# cycle's verify-solo leg uses a key, which stays possible as an extra), and that Windows
# Firewall admits a remote client through the rule (WITNESSED 2 Oct 2026 for the first build).
#
# 12 Nov 26 - SOLO 62, THE DOORS (the owner: REMOTE.API and REMOTE.SSH from any session that passed SD's admin gate, remote ones
# included, through a helper; "by design solo is less secure than core").  Install and Upgrade also register a THIRD task,
# "SD Core Solo Doors": SYSTEM, no trigger, runs solo-doors.ps1 -Serve with -AppDir and -ForUser fixed here, and its security
# descriptor lets -ForUser start it (read and execute) and nothing more.  They make %ProgramData%\SDCoreSolo\doors, where the
# helper writes its answer: SYSTEM and Administrators full control, -ForUser read only.  Remove takes both away.
#   (12 Nov 26, the owner's "Installer keeps the MSI": when ssh is set up from SD on a computer with no ssh server, the OpenSSH
#   MSI the installer kept in <Solo folder>\ssh-server is installed first, by Install-SshMsi.)
#   -Action Doors -Door api|ssh -Mode off|local|open   is what that helper runs, once it has checked a request, so each change
# is made by the same steps an install makes (one copy of each): the API's listener switch and rule; ssh's task (Register-SshTask
# when it was never set up - the owner's "set it up from the page") and rule.  The API listener only moves when SD next starts;
# nothing here restarts SD.
#
# 16 Nov 26 Windows port - from Linux Solo 2d3db81 (S.247), SCHEDULED JOBS (the owner's decisions of 16 Nov 2026).  A job is a task
# "\SD Core Solo Jobs\sd-solo-job-<name>": the Solo user (-ForUser, by SID), LogonType S4U ("do not store password") so that it runs while
# the user is signed out, the least privilege, and ONE action, fixed here: <Solo folder>\usr\bin\sd-solo.exe run.job <name>.  The
# trigger is one of SD Core's five schedule shapes (SD Core's sd-jobs.ps1 Get-JobSchedule, copied); no missed run is made up
# (StartWhenAvailable false, Linux's Persistent=false) and a run still going is not doubled (IgnoreNew).  The command a job runs is never
# here: it is in the user's $jobs, which RUN.JOB reads.  THE FOLDER is SYSTEM and Administrators only, as SD Core's \SD is, for SD Core's
# measured reason (sd-taskfolder.ps1: the root gives Authenticated Users write, so anyone could make the folder first or plant a task
# in it); it is "SD Core Solo Jobs" and not "SD Core Solo" because the startup task has that name in the root, and a task and a folder
# are a file and a directory in the same System32\Tasks folder (not measured; the layout).  Each task also lets -ForUser READ it, so
# SET.JOB's list can show the next and the last run; nothing lets the user change one.
#   -Action Job -JobOp set|delete|run -JobName <name> [-JobSchedule <schedule>]   is what the doors helper runs for a checked job
# request (solo-doors.ps1): set registers the task (only when $jobs\<name> already holds that schedule: SET.JOB writes the definition
# first), delete stops and removes it, run starts it now.  The verdict line names the result: "JOB RESULT   : set|deleted|absent|started".
#   Install and Upgrade give every definition in $jobs its task (a reload's kept $jobs, which solo-setup.ps1 copied back before this step;
#   one that fails is said and the rest go on, as Linux's JOBS-RESTORE); Remove takes every job task and the folder away FIRST, so that
#   no job starts while SD is being taken down.  $jobs is the user's data: the uninstaller's Keep keeps it (sd-solo.iss KeepDataPass).
# NOT MEASURED when written: that SYSTEM (the doors helper) can register an S4U task for the Solo user; that the user can read a task in a
# folder it cannot write; a job's task firing with the user signed out.  A sitting owes them.
#
# 17 Nov 26 SD Core Solo - four-version audit D1, from Linux Solo's solo-sshguard.py (LSOLO 29): THE ssh LOCK-OUT.  Wherever Solo's
# ssh is set up (Register-SshTask: install, upgrade, the doors helper), a SYSTEM task "SD Core Solo SSH Guard" runs the admin-only
# copy of solo-sshguard.ps1; three wrong passwords from one address in ten minutes block that address on 4251 for ten minutes
# (a Windows Firewall rule per address).  Remove-SshTask takes the task and every lock-out rule away first.

param(
    [ValidateSet('Install', 'Upgrade', 'Remove', 'Doors', 'Job')] [string]$Action = 'Install',
    [ValidateSet('', 'api', 'ssh')] [string]$Door = '',
    [ValidateSet('', 'off', 'local', 'open')] [string]$Mode = '',
    # 16 Nov 26 - S.247: -Action Job only (the doors helper's job requests).  Each is checked again below.
    [ValidateSet('', 'set', 'delete', 'run')] [string]$JobOp = '',
    [string]$JobName = '',
    [string]$JobSchedule = '',
    [string]$ForUser = '',
    [string]$AppDir = '',
    [string]$Result = '',
    [switch]$Api,
    [switch]$ApiNetwork,
    [ValidateSet('open', 'restrict', 'leave')] [string]$SshScope = 'leave',
    [switch]$SshIntoSd,
    # Ruling 17: Microsoft's OpenSSH MSI from the release folder, installed
    # first so the ssh steps below have a server to work on.  Install only.
    [string]$SshMsi = '',
    # 16 Nov 26 - SOLO 72 (Linux Solo 6d53db4, S.234 N9): Remove only.  The uninstaller's Keep was chosen, so Solo's ssh host
    # key pair stays in the admin-only machine folder for a reinstall (solo-sshd.ps1 -Uninstall -KeepHostKey).
    [switch]$KeepHostKey
)

$ErrorActionPreference = 'Stop'

# 12 Nov 26 - SOLO 62: Register-DoorsTask calls Get-Acl and Set-Acl (Microsoft.PowerShell.Security), so the module path is set to
# Windows PowerShell's own folders before any cmdlet, as solo-sshd.ps1 does and for its reason (RELEASE_1.1 111: a PowerShell 7
# parent passes its module folders on, and the Security module then fails to load).  SET, not removed.
$env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules"

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
$DoorsTaskName = 'SD Core Solo Doors'                                     # SOLO 62
$DoorsDir = Join-Path $env:ProgramData 'SDCoreSolo\doors'                # SOLO 62: the helper's answer and log
$SshPort = 4251        # SOLO_SSH_PORT - solo-sshd.ps1 and solo-ssh-firewall.ps1 carry the same number
# The markers of the block an EARLIER build wrote into the system sshd_config.  They are only ever
# used to take it OUT now (Remove-OldSshBlock), on Install, Upgrade and Remove.
$script:oldBlockRemoved = $false   # SOLO 36: set by Remove-OldSshBlock when it took the old route's block out
$script:taskKind = ''              # SOLO 38: 'startup' (S4U, at boot) or 'sign-in' (Interactive: Windows refused S4U for this user)
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
    if ($heading -like '--- API listener*')           { return 'API listener' }
    if ($heading -like '--- OpenSSH server*')         { return 'ssh server install' }
    if ($heading -like '--- the old ssh route*')      { return 'ssh' }
    if ($heading -like '--- ssh:*')                   { return 'ssh' }
    if ($heading -like '--- doors*')                  { return 'doors' }
    if ($heading -like '--- scheduled jobs*')         { return 'scheduled jobs' }
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
Note ('choices      : api=' + [bool]$Api + ' apinetwork=' + [bool]$ApiNetwork + ' sshscope=' + $SshScope + ' sshintosd=' + [bool]$SshIntoSd + ' sshmsi=' + [bool]$SshMsi)
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
    if (-not ($after -contains $Begin)) { $script:oldBlockRemoved = $true; Note ('  PASS  the old SD Core Solo block is gone from the system sshd_config (backup ' + $backup + ')') }
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
    $action   = New-ScheduledTaskAction -Execute $sdexe -Argument '-start' -WorkingDirectory (Split-Path $sdexe)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    # 06 Oct 26 - SOLO 38.  WINDOWS REFUSES THE S4U TASK ("Access is denied") FOR A STANDARD ACCOUNT, whoever
    # registers it: measured in a guest, a standard user's own unelevated registration, an administrator's, and
    # a SYSTEM task's were all refused, for a startup and a log-on trigger alike; an ADMINISTRATOR user's own
    # S4U task is accepted (the case this build was made for).  What a standard user can have, with no
    # elevation, is an Interactive task that runs when that user signs in.  So: S4U at startup first, exactly as
    # before, and where Windows refuses it the sign-in task - SD then starts when the user signs in, not at
    # boot - said plainly in the report.  A refusal of BOTH is a failure, as it always was.
    $script:taskKind = 'startup'
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Settings $settings `
            -Principal (New-ScheduledTaskPrincipal -UserId $ForUser -LogonType S4U -RunLevel Limited) `
            -Trigger (New-ScheduledTaskTrigger -AtStartup) -ErrorAction Stop | Out-Null
    }
    catch {
        Note ('  Windows refused a startup task that runs while nobody is signed in, for ' + $ForUser + ': ' + $_.Exception.Message.Trim())
        Note ('  registering a task that starts SD when ' + $ForUser + ' signs in instead')
        # THE SIGN-IN TASK MUST NOT RUN sd-solo.exe ITSELF, AND MUST NOT SHOW A WINDOW.  Measured on a guest, 6 Oct 2026:
        #  1. An Interactive task shows the console of its program.  "sd -start" returns and leaves sdwind, which
        #     stays attached to that console, so a window sat on the desktop with "SD (64 Bit) has been started" and
        #     a cursor, no ":" prompt - and CLOSING IT STOPPED SD (sdwind present before the close, gone after).
        #  2. A hidden PowerShell that starts SD with Start-Process -WindowStyle Hidden starts it with a console that
        #     has no window, and nothing stays resident - but powershell.exe itself FLASHED a Windows Terminal window
        #     for about 0.6 s (the default terminal host opens it before -WindowStyle Hidden applies; ten frames of
        #     a capture at 0.17 s show it).
        #  3. Giving PowerShell its own console host - conhost.exe --headless <powershell> ... - removes the flash:
        #     121 frames across the start show no window, sdwind was up 1.4 to 1.7 s after the trigger, still up
        #     12 s later, and no powershell.exe or sd-solo.exe was left.  (--headless is Windows 10 1809 or later;
        #     where it fails sdwind does not appear and the check below fails the step, loudly.)
        #  4. SIGNING OUT KILLS sdwind AND LEAVES ITS SHARED SEGMENT, and the next "sd -start" then refuses ("SD did
        #     not shut down cleanly ... Run sd-solo -stop to clear it").  The first version of this task, after one
        #     sign-out and sign-in, fired (last run 19:46:18, result 0x0) and started nothing - the hidden launcher
        #     reports success whatever sd-solo said.  So the task runs solo-start.ps1 (shipped beside the programs),
        #     which starts SD, clears that leftover with -stop when the start failed and no sdwind is running, starts
        #     once more, and logs what it did to solo-start.log.  Its path is in double quotes in -File, so a user
        #     name with a space or an apostrophe is safe.
        $startScript = Join-Path $AppDir 'solo-start.ps1'
        if (-not (Test-Path -LiteralPath $startScript)) { throw ('solo-start.ps1 is not in ' + $AppDir + ' - the sign-in task would have nothing to run') }
        $conhost = Join-Path $env:SystemRoot 'System32\conhost.exe'
        $action = New-ScheduledTaskAction -Execute $conhost -WorkingDirectory (Split-Path $sdexe) `
            -Argument ('--headless "' + $Ps + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $startScript + '"')
        Register-ScheduledTask -TaskName $TaskName -Action $action -Settings $settings `
            -Principal (New-ScheduledTaskPrincipal -UserId $ForUser -LogonType Interactive -RunLevel Limited) `
            -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $ForUser) -ErrorAction Stop | Out-Null
        $script:taskKind = 'sign-in'
    }
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { Fail 'the startup task was not registered'; return }
    Note ('  task registered: "' + $TaskName + '" as ' + $t.Principal.UserId + ', ' + $t.Principal.LogonType + ', ' + $(if ($script:taskKind -eq 'startup') { 'at startup' } else { 'at sign-in (no startup task: Windows refused it for this account)' }) + ', runs ' + $t.Actions[0].Execute + ' ' + $t.Actions[0].Arguments)

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
    else {
        Note ('  PASS  the SD server (sdwind.exe) is running as ' + $ForUser + ', session ' + $mine[0].SessionId)
        if ($script:taskKind -eq 'sign-in') { Note ('  startup     : SD starts when ' + $ForUser + ' signs in; it does not start before that') }
    }
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

    # 17 Nov 26 - D1: the lock-out guard runs BEFORE the sshd it watches starts.
    Register-SshGuardTask

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
    # 12 Nov 26 - SOLO 62: AN UPGRADE OVER A RUNNING SOLO sshd FAILED HERE, and the line said only 'read ""'.  The
    # same keyscan run by hand a minute later gave the choose_kex refusal below, which passes - so at install time it
    # said something else, most likely because the restarted sshd was not yet answering; the line had dropped what.
    # So it tries up to three times, 3 s apart, until it reads a key or the known refusal, and a failure prints the
    # exit code and stderr of the last try.  NOT MEASURED: what the upgrade's keyscan actually printed.
    $seen = ''; $errText = ''; $kexit = ''
    for ($try = 1; $try -le 3; $try++) {
        $kp = Start-Process -FilePath $keyscan -ArgumentList @('-t', 'ed25519', '-p', "$SshPort", '127.0.0.1') -NoNewWindow -Wait -PassThru `
                    -RedirectStandardOutput $ko -RedirectStandardError $ke
        $kexit = [string]$kp.ExitCode
        foreach ($l in @(Get-Content -LiteralPath $ko -ErrorAction SilentlyContinue)) {
            $f = $l -split '\s+'
            if ($f.Count -ge 3 -and $f[1] -eq 'ssh-ed25519') { $seen = $f[2] }
        }
        $errText = ((Get-Content -LiteralPath $ke -ErrorAction SilentlyContinue) -join ' ')
        if ($seen -ne '' -or $errText -match 'choose_kex|unsupported KEX') { break }
        Note ('  ssh-keyscan try ' + $try + ' read nothing (exit ' + $kexit + ', stderr "' + $errText.Trim() + '")')
        if ($try -lt 3) { Start-Sleep -Seconds 3 }
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
    Fail ('the host key served on port ' + $SshPort + ' is not Solo''s (' + $keyscan + ' read "' + $seen + '", exit ' + $kexit + ', stderr "' + $errText.Trim() + '")')
}

# ---- 17 Nov 26 - four-version audit D1: the ssh lock-out guard (Linux Solo's solo-sshguard.py, LSOLO 29) ---------------
# A third SYSTEM task, "SD Core Solo SSH Guard", at startup, no time limit, restarted on failure: PowerShell running the copy
# of solo-sshguard.ps1 that solo-sshd.ps1 -Install put in the ADMIN-ONLY machine folder (never the one in the user's Solo
# folder).  It reads sshd.log, and a locked address gets a Windows Firewall block rule SD-Solo-SSH-Guard-<address> on 4251
# (group "SD Core Solo ssh lock-out") for ten minutes.  It ships ON wherever Solo's ssh is set up, as Linux Solo's guard is
# part of its ssh unit.  Remove takes the task and every such rule away.  NOT MEASURED: the task running, a real lock.
$SshGuardTaskName = 'SD Core Solo SSH Guard'
$SshGuardRulePrefix = 'SD-Solo-SSH-Guard-'      # solo-sshguard.ps1 $RulePrefix

function Register-SshGuardTask {
    $guard = Join-Path $MachineSshDir 'solo-sshguard.ps1'
    if (-not (Test-Path -LiteralPath $guard)) { Fail ('the ssh lock-out guard is not in the machine folder (' + $guard + ')'); return }
    if (Get-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SshGuardTaskName -Confirm:$false
    }
    $arg = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $guard + '" -Serve'
    Register-ScheduledTask -TaskName $SshGuardTaskName `
        -Action (New-ScheduledTaskAction -Execute $Ps -Argument $arg) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                       -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                       -MultipleInstances IgnoreNew) | Out-Null
    $t = Get-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue
    if (-not $t) { Fail 'the ssh lock-out task was not registered'; return }
    Start-ScheduledTask -TaskName $SshGuardTaskName
    $running = $false
    for ($k = 0; $k -lt 20 -and -not $running; $k++) {
        if ((Get-ScheduledTask -TaskName $SshGuardTaskName).State -eq 'Running') { $running = $true } else { Start-Sleep -Milliseconds 500 }
    }
    Note ('  task "' + $SshGuardTaskName + '" as ' + $t.Principal.UserId + ', at startup, runs ' + $t.Actions[0].Execute + ' ' + $t.Actions[0].Arguments)
    if ($running) { Note '  PASS  the ssh lock-out guard is running (three wrong passwords from one address in ten minutes lock it for ten minutes)' }
    else { Fail ('the ssh lock-out task is not running (state ' + (Get-ScheduledTask -TaskName $SshGuardTaskName).State + ')') }
}

function Remove-SshGuardTask {
    if (Get-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $SshGuardTaskName -Confirm:$false
    }
    Get-NetFirewallRule -Name ($SshGuardRulePrefix + '*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $leftRules = @(Get-NetFirewallRule -Name ($SshGuardRulePrefix + '*') -ErrorAction SilentlyContinue)
    if (Get-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue) { Fail 'the ssh lock-out task is still registered' }
    elseif ($leftRules.Count -gt 0) { Fail ('ssh lock-out rules are still there: ' + (($leftRules | ForEach-Object { $_.Name }) -join ', ')) }
    else { Note '  PASS  no ssh lock-out task and no lock-out rule' }
}

function Remove-SshTask {
    # 17 Nov 26 - D1: the guard first - it runs from the machine folder that -Uninstall deletes.
    Remove-SshGuardTask
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue
    }
    # Stopping the task need not end the sshd it started; -Uninstall ends Solo's, by command line (never the
    # system sshd), and deletes the admin-only machine folder with its host key and config.
    # 16 Nov 26 - SOLO 72: with -KeepHostKey everything there goes but the host key pair.
    $sshdArgs = @('-Uninstall')
    if ($KeepHostKey) { $sshdArgs += '-KeepHostKey' }
    $null = Invoke-Shipped 'solo-sshd.ps1' $sshdArgs
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $SshTaskName -Confirm:$false
    }
    $left = Split-Path -Parent $MachineSshDir
    $keptKey = Join-Path $MachineSshDir 'ssh_host_ed25519_key'
    $extra = @()
    if (Test-Path -LiteralPath $left) {
        $extra = @(Get-ChildItem -LiteralPath $left -Recurse -Force -File | Where-Object { -not ($KeepHostKey -and (($_.FullName -eq $keptKey) -or ($_.FullName -eq ($keptKey + '.pub')))) })
    }
    if (Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue) { Fail 'the ssh startup task is still registered' }
    elseif ((Get-SoloSshd).Count -gt 0) { Fail 'Solo''s sshd is still running after the ssh task was removed' }
    elseif ($extra.Count -gt 0) { Fail ('the machine ssh folder ' + $left + ' still holds ' + (($extra | ForEach-Object { $_.Name }) -join ', ')) }
    elseif ((-not $KeepHostKey) -and (Test-Path -LiteralPath $left)) { Fail ('the machine ssh folder ' + $left + ' is still there') }
    elseif ($KeepHostKey -and (Test-Path -LiteralPath $keptKey)) { Note ('  PASS  no ssh task, no sshd of Solo''s running; the host key pair is kept in ' + $MachineSshDir) }
    else { Note '  PASS  no ssh task, no sshd of Solo''s running and no machine ssh folder' }
}

# ---- SOLO 62: the doors helper's task and folder, and the six changes it asks for ------------------------
function Register-DoorsTask {
    # The folder first: SYSTEM and Administrators full control, the user read only, nothing inherited, so the SYSTEM helper writes
    # its answer where the user cannot plant a link, and the user can read it.
    if (-not (Test-Path -LiteralPath $DoorsDir)) { New-Item -ItemType Directory -Path $DoorsDir -Force | Out-Null }
    $sid = (New-Object Security.Principal.NTAccount($ForUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [Security.AccessControl.PropagationFlags]::None
    foreach ($who in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($who)), 'FullControl', $inh, $none, 'Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'ReadAndExecute', $inh, $none, 'Allow')))
    Set-Acl -LiteralPath $DoorsDir -AclObject $acl
    $back = (Get-Acl -LiteralPath $DoorsDir).Access | Where-Object { $_.FileSystemRights -match 'Write|Modify|FullControl' } |
            ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    $odd = @($back | Where-Object { @('S-1-5-18', 'S-1-5-32-544') -notcontains $_ })
    if ($odd.Count -gt 0) { Fail ('the doors folder can be written by ' + ($odd -join ', ')); return }
    Note ('  PASS  ' + $DoorsDir + ': SYSTEM and Administrators write, ' + $ForUser + ' reads')

    if (Get-ScheduledTask -TaskName $DoorsTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $DoorsTaskName -Confirm:$false
    }
    $script = Join-Path $AppDir 'solo-doors.ps1'
    if (-not (Test-Path -LiteralPath $script)) { Fail ('solo-doors.ps1 is not at ' + $script); return }
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -Serve -AppDir "' + $AppDir + '" -ForUser "' + $ForUser + '"'
    Register-ScheduledTask -TaskName $DoorsTaskName `
        -Action (New-ScheduledTaskAction -Execute $Ps -Argument $arg) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                       -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew) | Out-Null
    # Who may start it: the user, read and execute; SYSTEM and Administrators full.  Set through the Task Scheduler's own object,
    # which is the only way to give a task a security descriptor.  NOT MEASURED: that this user can then start it.
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $task = $svc.GetFolder('\').GetTask($DoorsTaskName)
    $task.SetSecurityDescriptor(('D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;' + $sid + ')'), 0)
    $t = Get-ScheduledTask -TaskName $DoorsTaskName -ErrorAction SilentlyContinue
    if (-not $t) { Fail 'the doors task was not registered'; return }
    Note ('  PASS  task "' + $DoorsTaskName + '" as ' + $t.Principal.UserId + ', no trigger, runs ' + $t.Actions[0].Execute + ' ' + $t.Actions[0].Arguments)
    Note ('  task security descriptor: ' + $task.GetSecurityDescriptor(4))
}

function Remove-DoorsTask {
    if (Get-ScheduledTask -TaskName $DoorsTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $DoorsTaskName -Confirm:$false
    }
    if (Test-Path -LiteralPath $DoorsDir) { Remove-Item -LiteralPath $DoorsDir -Recurse -Force -ErrorAction SilentlyContinue }
    if (Get-ScheduledTask -TaskName $DoorsTaskName -ErrorAction SilentlyContinue) { Fail 'the doors task is still registered' }
    elseif (Test-Path -LiteralPath $DoorsDir) { Fail ('the doors folder ' + $DoorsDir + ' is still there') }
    else { Note '  PASS  no doors task and no doors folder' }
}

# ---- 16 Nov 26 - S.247: the scheduled jobs' tasks (see the header) -----------------------------------------------------------
# BEGIN solo_jobs_functions
$JobFolderName = 'SD Core Solo Jobs'
$JobTaskPath = '\' + $JobFolderName + '\'
$JobPrefix = 'sd-solo-job-'
$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'      # SD Core's \SD folder (sd-taskfolder.ps1): SYSTEM and Administrators

function Test-JobName([string]$n) { return ($n -cmatch '^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$') }
function Test-JobTime([string]$t) { return ($t -cmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$') }

# SD Core's sd-jobs.ps1 Get-JobSchedule, word for word but for taking the schedule as one string: the trigger XML of one of the five
# shapes, or $null for anything else.  The machine's own time; StartBoundary is a fixed day in the past.
function Get-JobTrigger([string]$sched) {
    $w = @(([string]$sched).Split(' ') | Where-Object { $_ -ne '' })
    $start = '2026-01-01T'
    $on = '<Enabled>true</Enabled>'
    if ($w.Count -lt 1) { return $null }
    switch -CaseSensitive ($w[0]) {
        'every' {
            if ($w.Count -ne 3 -or $w[2] -cne 'minutes' -or ($w[1] -cnotmatch '^(5|10|15|20|30)$')) { return $null }
            return "<TimeTrigger><Repetition><Interval>PT$($w[1])M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>${start}00:00:00</StartBoundary>$on</TimeTrigger>"
        }
        'hourly' {
            if ($w.Count -ne 1) { return $null }
            return "<TimeTrigger><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>${start}00:00:00</StartBoundary>$on</TimeTrigger>"
        }
        'daily' {
            if ($w.Count -ne 2 -or -not (Test-JobTime $w[1])) { return $null }
            return "<CalendarTrigger><StartBoundary>$start$($w[1]):00</StartBoundary>$on<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>"
        }
        'weekly' {
            $days = @{ mon = 'Monday'; tue = 'Tuesday'; wed = 'Wednesday'; thu = 'Thursday'; fri = 'Friday'; sat = 'Saturday'; sun = 'Sunday' }
            if ($w.Count -ne 3 -or ($w[1] -cnotmatch '^(mon|tue|wed|thu|fri|sat|sun)$') -or -not (Test-JobTime $w[2])) { return $null }
            return "<CalendarTrigger><StartBoundary>$start$($w[2]):00</StartBoundary>$on<ScheduleByWeek><DaysOfWeek><$($days[$w[1]]) /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>"
        }
        'monthly' {
            if ($w.Count -ne 3 -or ($w[1] -cnotmatch '^([1-9]|1[0-9]|2[0-8])$') -or -not (Test-JobTime $w[2])) { return $null }
            $months = '<January /><February /><March /><April /><May /><June /><July /><August /><September /><October /><November /><December />'
            return "<CalendarTrigger><StartBoundary>$start$($w[2]):00</StartBoundary>$on<ScheduleByMonth><DaysOfMonth><Day>$($w[1])</Day></DaysOfMonth><Months>$months</Months></ScheduleByMonth></CalendarTrigger>"
        }
    }
    return $null
}

# The task.  Nothing in it comes from a request but the name (checked) and the trigger (made from a checked schedule above); the
# program, its folder and the user are this script's own.
function Get-JobTaskXml([string]$n, [string]$sched, [string]$trigger, [string]$userSid) {
    $e = { param($t) [Security.SecurityElement]::Escape($t) }
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>SD Core Solo scheduled job $n ($sched); written by SET.JOB through the doors helper, changed only by SET.JOB; the command is in SD (sdsys\`$jobs)</Description></RegistrationInfo>
  <Triggers>$trigger</Triggers>
  <Principals><Principal id="Author"><UserId>$(& $e $userSid)</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec><Command>$(& $e $sdexe)</Command><Arguments>run.job $n</Arguments><WorkingDirectory>$(& $e (Split-Path $sdexe))</WorkingDirectory></Exec></Actions>
</Task>
"@
}

# SD Core's Test-SdAdminOwner (sd-taskfolder.ps1): SYSTEM, Administrators, or a member of Administrators.  Any doubt: false.
function Test-JobFolderOwner([string]$sid) {
    if (@('S-1-5-18', 'S-1-5-32-544') -contains $sid) { return $true }
    try {
        $name = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $grp = [ADSI]("WinNT://./$name,group")
        foreach ($m in @($grp.psbase.Invoke('Members'))) {
            $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
            if ($null -ne $bytes -and (New-Object Security.Principal.SecurityIdentifier([byte[]]$bytes, 0)).Value -eq $sid) { return $true }
        }
    } catch { return $false }
    return $false
}

# SD Core's Initialize-SdTaskFolder for "\SD Core Solo Jobs": made with its SDDL when missing; one that exists is used only when its
# owner is SYSTEM, Administrators or a member, and is given the SDDL again.  Throws on any doubt.
function Initialize-JobFolder($svc) {
    try { $f = $svc.GetFolder($JobTaskPath.TrimEnd('\')) } catch { return $svc.GetFolder('\').CreateFolder($JobFolderName, $JobFolderSddl) }
    $owner = (New-Object Security.AccessControl.RawSecurityDescriptor($f.GetSecurityDescriptor(0x1))).Owner
    if ($null -eq $owner -or -not (Test-JobFolderOwner $owner.Value)) {
        throw ('the task folder ' + $JobTaskPath + ' is owned by ' + $(if ($null -eq $owner) { 'nobody' } else { $owner.Value }) + ', which is not SYSTEM, Administrators or one of its members, so it is not used')
    }
    $f.SetSecurityDescriptor($JobFolderSddl, 0)
    return $f
}

# The schedule a definition in $jobs holds (its first field), or '' when there is no such plain file.  A directory file's record keeps
# its fields on separate lines.  SYSTEM only READS the user's folder here; it never writes there.
function Read-JobSchedule([string]$n) {
    $p = Join-Path (Join-Path (Join-Path $AppDir 'sdsys') '$jobs') $n
    $it = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    if ($null -eq $it -or $it.PSIsContainer -or ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $it.Length -gt 4096) { return '' }
    $raw = ([IO.File]::ReadAllText($p, [Text.Encoding]::GetEncoding(28591))) -replace "`r`n", "`n"
    return ([string]@($raw -split ("[`n" + [char]254 + "]"))[0]).Trim()
}

function Get-ForUserSid { return (New-Object Security.Principal.NTAccount($ForUser)).Translate([Security.Principal.SecurityIdentifier]).Value }

# One job's task, registered whole (any task of that name is deleted first, never updated in place) and read back.  Returns '' when
# it is in place, else why not; the caller says it (Fail for a request, a line for a restore).  May throw.
function Register-JobTask([string]$n, [string]$sched) {
    if (-not (Test-JobName $n)) { return ('job "' + $n + '": not a job name') }
    $trigger = Get-JobTrigger $sched
    if ($null -eq $trigger) { return ('job ' + $n + ': "' + $sched + '" is none of the five schedules') }
    $sid = Get-ForUserSid
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $f = Initialize-JobFolder $svc
    try { $f.DeleteTask($JobPrefix + $n, 0) } catch { }
    Register-ScheduledTask -TaskName ($JobPrefix + $n) -TaskPath $JobTaskPath -Xml (Get-JobTaskXml $n $sched $trigger $sid) -Force -ErrorAction Stop | Out-Null
    $task = $svc.GetFolder($JobTaskPath.TrimEnd('\')).GetTask($JobPrefix + $n)
    # Who may read it: the user (so SET.JOB can list its next and last run), and nothing more; SYSTEM and Administrators full.
    $task.SetSecurityDescriptor(('D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;' + $sid + ')'), 0)
    $t = Get-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + $n) -ErrorAction Stop
    $a = $t.Actions[0]
    if ([string]$t.Principal.LogonType -ne 'S4U' -or $a.Execute -ne $sdexe -or $a.Arguments -cne ('run.job ' + $n) -or $t.Principal.UserId -notmatch ('(^|\\)' + [regex]::Escape(($ForUser.Split('\'))[-1]) + '$|^' + [regex]::Escape($sid) + '$')) {
        return ('job ' + $n + ': the task read back is not the one written (' + $t.Principal.UserId + ', ' + $t.Principal.LogonType + ', ' + $a.Execute + ' ' + $a.Arguments + ')')
    }
    Note ('  PASS  task ' + $JobTaskPath + $JobPrefix + $n + ': ' + $t.Principal.UserId + ', ' + $t.Principal.LogonType + ', ' + $sched + ', runs ' + $a.Execute + ' ' + $a.Arguments)
    return ''
}

# One job's task stopped (a running one first: an unregistered task leaves its process running, SD Core's RELEASE_1.1 291) and removed.
# Returns 'deleted', 'absent' (there was none), or '' when it is still there.
function Remove-JobTask([string]$n) {
    $t = Get-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + $n) -ErrorAction SilentlyContinue
    if ($null -eq $t) { Note ('  no task ' + $JobTaskPath + $JobPrefix + $n); return 'absent' }
    if ([string]$t.State -eq 'Running') {
        Stop-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + $n) -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1500
    }
    Unregister-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + $n) -Confirm:$false -ErrorAction Stop
    if (Get-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + $n) -ErrorAction SilentlyContinue) { Fail ('job ' + $n + ': its task is still registered'); return '' }
    Note ('  PASS  task ' + $JobTaskPath + $JobPrefix + $n + ' removed')
    return 'deleted'
}

# The uninstaller's: every job task, then the folder when nothing is left in it.  $jobs itself is the user's data and is not touched.
function Remove-AllJobTasks {
    $all = @(Get-ScheduledTask -TaskPath $JobTaskPath -ErrorAction SilentlyContinue)
    foreach ($t in $all) {
        if ($t.TaskName -like ($JobPrefix + '*')) { $null = Remove-JobTask $t.TaskName.Substring($JobPrefix.Length) }
        else { Note ('  ' + $JobTaskPath + $t.TaskName + ' is not a job task; left as it is') }
    }
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $tf = $svc.GetFolder($JobTaskPath.TrimEnd('\'))
        if ($tf.GetTasks(1).Count -eq 0 -and $tf.GetFolders(0).Count -eq 0) { $svc.GetFolder('\').DeleteFolder($JobFolderName, 0) }
    } catch { }
    if (@(Get-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + '*') -ErrorAction SilentlyContinue).Count -gt 0) { Fail 'a job task is still registered' }
    else { Note ('  PASS  no job task (' + $all.Count + ' found)') }
}

# Install and Upgrade: every definition in $jobs gets its task.  One that cannot is said, and the rest go on (Linux's JOBS-RESTORE).
function Restore-JobTasks {
    $dir = Join-Path (Join-Path $AppDir 'sdsys') '$jobs'
    $d = Get-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
    if ($null -eq $d) { Note '  no job definitions ($jobs): nothing to schedule'; return }
    if (-not $d.PSIsContainer -or ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Note ('  ' + $dir + ' is a link or not a folder: no job was scheduled'); return }
    $n = 0; $bad = 0
    foreach ($it in @(Get-ChildItem -LiteralPath $dir -Force -File | Sort-Object Name)) {
        if (-not (Test-JobName $it.Name)) { continue }
        $sched = Read-JobSchedule $it.Name
        if ($null -eq (Get-JobTrigger $sched)) { Note ('  NOT SCHEDULED  job ' + $it.Name + ': its schedule "' + $sched + '" is none of the five'); $bad++; continue }
        # Said, and not a failure of the install: the definition is kept, and set.job lists the job not scheduled.
        try { $why = Register-JobTask $it.Name $sched } catch { $why = $_.Exception.Message.Trim() }
        if ($why -ne '') { Note ('  NOT SCHEDULED  ' + $why); $bad++; continue }
        $n++
    }
    Note ('  ' + $n + ' job(s) given their tasks from the definitions in $jobs' + $(if ($bad) { '; ' + $bad + ' not (set.job lists them not scheduled)' } else { '' }))
}
# END solo_jobs_functions

# 16 Nov 26 - S.247.  -Action Job: one job's task, asked for by solo-doors.ps1 after it checked the request.  The same functions as an
# install's.  Every value is checked again here; the verdict and "JOB RESULT   : <what>" are what the helper reads.
if ($Action -eq 'Job') {
    $jres = ''
    try {
        Note ''
        Note ('--- scheduled jobs: ' + $JobOp + ' ' + $JobName + $(if ($JobSchedule) { ' (' + $JobSchedule + ')' } else { '' }))
        if (@('set', 'delete', 'run') -cnotcontains $JobOp -or -not (Test-JobName $JobName)) { Fail 'give -JobOp set|delete|run and -JobName with a job name' }
        elseif ($JobOp -eq 'set') {
            $have = Read-JobSchedule $JobName
            if ($have -cne $JobSchedule) { Fail ('the definition of ' + $JobName + ' in $jobs does not hold the schedule "' + $JobSchedule + '" (it holds "' + $have + '")') }
            else {
                $why = Register-JobTask $JobName $JobSchedule
                if ($why -ne '') { Fail $why } else { $jres = 'set' }
            }
        }
        elseif ($JobOp -eq 'delete') {
            $jres = Remove-JobTask $JobName
        }
        else {
            if ((Read-JobSchedule $JobName) -eq '') { Fail ('there is no definition of ' + $JobName + ' in $jobs; nothing was started') }
            elseif ($null -eq (Get-ScheduledTask -TaskPath $JobTaskPath -TaskName ($JobPrefix + $JobName) -ErrorAction SilentlyContinue)) { Fail ('job ' + $JobName + ' has no task; set.job change gives it one') }
            else {
                # Through the Task Scheduler's COM object, as the doors verb starts the helper (Start-ScheduledTask is CIM).
                $svc = New-Object -ComObject Schedule.Service
                $svc.Connect()
                $null = $svc.GetFolder($JobTaskPath.TrimEnd('\')).GetTask($JobPrefix + $JobName).Run($null)
                Note ('  PASS  task ' + $JobTaskPath + $JobPrefix + $JobName + ' started')
                $jres = 'started'
            }
        }
    }
    catch {
        Fail ('ERROR ' + $_.Exception.Message)
        Note $_.ScriptStackTrace
    }
    Note ''
    if ($fails.Count -eq 0 -and $jres -ne '') { Note ('JOB RESULT   : ' + $jres); Note 'VERDICT      : PASS'; $dc = 0 }
    else { Note ('VERDICT      : FAIL - ' + ($fails -join '; ')); $dc = 1 }
    Save-Report
    exit $dc
}

# -Action Doors: one change, asked for by solo-doors.ps1 after it checked the request.  The same scripts and functions as an install.
if ($Action -eq 'Doors') {
    try {
        Note ''
        Note ('--- doors: ' + $Door + ' ' + $Mode)
        if (@('api', 'ssh') -notcontains $Door -or @('off', 'local', 'open') -notcontains $Mode) { Fail 'give -Door api|ssh and -Mode off|local|open' }
        elseif ($Door -eq 'api') {
            $c = Invoke-Shipped 'solo-api-listener.ps1' @('-Show')
            # 17 Nov 26 - from Core 8bd42f1a (RELEASE_1.1 317; audit round 1): local binds 127.0.0.1 (-Local), open every interface
            # (-On), as Linux Solo's LOCAL.  The bind moves only at start-up too, so a move between local and open is a change.
            $wasOn = (@($lines | Where-Object { $_ -match 'state\s*:\s*ON\b' }).Count -gt 0)
            $wasLocal = (@($lines | Where-Object { $_ -match 'state\s*:\s*ON\b.*APILOCAL' }).Count -gt 0)
            $wasMode = if (-not $wasOn) { 'off' } elseif ($wasLocal) { 'local' } else { 'open' }
            if ($Mode -eq 'off') {
                $c = Invoke-Shipped 'api-firewall.ps1' @('-Remove');         if ($c -ne 0) { Fail ('api-firewall.ps1 -Remove exited ' + $c) }
                $c = Invoke-Shipped 'solo-api-listener.ps1' @('-Off');       if ($c -ne 0) { Fail ('solo-api-listener.ps1 -Off exited ' + $c) }
            } else {
                $c = Invoke-Shipped 'api-firewall.ps1' @($(if ($Mode -eq 'open') { '-Open' } else { '-Restrict' }))
                if ($c -ne 0) { Fail ('api-firewall.ps1 exited ' + $c) }
                $lsw = if ($Mode -eq 'open') { '-On' } else { '-Local' }
                $c = Invoke-Shipped 'solo-api-listener.ps1' @($lsw);         if ($c -ne 0) { Fail ('solo-api-listener.ps1 ' + $lsw + ' exited ' + $c) }
            }
            if ($wasMode -ne $Mode) { Note 'NEXT START   : the API listener changes when SD is next started (sd-solo -stop, then sd-solo -start, or the next boot)' }
        }
        else {
            $have = [bool](Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue)
            if ($Mode -eq 'off') {
                if ($have) {
                    Stop-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue
                    $null = Invoke-Shipped 'solo-sshd.ps1' @('-Stop')
                    Disable-ScheduledTask -TaskName $SshTaskName | Out-Null
                    if ((Get-ScheduledTask -TaskName $SshTaskName).State -ne 'Disabled') { Fail 'the ssh task is not disabled' }
                    elseif (Test-SshPortListening) { Fail ('something still listens on port ' + $SshPort) }
                    else { Note ('  PASS  the ssh task is disabled and nothing listens on ' + $SshPort + ' (its folder and host key are kept)') }
                } else { Note '  ssh was not set up: nothing to turn off' }
            } else {
                if (-not $have) {
                    Note '  ssh was not set up: setting it up now, as the installer would (the owner: "set it up from the page")'
                    # 12 Nov 26 (the first VM witness: "there is no sshd.exe"): a Solo installed without ssh may have no OpenSSH
                    # server on the computer at all.  The installer keeps the MSI in <Solo folder>\ssh-server (sd-solo.iss), so it
                    # is installed from there by the install step's own function, exactly as -SshMsi does.
                    if (-not (Find-Sshd)) {
                        $kept = @(Get-ChildItem -LiteralPath (Join-Path $AppDir 'ssh-server') -Filter '*.msi' -ErrorAction SilentlyContinue)
                        if ($kept.Count -eq 0) { Fail ('there is no ssh server on this computer and no OpenSSH MSI in ' + (Join-Path $AppDir 'ssh-server') + ' - run the SD Core Solo installer again') }
                        else { Install-SshMsi $kept[0].FullName }
                    }
                    if ($fails.Count -eq 0) { Register-SshTask }
                } else {
                    Enable-ScheduledTask -TaskName $SshTaskName | Out-Null
                    # 17 Nov 26 - D1: the lock-out guard runs whenever ssh does.
                    $g = Get-ScheduledTask -TaskName $SshGuardTaskName -ErrorAction SilentlyContinue
                    if (-not $g) { Register-SshGuardTask } elseif ($g.State -ne 'Running') { Start-ScheduledTask -TaskName $SshGuardTaskName }
                    if (-not (Test-SshPortListening)) { Start-ScheduledTask -TaskName $SshTaskName }
                    $ok = $false
                    for ($k = 0; $k -lt 30 -and -not $ok; $k++) { if (Test-SshPortListening) { $ok = $true } else { Start-Sleep -Seconds 1 } }
                    if ($ok) { Note ('  PASS  the ssh task is enabled and port ' + $SshPort + ' listens') } else { Fail ('nothing listens on port ' + $SshPort + ' after the ssh task was started') }
                }
                if ($fails.Count -eq 0) {
                    $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @($(if ($Mode -eq 'open') { '-Open' } else { '-Restrict' }))
                    if ($c -ne 0) { Fail ('solo-ssh-firewall.ps1 exited ' + $c) }
                }
            }
        }
    }
    catch {
        Fail ('ERROR ' + $_.Exception.Message)
        Note $_.ScriptStackTrace
    }
    Note ''
    if ($fails.Count -eq 0) { Note 'VERDICT      : PASS'; $dc = 0 } else { Note ('VERDICT      : FAIL - ' + ($fails -join '; ')); $dc = 1 }
    Save-Report
    exit $dc
}

try {
    # 06 Oct 26 - SOLO 33, THE OWNER'S CHOICE OF OPTION 1: THE ORDER IS THE FIX.  On Install and Upgrade the firewall
    # rule, and on Install the listener switch, come BEFORE the startup task.  Windows shows its "allow this app?"
    # alert the first time a program listens with no rule - measured on 6 Oct 2026 in fresh guests - and the
    # first listening start used to be solo-setup.ps1's unelevated "sd -start" in the user's session.  That start now
    # listens on nothing (sd.conf ships with APIPORT commented out), and the only start that listens is this
    # task's, in session 0, which cannot show an alert, with the rule already made.  A REMOVE keeps its old order.
    # 16 Nov 26 - S.247: the scheduled jobs' tasks go FIRST on a removal, so that no job starts while SD is being taken down.
    if ($Action -eq 'Remove') {
        Note ''
        Note '--- scheduled jobs (their tasks; the definitions in $jobs are the user''s data)'
        try { Remove-AllJobTasks } catch { Fail ('ERROR ' + $_.Exception.Message.Trim()) }
    }

    if ($Action -eq 'Remove') {
        Note ''
        Note '--- startup task'
        Remove-SoloTask
    }

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

        # 17 Nov 26 - from Core 8bd42f1a (RELEASE_1.1 317, its MatchApiListenerToScope; audit round 1): a kept API that is ON for this
        # computer only (the rule is not open to any address) listens on 127.0.0.1 from the first start, as Linux Solo's LOCAL.  An
        # open rule, or an API that is off, is left exactly as the user had it (nothing the user opened is shut).
        Note ''
        Note '--- API listener bind'
        $mark = $lines.Count
        $c = Invoke-Shipped 'solo-api-listener.ps1' @('-Show')
        $shown = @($lines | Select-Object -Skip $mark)
        $onAll = (@($shown | Where-Object { $_ -match 'state\s*:\s*ON\b' -and $_ -notmatch 'APILOCAL' }).Count -gt 0)
        $scope = ''
        try {
            $fw = New-Object -ComObject HNetCfg.FwPolicy2
            foreach ($x in $fw.Rules) {
                if ($x.Name -eq 'SD Core Solo API (SDClient)' -and $x.Direction -eq 1) {
                    $scope = if (@(([string]$x.RemoteAddresses) -split ',') -contains '*') { 'open' } else { 'restricted' }
                    break
                }
            }
        } catch { $scope = '' }
        Note ('  listener on every interface: ' + $onAll + '   rule scope: ' + $(if ($scope -eq '') { '(no rule or unreadable)' } else { $scope }))
        if ($onAll -and $scope -eq 'restricted') {
            $c = Invoke-Shipped 'solo-api-listener.ps1' @('-Local')
            if ($c -ne 0) { Fail ('solo-api-listener.ps1 -Local exited ' + $c) }
        } else { Note '  left as it is' }
    }

    # The listener follows the API box, on an install: ON after the rule above exists, OFF when the box is
    # unticked (which also cleans a kept sd.conf that still carries an APIPORT line).  An upgrade keeps sd.conf.
    if ($Action -eq 'Install') {
        Note ''
        Note '--- API listener switch'
        # 17 Nov 26 (RELEASE_1.1 317 carried): an API for this computer only listens on 127.0.0.1 (-Local); for the network, every interface.
        $c = Invoke-Shipped 'solo-api-listener.ps1' @($(if ($Api -and $ApiNetwork) { '-On' } elseif ($Api) { '-Local' } else { '-Off' }))
        if ($c -ne 0) { Fail ('solo-api-listener.ps1 exited ' + $c) }
    }

    if ($Action -ne 'Remove') {
        Note ''
        Note '--- startup task'
        # 06 Oct 26 - SOLO 38.  A throw here used to land in the catch at the bottom and END the whole step, so the
        # ssh task, its rule and 4251 were never tried although ssh was chosen (measured, a standard user).  The
        # startup task is recorded as a failed step and the rest goes on: nothing below depends on it.
        try { Register-SoloTask }
        catch {
            Fail ('ERROR ' + $_.Exception.Message.Trim())
            Note ('  ' + $_.ScriptStackTrace)
        }
        if ($Action -eq 'Install' -and $Api) {
            Note ''
            Note '--- API listener (running)'
            $listen = @()
            for ($k = 0; $k -lt 15 -and $listen.Count -eq 0; $k++) {
                $listen = @(Get-NetTCPConnection -State Listen -LocalPort 4249 -ErrorAction SilentlyContinue)
                if ($listen.Count -eq 0) { Start-Sleep -Seconds 1 }
            }
            foreach ($l in $listen) {
                $pn = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).Name
                Note ('  listener   : ' + $l.LocalAddress + ':4249  pid ' + $l.OwningProcess + '  ' + $pn)
            }
            if ($listen.Count -gt 0) { Note '  PASS  the API is listening on 4249 (SD started after the firewall rule and the listener switch)' }
            else { Fail 'nothing is listening on port 4249 although the API was chosen' }
        }
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
        # 06 Oct 26 - SOLO 36: Install: only when the installer asked for it (-SshIntoSd; the user's choice, or the
        # control file's ssh=).  Upgrade: only where Solo's sshd is ALREADY set up - its task is registered, or the
        # old route's block was just taken out (a Solo from before SOLO 28 is moved to its own sshd, as before) -
        # and never on a computer whose user chose no ssh, which "wherever sshd.exe is" would have turned on.
        $haveSshTask = [bool](Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue)
        $wantSsh = ($Action -eq 'Install' -and [bool]$SshIntoSd) -or ($Action -eq 'Upgrade' -and ($haveSshTask -or $script:oldBlockRemoved))
        if ($Action -eq 'Upgrade') { Note ('  upgrade: ssh task registered=' + $haveSshTask + '  old route block removed=' + [bool]$script:oldBlockRemoved) }
        if ($wantSsh) {
            Register-SshTask
            if ($Action -eq 'Install' -and $SshScope -ne 'leave') {
                # The one admin step Solo's ssh still has.
                $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @($(if ($SshScope -eq 'open') { '-Open' } else { '-Restrict' }))
                if ($c -ne 0) { Fail ('solo-ssh-firewall.ps1 exited ' + $c) }
            }
            elseif ($Action -eq 'Upgrade') {
                # An upgrade does not revisit a rule that is there, and no rule means this computer only,
                # which is what -Restrict would make.  Until 06 Oct 26 (SOLO 36) a MANAGED computer with no rule
                # was opened here, because the master reached it over Microsoft's port 22 before; the user
                # may have chosen otherwise now, so nothing is opened by an upgrade.
                $haveRule = @(Get-NetFirewallRule -Name 'SD-Solo-SSH-In-TCP' -ErrorAction SilentlyContinue).Count -gt 0
                Note ('  firewall   : rule SD-Solo-SSH-In-TCP present=' + $haveRule + ' (left as it is)')
            }
        }
        else { Note '  not set up: ssh was not chosen (or, on an upgrade, it was not set up before)' }
    }

    # SOLO 62: the doors helper (REMOTE.API / REMOTE.SSH), on every install and upgrade; taken away on removal.
    Note ''
    Note '--- doors helper'
    if ($Action -eq 'Remove') { Remove-DoorsTask } else { Register-DoorsTask }

    # 16 Nov 26 - S.247: every definition in $jobs gets its task (a reload's kept ones; on an upgrade, the tasks are made again whole).
    if ($Action -ne 'Remove') {
        Note ''
        Note '--- scheduled jobs (a task for each definition in $jobs)'
        Restore-JobTasks
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
