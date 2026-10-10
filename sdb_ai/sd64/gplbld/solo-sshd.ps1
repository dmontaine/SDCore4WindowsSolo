# solo-sshd.ps1 - SD Core Solo's OWN ssh server: its own sshd, on its own fixed port, run as SYSTEM,
# signing the owner in with his WINDOWS ACCOUNT NAME AND PASSWORD.  SOLO 28 (the multi-user port's
# RELEASE_1.1 118).
#
#   -Prepare      (ordinary user)  make <app>\ssh\authorized_keys, move old managed keys in, print facts
#   -Install      (ELEVATED)       make the admin-only machine folder, host key, config; check its permissions
#   -Stop         (ELEVATED)       end the sshd that was started from Solo's config
#   -Show         (anyone)         report, change nothing
#   -Uninstall    (ELEVATED)       -Stop, then delete the machine folder
#   -PrintConfig  (anyone)         print the sshd_config text for -OsUser, write nothing (the guard uses it)
# All with: powershell -NoProfile -ExecutionPolicy Bypass -File solo-sshd.ps1 <switch> [-OsUser name] [-AppDir path]
#
# THE OWNER'S RULINGS, 2 Oct 2026.  (1) Solo's ssh has its OWN port, FIXED AT 4251 and not adjustable, routed
# by port, no "Match User", no dedicated login; the full product keeps the system sshd on 22.  (2) Sign-in is
# the Windows ACCOUNT NAME AND PASSWORD, never a key or shared key to set up first - "that is the way I understood
# the sd core full works ... on any of the four versions" - so a key stays an OPTIONAL extra (the master's request
# 49 key, a person's own), never the only way in.  (3) After a probe in which he typed his own password, he chose
# to RUN SOLO'S sshd AS SYSTEM (the identity of the old port-22 route).
#
# WHY SYSTEM, MEASURED 2 Oct 2026 21:11 (probe-solo-sshd-password.ps1, the owner typed his own password; the log
# carries none): a PER-USER sshd, no administrator, VERIFIED the Windows password ("Accepted password for don")
# and then failed "CreateProcessAsUserW failed error:1314 / fork of unprivileged child failed" - 1314 is
# ERROR_PRIVILEGE_NOT_HELD: it cannot start the session under the logon token the password check made.  (A KEY
# login works there, using sshd's own token - which is what the first build relied on.)  Linux's non-root sshd got
# through only because PAM has a setuid helper that checks the caller's own password; Windows has no analogue.
#
# WHAT A SYSTEM PROCESS MAY NEVER DO: read or run anything a user can edit.  So the config, host key, pid file and
# log live in an ADMIN-ONLY folder, %ProgramData%\SDCoreSolo\ssh, made by the elevated installer step, and the
# startup task runs sshd.exe itself against that config - no script of the user's runs as SYSTEM, ever.  Users get
# read of the folder (the .pub fingerprint is what request 49 reports, and the config is not a secret) and NO write;
# the private key is SYSTEM and Administrators only.  -Install READS THE PERMISSIONS BACK and refuses to report
# success unless nobody else can write there, because a wrong ACL here is a privilege-escalation hole, not a
# cosmetic fault.  The one thing in the config that points into the user's own tree is the ForceCommand, which
# runs as the signed-in user (sshd starts it under that user's token), and the optional AuthorizedKeysFile.
#
# THE COST OF PASSWORD LOGIN, for the docs: anyone who can reach port 4251 can try passwords for the owner's
# Windows account, and the account lockout policy then locks the OWNER out (here: 10 failures in 10 minutes).  The
# old port-22 route had the same property.  The firewall rule is open only when the owner chose it, or in managed mode.
#
# AN SSHD A SYSTEM TASK STARTED IS NOT READABLE FROM AN ORDINARY SHELL (measured: path, command line and owner read
# empty to an unelevated shell, even of the same user; an elevated shell reads them).  -Stop finds sshd by command
# line, so unelevated it finds nothing while the port is held: it looks at who holds the port and REFUSES rather
# than answer NONE.  Run -Stop elevated, as solo-machine.ps1 does at upgrade and uninstall.
#
# LEGACY: the first build of SOLO 28 ran a per-user sshd from an S4U task out of <app>\ssh.  -Prepare deletes the
# files that build left there (config, host key, pid, log) and -Stop also ends an sshd started from that config.
#
# OUTPUT, one machine-readable line each (anchor on these, nothing else):
#   OSUSER=<name as sshd matches it>   PORT=4251   HOSTKEY=<SHA256:...>   KEYFILE=<path>   CONFIG=<path>
#   MACHINEDIR=<path>   MIGRATED=<n>   ACL=OK
#   RESULT=PREPARED|INSTALLED|STOPPED|NONE|REMOVED        ERROR=<text>  (exit 1)
# Exit 0 only with a RESULT= line.  -AppDir exists for the guard (test-solosshd-units.ps1), which runs this against a
# scratch tree with %ProgramData% and %USERPROFILE% overridden in the child; -Install ignores the %ProgramData%
# override and asks the OS for the folder, because it runs elevated.

param(
    [switch]$Prepare,
    [switch]$Install,
    [switch]$Stop,
    [switch]$Show,
    [switch]$Uninstall,
    [switch]$PrintConfig,
    [string]$AppDir = '',
    [string]$OsUser = ''
)

# 09 Oct 26 - RELEASE_1.1 111, the wider exposure (SD Core for Windows measured it the same day).  The Solo docs
# (17a) tell a person to run this script by hand, and a PowerShell 7 window passes its module folders on to the 5.1
# this starts, where Get-Acl (Get-AclProblems, below) fails to load.  Set to Windows PowerShell's own folders, as
# the full product's scripts now do; SET, not removed, because an absent value is rebuilt from machine and user
# settings.  Before any cmdlet.
$env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules"

# 'Continue', NOT 'Stop': under Stop, Windows PowerShell 5.1 turns a native command's stderr into
# a terminating error even on success (PROJECT_STATUS 6).  Every native call is checked by its
# exit code and by the file it was meant to make.
$ErrorActionPreference = 'Continue'

# SOLO_SSH_PORT.  Not a parameter, on purpose: the owner ruled it fixed.  solo-ssh-firewall.ps1
# carries the same number and test-solosshd-units.ps1 checks the two agree.
$Port = 4251
$Tag = 'sdcoresolo-managed'

function Stop-With([string]$m) { Write-Output ('ERROR=' + $m); exit 1 }

if ($AppDir -eq '') { $AppDir = $PSScriptRoot }
if (-not $AppDir) { Stop-With 'no app folder' }
$userSshDir = Join-Path $AppDir 'ssh'
$akFile  = Join-Path $userSshDir 'authorized_keys'
$legacyCfg = Join-Path $userSshDir 'sshd_config'
$sdExe   = Join-Path $AppDir 'usr\bin\sd-solo.exe'
$fwd     = { param($p) ($p -replace '\\', '/') }

# The machine folder.  -Install runs ELEVATED and takes it from the OS, never from an environment variable a
# user's session could have set; the user-level modes read %ProgramData% so the guard can point them at a scratch.
$machineRoot = $env:ProgramData
if ($Install -or $Uninstall) { $machineRoot = [Environment]::GetFolderPath('CommonApplicationData') }
if (-not $machineRoot) { Stop-With 'no ProgramData folder' }
$machineDir = Join-Path $machineRoot 'SDCoreSolo\ssh'
$cfg     = Join-Path $machineDir 'sshd_config'
$hostKey = Join-Path $machineDir 'ssh_host_ed25519_key'
$pidFile = Join-Path $machineDir 'sshd.pid'
$logFile = Join-Path $machineDir 'sshd.log'

function Test-Elevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# The name sshd matches this user by: lower case, no domain for a local account, user@domain for a
# domain one.  -Install is given it (-OsUser) by solo-machine.ps1, because the ELEVATED process may belong to a
# different administrator than the user Solo is for.
function Get-OsUser {
    $n = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $u = $n.Split('\')
    $name = $u[$u.Count - 1]
    if ($u.Count -gt 1 -and $u[0] -ine $env:COMPUTERNAME) { $name = $name + '@' + $u[0] }
    return $name.ToLower()
}

function Find-Sshd {
    foreach ($p in @((Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'),
                     (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return ''
}

function Find-Keygen {
    foreach ($p in @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'),
                     (Join-Path $env:ProgramFiles 'OpenSSH\ssh-keygen.exe'))) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return ''
}

function Get-Fingerprint([string]$b64) {
    try { $bytes = [Convert]::FromBase64String($b64) } catch { return '' }
    if ($bytes.Length -lt 8) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    return 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash($bytes)).TrimEnd('=')
}

# The configuration, as one pure function so a guard can print it, compare it with what is on disk and
# have sshd -t accept it.  LF, ASCII.  PasswordAuthentication is the point of the exercise; the key lines are
# the optional extra.  No AuthenticationMethods line: the owner may sign in by password OR by a key he chose to set up.
function Get-Config([string]$app, [string]$user, [string]$mdir) {
    return (@(
        '# SD Core Solo''s own sshd, run as SYSTEM by the startup task "SD Core Solo SSH".',
        '# Written by solo-sshd.ps1 -Install (elevated).  Do not edit; the installer rewrites it.',
        ('Port ' + $Port),
        ('HostKey ' + (& $fwd (Join-Path $mdir 'ssh_host_ed25519_key'))),
        ('PidFile ' + (& $fwd (Join-Path $mdir 'sshd.pid'))),
        ('AuthorizedKeysFile ' + (& $fwd (Join-Path (Join-Path $app 'ssh') 'authorized_keys'))),
        'StrictModes yes',
        'PasswordAuthentication yes',
        'PubkeyAuthentication yes',
        'KbdInteractiveAuthentication no',
        'PermitEmptyPasswords no',
        ('AllowUsers ' + $user),
        'DisableForwarding yes',
        'LogLevel INFO',
        ('ForceCommand "' + (Join-Path $app 'usr\bin\sd-solo.exe') + '"')
    ) -join "`n") + "`n"
}

# Moves the master's old key lines out of ~\.ssh\authorized_keys (where the system sshd's Match block
# read them) into Solo's own file, keeping a backup of the old file once.  Only OUR tagged lines
# move; the owner's own keys are never touched.  Returns the number moved.
function Move-OldManagedKeys {
    # An S4U boot task may start with no USERPROFILE in its environment, and Join-Path throws on an
    # empty string.  Ask the OS for the folder instead.
    $profileDir = $env:USERPROFILE
    if (-not $profileDir) { $profileDir = [Environment]::GetFolderPath('UserProfile') }
    if (-not $profileDir) { return 0 }
    $old = Join-Path $profileDir '.ssh\authorized_keys'
    if (-not (Test-Path -LiteralPath $old)) { return 0 }
    $oldLines = @([IO.File]::ReadAllLines($old))
    $rx = '^restrict\s+\S+\s+(\S+)\s+' + $Tag + '$'
    $ours = @($oldLines | Where-Object { $_ -match $rx })
    if ($ours.Count -eq 0) { return 0 }
    $have = @([IO.File]::ReadAllLines($akFile))
    $moved = 0
    $add = @()
    foreach ($l in $ours) {
        $blob = ($l -split '\s+')[2]
        $present = @($have | Where-Object { $_ -match $rx -and (($_ -split '\s+')[2]) -eq $blob })
        if ($present.Count -eq 0) { $add += $l; $moved++ }
    }
    if ($add.Count -gt 0) {
        [IO.File]::WriteAllLines($akFile, [string[]]($have + $add), (New-Object Text.UTF8Encoding($false)))
    }
    $bak = $old + '.sdcoresolo-backup'
    if (-not (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $old -Destination $bak }
    $keep = @($oldLines | Where-Object { $_ -notmatch $rx })
    [IO.File]::WriteAllLines($old, [string[]]$keep, (New-Object Text.UTF8Encoding($false)))
    return $moved
}

function Get-HostFingerprint {
    try {
        $t = ([IO.File]::ReadAllText($hostKey + '.pub').Trim() -split '\s+')
        if ($t.Count -ge 2) { return (Get-Fingerprint $t[1]) }
    } catch { }
    return ''
}

# ---- -Prepare: what the USER owns ----------------------------------------------------------
function Invoke-Prepare {
    $osUser = Get-OsUser
    if (-not (Test-Path -LiteralPath $userSshDir)) { New-Item -ItemType Directory -Path $userSshDir | Out-Null }
    if (-not (Test-Path -LiteralPath $userSshDir)) { Stop-With ('could not make ' + $userSshDir) }

    # What the first build of SOLO 28 left in <app>\ssh (a per-user sshd's config, host key, pid, log): useless
    # now and, for the host key, a private key sitting in the user's tree for nothing.
    foreach ($n in @('sshd_config', 'ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', 'sshd.pid', 'sshd.log', 'sshd-t.err', 'sshd-t.out')) {
        Remove-Item -LiteralPath (Join-Path $userSshDir $n) -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path -LiteralPath $akFile)) { [IO.File]::WriteAllText($akFile, '', (New-Object Text.UTF8Encoding($false))) }
    $moved = Move-OldManagedKeys

    # The fingerprint the multi-user product pinned used to be recorded here by an elevated step,
    # and it was the SYSTEM sshd's.  It is stale now and solo-sshkey.ps1 reads the real one.
    Remove-Item -LiteralPath (Join-Path $AppDir 'sdsys\ssh-hostkey') -Force -ErrorAction SilentlyContinue

    Write-Output ('OSUSER=' + $osUser)
    Write-Output ('PORT=' + $Port)
    Write-Output ('HOSTKEY=' + (Get-HostFingerprint))
    Write-Output ('KEYFILE=' + $akFile)
    Write-Output ('CONFIG=' + $cfg)
    Write-Output ('MACHINEDIR=' + $machineDir)
    Write-Output ('MIGRATED=' + $moved)
}

# ---- -Install: what only an administrator may own -------------------------------------------
$SidSystem = 'S-1-5-18'; $SidAdmins = 'S-1-5-32-544'; $SidUsers = 'S-1-5-32-545'

function Get-SidOf($identity) {
    try { return $identity.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return '' }
}

# THE READ-BACK.  Nobody but SYSTEM and Administrators may be able to change, add to or take ownership of
# anything here (the sshd runs as SYSTEM and trusts it); the private key may be seen by those two ONLY.
# Returns a list of problems, empty when the folder is as it must be.
function Get-AclProblems([string]$path, [bool]$privateOnly) {
    $problems = @()
    $acl = Get-Acl -LiteralPath $path
    $ownerSid = Get-SidOf (New-Object Security.Principal.NTAccount($acl.Owner))
    if (@($SidSystem, $SidAdmins) -notcontains $ownerSid) { $problems += ($path + ': owner is ' + $acl.Owner + ' (' + $ownerSid + '), not SYSTEM or Administrators') }
    $writeMask = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = Get-SidOf $ace.IdentityReference
        if (@($SidSystem, $SidAdmins) -contains $sid) { continue }
        if ($privateOnly) { $problems += ($path + ': ' + $ace.IdentityReference + ' has access to a private key'); continue }
        if (($ace.FileSystemRights -band $writeMask) -ne 0) { $problems += ($path + ': ' + $ace.IdentityReference + ' can write (' + $ace.FileSystemRights + ')') }
    }
    return $problems
}

function Invoke-Icacls([string[]]$a) {
    $o = & icacls.exe @a 2>&1
    if ($LASTEXITCODE -ne 0) { Stop-With ('icacls ' + ($a -join ' ') + ' failed (' + $LASTEXITCODE + '): ' + (($o | Out-String).Trim() -replace '\s+', ' ')) }
}

# Removes every principal on the file's ACL that is not in the keep list, BY SID, after the ACL has been cut down
# to what is wanted.  ssh-keygen gives the USER WHO RAN IT an explicit Modify ACE on both host-key files (found
# 2 Oct 2026, the first time -Install ran elevated: "ace\Don can write", "ace\Don has access to a private key"),
# and "icacls /inheritance:r /grant:r" leaves explicit ACEs alone.  Found by reading the ACL, not by guessing a
# name, and with no moment when the private key is readable by anyone else (a /reset would inherit Users:RX).
function Remove-ExtraAces([string]$path, [string[]]$keepSids) {
    $acl = Get-Acl -LiteralPath $path
    $extra = @($acl.Access | ForEach-Object { Get-SidOf $_.IdentityReference } | Where-Object { $_ -and ($keepSids -notcontains $_) } | Sort-Object -Unique)
    foreach ($sid in $extra) { Invoke-Icacls @($path, '/remove', ('*' + $sid)) }
}

# What goes into a config a SYSTEM process reads must not be able to add a line to it.  Checked BEFORE the
# elevation test so the guard can prove it without being elevated.
function Assert-ConfigInputs {
    if ($OsUser -eq '') { Stop-With 'give -OsUser: the login name sshd is to allow' }
    if ($OsUser -notmatch '^[A-Za-z0-9._@-]+$') { Stop-With ('refusing a login name with unexpected characters: ' + $OsUser) }
    if ($AppDir -match '["\r\n]') { Stop-With 'the app folder name has a quote or a line break in it' }
}

function Invoke-Install {
    Assert-ConfigInputs
    if (-not (Test-Elevated)) { Stop-With 'this needs an ELEVATED PowerShell - the machine folder must be admin-only' }
    $sshd = Find-Sshd
    if ($sshd -eq '') { Stop-With 'no sshd.exe (System32\OpenSSH or Program Files\OpenSSH)' }
    $keygen = Find-Keygen
    if ($keygen -eq '') { Stop-With 'no ssh-keygen.exe beside sshd.exe to make the host key' }

    if (-not (Test-Path -LiteralPath $machineDir)) { New-Item -ItemType Directory -Path $machineDir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $machineDir)) { Stop-With ('could not make ' + $machineDir) }
    # The folder: SYSTEM and Administrators full, Users read and traverse only, nothing inherited from ProgramData.
    Invoke-Icacls @($machineDir, '/inheritance:r', '/grant:r', ('*' + $SidSystem + ':(OI)(CI)F'), ('*' + $SidAdmins + ':(OI)(CI)F'), ('*' + $SidUsers + ':(OI)(CI)RX'))
    Invoke-Icacls @($machineDir, '/setowner', ('*' + $SidAdmins))
    # The parent, SDCoreSolo, was made on the way: same rule, no write for users.
    $parent = Split-Path -Parent $machineDir
    Invoke-Icacls @($parent, '/inheritance:r', '/grant:r', ('*' + $SidSystem + ':(OI)(CI)F'), ('*' + $SidAdmins + ':(OI)(CI)F'), ('*' + $SidUsers + ':(OI)(CI)RX'))
    Invoke-Icacls @($parent, '/setowner', ('*' + $SidAdmins))

    # The host key: kept across upgrades so clients do not see a changed key.
    if (-not (Test-Path -LiteralPath $hostKey) -or -not (Test-Path -LiteralPath ($hostKey + '.pub'))) {
        Remove-Item -LiteralPath $hostKey, ($hostKey + '.pub') -Force -ErrorAction SilentlyContinue
        $null = & $keygen -q -t ed25519 -N '""' -f $hostKey
        if (-not (Test-Path -LiteralPath $hostKey) -or -not (Test-Path -LiteralPath ($hostKey + '.pub'))) { Stop-With 'ssh-keygen did not make the host key' }
    }
    # The PRIVATE key: SYSTEM and Administrators only, owned by Administrators (the OpenSSH server checks both).
    Invoke-Icacls @($hostKey, '/inheritance:r', '/grant:r', ('*' + $SidSystem + ':F'), ('*' + $SidAdmins + ':F'))
    Remove-ExtraAces $hostKey @($SidSystem, $SidAdmins)
    Invoke-Icacls @($hostKey, '/setowner', ('*' + $SidAdmins))

    # The PUBLIC key may be read by anyone (request 49 reports its fingerprint) and written by SYSTEM and
    # Administrators only: the same cut, keeping the readers ssh-keygen and the folder give.
    Invoke-Icacls @(($hostKey + '.pub'), '/inheritance:r', '/grant:r', ('*' + $SidSystem + ':F'), ('*' + $SidAdmins + ':F'), ('*' + $SidUsers + ':R'))
    Remove-ExtraAces ($hostKey + '.pub') @($SidSystem, $SidAdmins, $SidUsers, 'S-1-1-0')
    Invoke-Icacls @(($hostKey + '.pub'), '/setowner', ('*' + $SidAdmins))

    $want = Get-Config $AppDir $OsUser $machineDir
    [IO.File]::WriteAllText($cfg, $want, (New-Object Text.UTF8Encoding($false)))
    Invoke-Icacls @($cfg, '/setowner', ('*' + $SidAdmins))

    # THE READ-BACK: every file the SYSTEM sshd will trust.
    $problems = @()
    foreach ($p in @($parent, $machineDir, $cfg, ($hostKey + '.pub'))) { $problems += @(Get-AclProblems $p $false) }
    $problems += @(Get-AclProblems $hostKey $true)
    if ($problems.Count -gt 0) {
        foreach ($p in $problems) { Write-Output ('PROBLEM=' + $p) }
        Stop-With ('the machine folder is not admin-only (' + $problems.Count + ' problem(s) above) - the SYSTEM sshd must not trust it')
    }

    $t = Start-Process -FilePath $sshd -ArgumentList @('-t', '-f', ('"' + $cfg + '"')) -NoNewWindow -Wait -PassThru `
             -RedirectStandardError (Join-Path $env:TEMP 'sd-solo-sshd-t.err') -RedirectStandardOutput (Join-Path $env:TEMP 'sd-solo-sshd-t.out')
    if ($t.ExitCode -ne 0) {
        $why = ((Get-Content -LiteralPath (Join-Path $env:TEMP 'sd-solo-sshd-t.err') -ErrorAction SilentlyContinue) -join ' | ')
        Stop-With ('sshd -t rejected the configuration: ' + $why)
    }

    Write-Output ('OSUSER=' + $OsUser)
    Write-Output ('PORT=' + $Port)
    Write-Output ('HOSTKEY=' + (Get-HostFingerprint))
    Write-Output ('MACHINEDIR=' + $machineDir)
    Write-Output ('CONFIG=' + $cfg)
    Write-Output 'ACL=OK'
}

# The sshd processes that were started from Solo's config (the machine one, or the legacy per-user one), by
# command line - never by name alone: the system sshd service is also called sshd.exe and must never be touched.
function Get-OurSshd {
    $needles = @($cfg.ToLower(), $legacyCfg.ToLower())
    return @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction SilentlyContinue |
             Where-Object { $c = $_.CommandLine; $c -and (@($needles | Where-Object { $c.ToLower().Contains($_) }).Count -gt 0) })
}

function Test-Listening { return (@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue).Count -gt 0) }

# The pids that hold the port, and the ones among them this shell cannot inspect (no command line).
function Get-PortHolders {
    return @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
             ForEach-Object { $_.OwningProcess } | Sort-Object -Unique)
}
function Get-BlindHolders {
    return @(Get-PortHolders | Where-Object {
        $p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $_) -ErrorAction SilentlyContinue
        (-not $p) -or (-not $p.CommandLine)
    })
}

function Invoke-Stop {
    $n = 0
    foreach ($p in (Get-OurSshd)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }
    if ($n -eq 0) {
        # THE NULL CASE, SAID OUT LOUD: nothing of ours was FOUND, but a holder this shell cannot read may be it.
        $blind = @(Get-BlindHolders)
        if ($blind.Count -gt 0) {
            Write-Output ('STOPPED=0')
            Stop-With ('port ' + $Port + ' is held by pid ' + ($blind -join ',') + ', which this shell cannot inspect (a process a SYSTEM task started is not readable from an ordinary shell).  Nothing was stopped.  Run -Stop from an ELEVATED PowerShell.')
        }
    }
    Write-Output ('STOPPED=' + $n)
    if ($n -gt 0) { Write-Output 'RESULT=STOPPED' } else { Write-Output 'RESULT=NONE' }
}

if (@($Prepare, $Install, $Stop, $Show, $Uninstall, $PrintConfig | Where-Object { $_ }).Count -ne 1) {
    Stop-With 'give exactly one of -Prepare, -Install, -Stop, -Show, -Uninstall or -PrintConfig'
}

if ($PrintConfig) {
    Assert-ConfigInputs
    Write-Output (Get-Config $AppDir $OsUser $machineDir).TrimEnd("`n")
    exit 0
}

if ($Show) {
    Write-Output ('SSHD=' + (Find-Sshd))
    Write-Output ('MACHINEDIR=' + $machineDir + ' exists=' + (Test-Path -LiteralPath $machineDir))
    Write-Output ('CONFIG=' + $cfg + ' exists=' + (Test-Path -LiteralPath $cfg))
    Write-Output ('KEYFILE=' + $akFile + ' exists=' + (Test-Path -LiteralPath $akFile))
    Write-Output ('PORT=' + $Port + ' listening=' + (Test-Listening))
    Write-Output ('PROCESSES=' + (Get-OurSshd).Count)
    Write-Output ('PORTHOLDERS=' + ((Get-PortHolders) -join ',') + ' cannot-inspect=' + ((Get-BlindHolders) -join ','))
    Write-Output 'RESULT=PREPARED'
    exit 0
}

if ($Stop) { Invoke-Stop; exit 0 }

if ($Uninstall) {
    if (-not (Test-Elevated)) { Stop-With 'this needs an ELEVATED PowerShell' }
    Invoke-Stop
    $parent = Split-Path -Parent $machineDir
    # A recursive delete as an administrator: refuse unless the folder is exactly ...\SDCoreSolo and its child is ssh.
    if ((Split-Path -Leaf $parent) -ne 'SDCoreSolo' -or (Split-Path -Leaf $machineDir) -ne 'ssh') { Stop-With ('refusing to delete ' + $parent + ' - it is not an SDCoreSolo folder') }
    if (Test-Path -LiteralPath $parent) { Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $parent) { Stop-With ('could not remove ' + $parent) }
    Write-Output ('MACHINEDIR=' + $machineDir + ' exists=False')
    Write-Output 'RESULT=REMOVED'
    exit 0
}

if ($Install) { Invoke-Install; Write-Output 'RESULT=INSTALLED'; exit 0 }

Invoke-Prepare
Write-Output 'RESULT=PREPARED'
exit 0
