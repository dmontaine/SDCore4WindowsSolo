# solo-sshd.ps1 - SD Core Solo's OWN ssh server: a small sshd run by the Solo owner, as
# the owner, on its own fixed port.  SOLO 28 (the multi-user port's RELEASE_1.1 118).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-sshd.ps1 -Prepare   make the files, print facts
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-sshd.ps1 -Run       -Prepare, then run sshd (blocks)
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-sshd.ps1 -Stop      stop the sshd this script started
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-sshd.ps1 -Show      report, change nothing
#
# UNELEVATED BY DESIGN.  It runs as the Solo owner (from the S4U startup task solo-machine.ps1
# registers, "SD Core Solo SSH"), writes only under <app>\ssh, and never touches the system
# sshd, its sshd_config, its service or any firewall rule.
#
# WHY THIS EXISTS - THE OWNER'S RULING, 2 Oct 2026, put to him by the Linux agent (mail T3410)
# and confirmed here: "Separate port for sd-solo".  Solo's ssh listens on its OWN port, FIXED AT
# 4251 and not adjustable (like the API pair 4247/4249); the full product keeps the system sshd on
# 22.  Routing is by PORT, not by login name: no "Match User" block for Solo, no dedicated login,
# no reserved account name.  The person who owns Solo and is also a full-product user - the
# owner is both - uses 22 for the full product and 4251 for Solo.  Solo has ONE route: its own
# sshd and its own key file (<app>\ssh\authorized_keys), replacing both the old "Match User"
# block in the system sshd_config and the managed keys in ~\.ssh\authorized_keys.
#
# KEY-ONLY, AND THAT IS A CHANGE.  The system sshd signed Solo's owner in with the Windows
# PASSWORD (SOLO ruling 5).  A sshd run by an ordinary user has been MEASURED to accept a KEY
# login and to refuse a stranger's key (gplbld\probe-solo-sshd-port.ps1, 2 Oct 2026); logging a
# Windows PASSWORD in through a non-SYSTEM sshd is NOT measured, and nobody may type the owner's
# password into a test.  Linux Solo is key-only too (its owner ruled "Key-only").  The owner of
# this agent said "yes build it" to a plan that stated key-only.  A person with no key puts a
# public key in <app>\ssh\authorized_keys (the docs say how); the managed-mode master installs
# its own through API request 49 (solo-sshkey.ps1).
#
# MEASURED 2 Oct 2026, OpenSSH_for_Windows_9.5p2, ordinary user, loopback, scratch config:
#   - a private sshd started unelevated listened, accepted the owner's key (user authenticated
#     by "privileged process"), ran the ForceCommand as the owner; a stranger key was refused;
#     the system sshd on 22 was untouched.
#   - "StrictModes yes" works with the key file under the user's profile, and REFUSES the same
#     key once the file is writable by Everyone (control), accepting it again when the grant is
#     removed - so StrictModes stays ON here, as it does on Linux.
#   - a "Match User" ForceCommand overrides the full product's GLOBAL one, but a global
#     AllowGroups is not overridden - which is why routing by a Match block was never attractive.
# WITNESSED 2 Oct 2026 19:27-19:35 (cycle + verify-solo leg 18b): a key login to an sshd that the
#   S4U startup task started (pid 14372, session 0, owner the user, 4251) reaches sd-solo.
# NOT MEASURED: that task starting sshd AT BOOT with nobody signed in (the installer ran it that
#   time), a non-loopback client, the upgrade over a Solo that wrote the old Match block.
#
# *** AN SSHD THE TASK STARTED CANNOT BE INSPECTED FROM AN ORDINARY SHELL, MEASURED 2 Oct 2026. ***
#   Its path, command line and owner read as EMPTY to an unelevated shell of the same user (the
#   elevated installer reads them fine: "sshd.exe pid 14372 session 0 owner ace\Don"), and so does
#   its parent powershell.  Get-OurSshd finds sshd by command line, so from an ordinary shell it
#   finds NOTHING while the port is held.  -Stop, -Run and -Show therefore look at who holds the
#   port too, and say so rather than answer NONE: an ordinary shell cannot stop it - run -Stop
#   from an ELEVATED PowerShell (solo-machine.ps1 does, at uninstall and upgrade).
#
# FILES, all under <app>\ssh (the user's own tree: the profile's ACL - the user, SYSTEM,
# Administrators - is what StrictModes and the host-key check want):
#   sshd_config               rewritten on every start; do not edit
#   ssh_host_ed25519_key[.pub]  made once; its fingerprint is what request 49 tells the master
#   authorized_keys           the keys that may sign in; "restrict ... sdcoresolo-managed" lines
#                             are the master's (solo-sshkey.ps1), any other line is the owner's
#   sshd.pid, sshd.log
#
# OUTPUT, one machine-readable line each (anchor on these, nothing else):
#   OSUSER=<name as sshd matches it>   PORT=4251   HOSTKEY=<SHA256:...>
#   KEYFILE=<path>   CONFIG=<path>   MIGRATED=<n old managed key lines moved>
#   RESULT=PREPARED|RUNNING|ALREADY|STOPPED|NONE        ERROR=<text>  (exit 1)
# Exit 0 only with a RESULT= line.  -AppDir exists for the guard (test-solosshd-units.ps1),
# which runs this against a scratch tree; the installer and the task never pass it.

param(
    [switch]$Prepare,
    [switch]$Run,
    [switch]$Stop,
    [switch]$Show,
    [string]$AppDir = ''
)

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
$sshDir  = Join-Path $AppDir 'ssh'
$cfg     = Join-Path $sshDir 'sshd_config'
$hostKey = Join-Path $sshDir 'ssh_host_ed25519_key'
$akFile  = Join-Path $sshDir 'authorized_keys'
$pidFile = Join-Path $sshDir 'sshd.pid'
$logFile = Join-Path $sshDir 'sshd.log'
$sdExe   = Join-Path $AppDir 'usr\bin\sd-solo.exe'
$fwd     = { param($p) ($p -replace '\\', '/') }

# The name sshd matches this user by: lower case, no domain for a local account, user@domain for a
# domain one (the same rule solo-sshkey.ps1 and, before it, solo-machine.ps1 used).
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

# The configuration, as one pure function of (app folder, user name) so a guard can compare it
# with what is on disk and with what sshd -t accepts.  LF, ASCII.
function Get-Config([string]$app, [string]$osUser) {
    $s = Join-Path $app 'ssh'
    return (@(
        '# SD Core Solo''s own sshd - written by solo-sshd.ps1 and rewritten each time it starts.',
        '# Do not edit this file; put keys in authorized_keys beside it.',
        ('Port ' + $Port),
        ('HostKey ' + (& $fwd (Join-Path $s 'ssh_host_ed25519_key'))),
        ('PidFile ' + (& $fwd (Join-Path $s 'sshd.pid'))),
        ('AuthorizedKeysFile ' + (& $fwd (Join-Path $s 'authorized_keys'))),
        'StrictModes yes',
        'PubkeyAuthentication yes',
        'PasswordAuthentication no',
        'KbdInteractiveAuthentication no',
        'AuthenticationMethods publickey',
        ('AllowUsers ' + $osUser),
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
    # empty string - which would stop -Run before sshd started.  Ask the OS for the folder instead.
    # An S4U boot task may start with no USERPROFILE in its environment, and Join-Path throws on an
    # empty string - which would stop -Run before sshd started.  Ask the OS for the folder instead.
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

function Invoke-Prepare {
    $osUser = Get-OsUser
    if (-not (Test-Path -LiteralPath $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
    if (-not (Test-Path -LiteralPath $sshDir)) { Stop-With ('could not make ' + $sshDir) }

    $keygen = Find-Keygen
    if (-not (Test-Path -LiteralPath $hostKey) -or -not (Test-Path -LiteralPath ($hostKey + '.pub'))) {
        if ($keygen -eq '') { Stop-With 'no ssh-keygen.exe (System32\OpenSSH or Program Files\OpenSSH) to make the host key' }
        Remove-Item -LiteralPath $hostKey, ($hostKey + '.pub') -Force -ErrorAction SilentlyContinue
        $null = & $keygen -q -t ed25519 -N '""' -f $hostKey
        if (-not (Test-Path -LiteralPath $hostKey) -or -not (Test-Path -LiteralPath ($hostKey + '.pub'))) {
            Stop-With 'ssh-keygen did not make the host key'
        }
    }

    $want = Get-Config $AppDir $osUser
    $cur = ''
    if (Test-Path -LiteralPath $cfg) { $cur = [IO.File]::ReadAllText($cfg) }
    if ($cur -ne $want) { [IO.File]::WriteAllText($cfg, $want, (New-Object Text.UTF8Encoding($false))) }

    if (-not (Test-Path -LiteralPath $akFile)) { [IO.File]::WriteAllText($akFile, '', (New-Object Text.UTF8Encoding($false))) }
    $moved = Move-OldManagedKeys

    # The fingerprint the multi-user product pinned used to be recorded here by an elevated step,
    # and it was the SYSTEM sshd's.  It is stale now and solo-sshkey.ps1 reads the real one.
    Remove-Item -LiteralPath (Join-Path $AppDir 'sdsys\ssh-hostkey') -Force -ErrorAction SilentlyContinue

    $hk = ''
    try {
        $t = ([IO.File]::ReadAllText($hostKey + '.pub').Trim() -split '\s+')
        if ($t.Count -ge 2) { $hk = Get-Fingerprint $t[1] }
    } catch { $hk = '' }

    Write-Output ('OSUSER=' + $osUser)
    Write-Output ('PORT=' + $Port)
    Write-Output ('HOSTKEY=' + $hk)
    Write-Output ('KEYFILE=' + $akFile)
    Write-Output ('CONFIG=' + $cfg)
    Write-Output ('MIGRATED=' + $moved)
}

# The sshd processes that were started from THIS config, by command line - never by name alone:
# the system sshd service is also called sshd.exe and must never be touched.
function Get-OurSshd {
    $needle = $cfg.ToLower()
    return @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction SilentlyContinue |
             Where-Object { $_.CommandLine -and $_.CommandLine.ToLower().Contains($needle) })
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

if (@($Prepare, $Run, $Stop, $Show | Where-Object { $_ }).Count -ne 1) { Stop-With 'give exactly one of -Prepare, -Run, -Stop or -Show' }

if ($Show) {
    $sshd = Find-Sshd
    Write-Output ('SSHD=' + $sshd)
    Write-Output ('CONFIG=' + $cfg + ' exists=' + (Test-Path -LiteralPath $cfg))
    Write-Output ('KEYFILE=' + $akFile + ' exists=' + (Test-Path -LiteralPath $akFile))
    Write-Output ('PORT=' + $Port + ' listening=' + (Test-Listening))
    Write-Output ('PROCESSES=' + (Get-OurSshd).Count)
    Write-Output ('PORTHOLDERS=' + ((Get-PortHolders) -join ',') + ' cannot-inspect=' + ((Get-BlindHolders) -join ','))
    Write-Output 'RESULT=PREPARED'
    exit 0
}

if ($Stop) {
    $n = 0
    foreach ($p in (Get-OurSshd)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }
    if ($n -eq 0) {
        # THE NULL CASE, SAID OUT LOUD: nothing of ours was FOUND, but a holder this shell cannot read may be it.
        $blind = @(Get-BlindHolders)
        if ($blind.Count -gt 0) {
            Write-Output ('STOPPED=0')
            Stop-With ('port ' + $Port + ' is held by pid ' + ($blind -join ',') + ', which this shell cannot inspect (a process the startup task started is not readable from an ordinary shell).  Nothing was stopped.  Run -Stop from an ELEVATED PowerShell.')
        }
    }
    Write-Output ('STOPPED=' + $n)
    if ($n -gt 0) { Write-Output 'RESULT=STOPPED' } else { Write-Output 'RESULT=NONE' }
    exit 0
}

Invoke-Prepare
if ($Prepare) { Write-Output 'RESULT=PREPARED'; exit 0 }

# ---- -Run: the sshd itself ---------------------------------------------------------------
$sshd = Find-Sshd
if ($sshd -eq '') { Stop-With 'no sshd.exe (System32\OpenSSH or Program Files\OpenSSH)' }
if (-not (Test-Path -LiteralPath $sdExe)) { Stop-With ('no sd-solo.exe at ' + $sdExe + ' to force') }
$t = Start-Process -FilePath $sshd -ArgumentList @('-t', '-f', ('"' + $cfg + '"')) -NoNewWindow -Wait -PassThru `
         -RedirectStandardError (Join-Path $sshDir 'sshd-t.err') -RedirectStandardOutput (Join-Path $sshDir 'sshd-t.out')
if ($t.ExitCode -ne 0) {
    $why = ((Get-Content -LiteralPath (Join-Path $sshDir 'sshd-t.err') -ErrorAction SilentlyContinue) -join ' | ')
    Stop-With ('sshd -t rejected the configuration: ' + $why)
}
if (Test-Listening) {
    if ((Get-OurSshd).Count -gt 0) { Write-Output 'RESULT=ALREADY'; exit 0 }
    $blind = @(Get-BlindHolders)
    if ($blind.Count -gt 0) {
        Stop-With ('port ' + $Port + ' is already held by pid ' + ($blind -join ',') + ', which this shell cannot inspect - it may be this sshd, started by the startup task (readable only from an elevated shell).  Nothing was started.')
    }
    Stop-With ('port ' + $Port + ' is already in use by something that is not this sshd')
}
Write-Output 'RESULT=RUNNING'
$p = Start-Process -FilePath $sshd -ArgumentList @('-D', '-f', ('"' + $cfg + '"'), '-E', ('"' + $logFile + '"')) -NoNewWindow -Wait -PassThru
exit $p.ExitCode
