# solo-doors.ps1 - SD Core Solo's two doors (the API and ssh): report them, and change them for REMOTE.API and REMOTE.SSH.  SOLO 62.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-doors.ps1 -Show  -AppDir <Solo folder>
#       anyone, unelevated: what is installed, as "api mode: ...", "api listening: ...", "ssh mode: ...", "ssh listening: ...".
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-doors.ps1 -Serve -AppDir <Solo folder> -ForUser <DOMAIN\user>
#       the SYSTEM task "SD Core Solo Doors" only (solo-machine.ps1 registers it with these two arguments fixed): takes ONE
#       request from <Solo folder>\sdsys\doors.request, checks it, and does it.
#
# Exit 0 done / reported, 1 failed or refused, 2 could not run (a missing argument, not elevated for -Serve).
#
# WHY IT EXISTS (SOLO 62; the owner, 12 Nov 2026: option 2 "with the ability to manage remotely, not just console only - by
# design solo is less secure than core", and (i), "build as designed and accept" that the proof is only as strong as the
# user-writable $cred).  On Linux Solo the doors are the user's own systemd units; on Windows the API firewall rule, the ssh
# task and the ssh rule are machine objects that need elevation, which no Solo session has.  So this helper, run as SYSTEM by a
# task the installer registers and the Solo user may start, does the six door changes for a session that passed SD's admin
# gate - from the console or remotely.  It never asks Windows for consent.
#
# THE REQUEST AND ITS PROOF.  The verb (gpl.bp/remotedoor) writes doors.request in the Solo folder's sdsys: lines key=value,
#   version=1  door=api|ssh  mode=off|local|open  nonce=<base64>  time=<seconds>  cred=$admin|$global  proof=<base64>
#   (16 Nov 26 - SOLO 60: lower case, as the $cred ids now are; an older verb's $ADMIN|$GLOBAL is accepted too - -contains ignores case)
# where time is LOCAL seconds since 1 Jan 1970 (SD's date and time are local; this script counts the same way), and
#   authmsg = 'sd-solo-doors|v1|' + door + '|' + mode + '|' + nonce + '|' + time
#   proof   = ClientKey XOR HMAC-SHA256(StoredKey, authmsg)        (SCRAM's ClientProof over this message)
# ClientKey is HMAC(PBKDF2(password, salt, iter), "Client Key"), which only someone holding the password can make; StoredKey is
# SHA-256(ClientKey) and is what $cred keeps (gpl.bp/cred_set).  This script reads StoredKey from <sdsys>\$cred\<cred>, recovers
# ClientKey = proof XOR HMAC(StoredKey, authmsg), and acts only if SHA-256 of it equals StoredKey (compared in constant time).
# THE LIMIT, ACCEPTED BY THE OWNER (i): $cred is in the user's own folder and the user can write it, so a program running as the
# user can put a verifier of its own there and forge a proof.  The proof stops a request made without the password, nothing more.
# A request older than 300 seconds, from the future by more than 60, or with a nonce already used, is refused.
#
# WHAT IT DOES, AND ONLY THIS (six changes, words of this script mapped to the installer's own scripts through solo-machine.ps1
# -Action Doors, so there is one copy of each step):  api off | local | open;  ssh off | local | open.  Nothing from the request
# reaches a command line but those words, each checked against its list first.  The two fixed arguments (-AppDir, -ForUser) come
# from the task's definition, never from the request.
#
# THE ANSWER goes to %ProgramData%\SDCoreSolo\doors\result.txt, a folder only SYSTEM and Administrators can write and the user can
# read (made by solo-machine.ps1), so a SYSTEM process never writes into the user's own folder, where a link could aim it at
# another file.  The request file is read only if it is a plain file under 4 KB (not a link), and is deleted after reading.
# The result's first line is "nonce=<the request's nonce>", so the verb cannot read an older answer as its own; its success line is
# "SOLO API LISTENER <mode>" or "SOLO SSH LISTENER <mode>", printed only when solo-machine.ps1's verdict was PASS.
#
# THE API LISTENER ONLY MOVES AT START-UP.  Solo's daemon reads APIPORT once, as it starts; this does not restart it (a restart from
# here would end every session, a remote caller's included).  When the listener setting moved, the answer says so, and the verb
# prints when it takes effect: the next "sd-solo -stop" then "sd-solo -start", or the next boot.
#
# NOT MEASURED when written (12 Nov 2026): that the Solo user can start a SYSTEM task whose security descriptor grants it read and
# execute (solo-machine.ps1 sets it), and the whole path end to end.  A sitting owes both.
#
# 16 Nov 26 Windows port - from Linux Solo 2d3db81 (S.247), SCHEDULED JOBS: THE SAME HELPER REGISTERS, DELETES AND STARTS THEIR TASKS.
# WHY HERE: a job is a Task Scheduler task that runs as the Solo user with LogonType S4U, so that it runs while the user is signed out,
# and an unelevated session cannot register an S4U task (MEASURED: "Access is denied").  This helper is already the elevated door a Solo
# session has - registered by the installer, startable by the user alone, -AppDir and -ForUser fixed in its definition, a request file,
# a proof, an answer in the admin-only folder - so the jobs take a second KIND of request rather than a second SYSTEM task, folder,
# installer step and removal (the smaller change).  A job request is:
#   version=1  kind=job  op=set|delete|run  name=<job name>  [sched=<schedule>]  nonce=<base64>  time=<seconds>  [proof=<base64>]
# (a request with no kind is a door request, as before).  name passes SD Core's job name rule; sched (op=set only) is one of the five
# shapes, spelt as SET.JOB spells it; nothing else is read.  THE COMMAND IS NEVER IN THE REQUEST: it stays in the user's $jobs, and the
# task runs only <Solo folder>\usr\bin\sd-solo.exe run.job <name>, the program path from -AppDir and the user from -ForUser, both fixed
# by this task's definition.  op=set carries a proof made from the ACCOUNT password the person typed into SET.JOB (or the tool.jobs
# form), checked against $cred\sduser's StoredKey exactly as a door's is against $admin's, over
#   authmsg = 'sd-solo-jobs|v1|set|' + name + '|' + sched + '|' + nonce + '|' + time
# and the definition $jobs\<name> must already hold that schedule (SET.JOB writes it first).  op=delete and op=run carry no proof, as
# Linux's set.job delete and run ask no password: delete only takes a task away, and run starts a task that runs the user's own fixed
# command, which any process of the user could start as sd-solo.exe run.job <name> itself.  The same time window and nonce list apply.
# The work is solo-machine.ps1 -Action Job (one copy, which the installer's Install and Remove steps use too).  The success line is
# "SOLO JOB SET <name>", "SOLO JOB DELETED <name>", "SOLO JOB ABSENT <name>" (there was no task) or "SOLO JOB STARTED <name>".
# NOT MEASURED when written: that SYSTEM can register an S4U task for the Solo user (an elevated administrator can: the startup task),
# and any of it end to end.
# 20 Nov 26 - SOLO 74, WITHDRAWING THE PARAGRAPH ABOVE: SYSTEM CANNOT (sit8 VM: SET.JOB ADD refused; probe-solojob as SYSTEM "Access is
# denied", as the user PASS; row 280 measured the same on 13 Nov).  The job requests are removed; a request with kind=job is refused.
# The jobs run from the job clock, one task the installer's elevated step registers as the user (solo-machine.ps1 Register-JobClock).
#
# 18 Nov 26 SD Core Solo - SOLO 78 (audit P-4455): ssh's local is sshd's listen address, 127.0.0.1 (solo-sshd.ps1 -Listen), as the API's
# is APILOCAL; -Show reads it from the machine sshd_config ("ssh listen: ..."), and "ssh mode: open" needs it AND an open rule.
# 18 Nov 26 SD Core Solo - SOLO 78: both modes also carry ListenAddress ::1 (Windows' ssh client does not fall back from ::1 for
# "localhost"); the IPv4 line decides local or open, and a config without ::1 reads as local-v4only or open-v4only.
param(
    [switch]$Show,
    [switch]$Serve,
    [string]$AppDir = '',
    [string]$ForUser = ''
)
$ErrorActionPreference = 'Stop'
$ApiPort = 4249
$SshPort = 4251
$SshTaskName = 'SD Core Solo SSH'
$DoorsDir = Join-Path $env:ProgramData 'SDCoreSolo\doors'
$Ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Say([string]$t) { Write-Output ('solo-doors: ' + $t) }
Say ('mode   : ' + $(if ($Show) { 'Show' } elseif ($Serve) { 'Serve' } else { '(none given)' }) + '   app dir: ' + $AppDir + $(if ($Serve) { '   for: ' + $ForUser } else { '' }))
if (-not ($Show -xor $Serve)) { Say 'give exactly one of -Show or -Serve'; exit 2 }
if ($AppDir -eq '' -or -not (Test-Path -LiteralPath (Join-Path $AppDir 'sdsys'))) { Say 'no -AppDir, or it has no sdsys folder'; exit 2 }

function Invoke-Script([string]$Script, [string[]]$ScriptArgs) {
    $path = Join-Path $AppDir $Script
    if (-not (Test-Path -LiteralPath $path)) { return @{ Code = 99; Out = @($Script + ' is not there') } }
    $out = & $Ps -NoProfile -ExecutionPolicy Bypass -File $path @ScriptArgs 2>&1
    return @{ Code = $LASTEXITCODE; Out = @($out | ForEach-Object { [string]$_ }) }
}

# NO CIM IN -Show (12 Nov 2026, measured in Win11VM Solo WS2.0-0): in an ssh logon every CIM cmdlet fails with
# CimJob_BrokenCimSession - Get-NetTCPConnection, Get-ScheduledTask, and the firewall scripts' Get-NetFirewallRule - so
# the report the verb reads is taken through .NET and COM instead, which work in any logon.
#
# A firewall rule's scope: open, restricted or none, by the firewall scripts' own test read through the firewall's COM
# object, where a rule's Name is the DisplayName the scripts give it.  none: no rule, or one not for TCP on the port (an
# earlier build's rule on 4243 admits nothing on 4249); open: any remote address ('*', the COM spelling of 'Any');
# otherwise restricted.
function Get-Scope([string]$DisplayName, [int]$Port) {
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        $rule = $null
        foreach ($x in $fw.Rules) { if ($x.Name -eq $DisplayName -and $x.Direction -eq 1) { $rule = $x; break } }
        if ($null -eq $rule -or $rule.Protocol -ne 6 -or [string]$rule.LocalPorts -ne [string]$Port) { return 'none' }
        if (@(([string]$rule.RemoteAddresses) -split ',') -contains '*') { return 'open' }
        return 'restricted'
    } catch { return '' }
}

# 19 Nov 26 - RELEASE_1.1 317 (SD Core's sit7; owner: "warn only").  An enabled inbound BLOCK rule beats Solo's own rule: Windows
# makes one when somebody presses Cancel at its "allow sdwind through?" alert.  Reported, never removed (it may be the user's
# own): one "api blocked:" line per rule that covers this install's sdwind.exe (the API listener) or names TCP port $Port.  The
# COM object, as Get-Scope (no CIM in -Show).  COM: Direction 1 = in, Action 0 = block, Protocol 6 = TCP, 256 = any.
function Get-ApiBlocks([int]$Port) {
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        $sdwind = [System.IO.Path]::GetFullPath((Join-Path $AppDir 'usr\bin\sdwind.exe'))
        foreach ($x in $fw.Rules) {
            if ($x.Direction -ne 1 -or $x.Action -ne 0 -or -not $x.Enabled) { continue }
            $app = [string]$x.ApplicationName
            $byApp = ($app -ne '' -and [Environment]::ExpandEnvironmentVariables($app) -ieq $sdwind)
            $byPort = (($x.Protocol -eq 6 -or $x.Protocol -eq 256) -and (@(([string]$x.LocalPorts) -split ',') -contains [string]$Port))
            if ($byApp -or $byPort) { Write-Output ('api blocked: the Windows firewall rule "' + $x.Name + '" blocks the API, so other computers cannot connect until it is disabled or removed') }
        }
    } catch { Write-Output ('api blocked: unknown - the other firewall rules could not be read (' + $_.Exception.Message + ')') }
}

function Test-Listening([int]$Port) {
    return @([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() |
             Where-Object { $_.Port -eq $Port }).Count -gt 0
}

# A scheduled task through the Task Scheduler's COM object: $null when it is absent or this caller may not see it.
function Get-Task([string]$Name) {
    try { return (New-Object -ComObject Schedule.Service | ForEach-Object { $_.Connect(); $_ }).GetFolder('\').GetTask($Name) }
    catch { return $null }
}

# 18 Nov 26 - SOLO 78: the listen address in Solo's sshd_config (users may read the machine folder), the same reading as
# solo-sshd.ps1's Get-ConfigListen (that script's -Show uses CIM, which an ssh logon cannot, so it is not called from here):
# local, open, every (no ListenAddress line), none (no config), else other <list>.
function Get-SshConfigListen {
    $p = Join-Path $env:ProgramData 'SDCoreSolo\ssh\sshd_config'
    try {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return 'none' }
        $a = @([IO.File]::ReadAllLines($p) | ForEach-Object { if ($_ -match '^\s*ListenAddress\s+(\S+)') { $Matches[1] } })
    } catch { return 'unreadable' }
    if ($a.Count -eq 0) { return 'every' }
    # 18 Nov 26: ::1 is in both modes; the IPv4 line decides; a port is cut only from "[addr]:port" or an IPv4 "addr:port".
    $hosts = @($a | ForEach-Object {
        if ($_ -match '^\[([^\]]+)\](:\d+)?$') { $Matches[1] }
        elseif (($_.ToCharArray() | Where-Object { $_ -eq ':' }).Count -eq 1) { $_ -replace ':\d+$', '' }
        else { $_ } })
    $v6 = ($hosts -contains '::1')
    $rest = @($hosts | Where-Object { $_ -ne '::1' })
    $mode = ''
    if ($rest.Count -gt 0 -and @($rest | Where-Object { $_ -ne '127.0.0.1' }).Count -eq 0) { $mode = 'local' }
    elseif ($rest.Count -gt 0 -and @($rest | Where-Object { $_ -ne '0.0.0.0' -and $_ -ne '127.0.0.1' }).Count -eq 0 -and $rest -contains '0.0.0.0') { $mode = 'open' }
    if ($mode -eq '') { return ('other ' + ($a -join ',')) }
    if ($v6) { return $mode }
    return ($mode + '-v4only')
}

function Show-Doors {
    # The API: the listener line in sd.conf, then who may reach it.
    $r = Invoke-Script 'solo-api-listener.ps1' @('-Show', '-ConfPath', (Join-Path $AppDir 'sd.conf'))
    $on = $null
    foreach ($l in $r.Out) {
        if ($l -match 'state\s*:\s*ON\b') { $on = $true }
        elseif ($l -match 'state\s*:\s*OFF\b') { $on = $false }
    }
    if ($null -eq $on) { Say ('api mode: unknown - the listener setting could not be read (' + (($r.Out | Select-Object -Last 1)) + ')') }
    else {
        $scope = Get-Scope 'SD Core Solo API (SDClient)' $ApiPort
        $mode = if (-not $on) { 'off' } elseif ($scope -eq 'open') { 'open' } else { 'local' }
        Write-Output ('api mode: ' + $mode)
        if ($mode -eq 'open') { Get-ApiBlocks $ApiPort }   # 19 Nov 26 - RELEASE_1.1 317: open, unless a Block rule says otherwise
    }
    Write-Output ('api listening: ' + $(if (Test-Listening $ApiPort) { 'yes' } else { 'no' }))

    # ssh: Solo's own sshd, run by a SYSTEM task; not set up at all when there is no task.
    # 21 Nov 26 - SOLO 85 and SOLO 89 (VM sit12).  An ELEVATED caller is shown the SYSTEM task, so for it no task is "not set up", whatever
    # the machine ssh folder holds: a Keep keeps that folder for the host key, and the old test read it as set up, so a second Keep would
    # have noted ssh=local and turned ssh on.  An UNELEVATED caller is NOT shown the task (measured: a Disabled task came back as no task),
    # so for it the folder (ssh was set up once) with nothing on the port stands for an off task; it was reported as local, and the verb
    # then said "ssh is local ... nothing listens" right after remote.ssh off.  The one wrong reading left: an enabled task whose sshd has
    # not started yet (seconds after boot) reads off to an unelevated caller.  A task that cannot be seen while sshd listens reads as set up.
    $elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $t = Get-Task $SshTaskName
    $folder = Test-Path -LiteralPath (Join-Path $env:ProgramData 'SDCoreSolo\ssh')
    $sshUp = Test-Listening $SshPort
    if (-not $t -and -not $sshUp -and ($elevated -or -not $folder)) { Write-Output 'ssh mode: notsetup' }
    elseif (-not $t -and -not $sshUp) { Write-Output 'ssh mode: off' }
    elseif ($t -and -not $t.Enabled) { Write-Output 'ssh mode: off' }
    else {
        # 18 Nov 26 - SOLO 78: open only when sshd listens on more than 127.0.0.1 (its config's ListenAddress) AND the rule is
        # open; a config that listens on 127.0.0.1, or a rule for this computer only, is local.
        $scope = Get-Scope 'SD Core Solo ssh (port 4251)' $SshPort
        $listen = Get-SshConfigListen
        Write-Output ('ssh mode: ' + $(if ($scope -eq 'open' -and $listen -notlike 'local*') { 'open' } else { 'local' }))
    }
    Write-Output ('ssh listening: ' + $(if (Test-Listening $SshPort) { 'yes' } else { 'no' }))
    Write-Output ('ssh listen: ' + $(switch -regex (Get-SshConfigListen) { '^local$' { '127.0.0.1 and ::1 only' } '^open$' { '0.0.0.0 and ::1' }
        '^local-v4only$' { '127.0.0.1 only (no ::1: written again at the next change)' } '^open-v4only$' { '0.0.0.0 only (no ::1: written again at the next change)' }
        '^every$' { 'every address (an older build)' } '^none$' { 'no config' } default { $_ } }))
    # Where the helper answers, and whether the helper is there: the verb reads both.
    Write-Output ('doors dir: ' + $DoorsDir)
    Write-Output ('doors helper: ' + $(if ((Test-Path -LiteralPath $DoorsDir) -and (Get-Task 'SD Core Solo Doors')) { 'yes' } else { 'no' }))
}

if ($Show) { Show-Doors; exit 0 }

# ---------------------------------------------------------------- -Serve: the SYSTEM task's one request
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say ('refused: -Serve runs elevated (the task runs it as SYSTEM); this is ' + $me.Name); exit 2
}
if ($ForUser -eq '') { Say 'no -ForUser'; exit 2 }
if (-not (Test-Path -LiteralPath $DoorsDir)) { Say ('no ' + $DoorsDir + ' - the installer makes it'); exit 2 }
$Result = Join-Path $DoorsDir 'result.txt'
$Log = Join-Path $DoorsDir 'doors.log'
$Used = Join-Path $DoorsDir 'nonces.txt'
$lines = New-Object System.Collections.ArrayList
function Log([string]$t) { try { [IO.File]::AppendAllText($Log, ((Get-Date -Format s) + ' ' + $t + "`r`n")) } catch { } }
function Finish([string]$nonce, [bool]$ok, [string]$why) {
    $out = @('nonce=' + $nonce) + $lines.ToArray()
    if (-not $ok) { $out += ('REFUSED: ' + $why) }
    [IO.File]::WriteAllLines($Result, [string[]]$out, (New-Object Text.UTF8Encoding($false)))
    Log ($(if ($ok) { 'done ' } else { 'refused ' }) + $why)
    foreach ($o in $out) { Write-Output $o }
    exit $(if ($ok) { 0 } else { 1 })
}

$reqPath = Join-Path (Join-Path $AppDir 'sdsys') 'doors.request'
if (-not (Test-Path -LiteralPath $reqPath -PathType Leaf)) { Finish '' $false 'no request' }
$item = Get-Item -LiteralPath $reqPath -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4096) {
    Remove-Item -LiteralPath $reqPath -Force -ErrorAction SilentlyContinue
    Finish '' $false 'the request is a link or too large'
}
$text = [IO.File]::ReadAllText($reqPath, [Text.Encoding]::ASCII)
Remove-Item -LiteralPath $reqPath -Force -ErrorAction SilentlyContinue
$req = @{}
foreach ($l in ($text -split "[`r`n]+")) {
    $i = $l.IndexOf('=')
    if ($i -gt 0) { $req[$l.Substring(0, $i).Trim()] = $l.Substring($i + 1).Trim() }
}
$nonce = [string]$req['nonce']
if ($nonce -notmatch '^[A-Za-z0-9+/=]{16,88}$') { Finish '' $false 'the nonce is missing or malformed' }
if ($req['version'] -ne '1') { Finish $nonce $false 'unknown request version' }
# 20 Nov 26 - SOLO 74: door requests only.  The job requests (kind=job, 16 Nov 26, S.247) are gone: this helper is SYSTEM, and Windows
# refuses SYSTEM an S4U task for another account (sit8, "Access is denied"), so it could never make a job's task.  The jobs run from one
# task the installer registers as the user (solo-machine.ps1 Register-JobClock).  A request that still names kind=job is refused here.
$kind = [string]$req['kind']
if ($kind -eq '') { $kind = 'door' }
if ($kind -cne 'door') { Finish $nonce $false 'unknown kind of request (scheduled jobs no longer go through this helper)' }
$time = [string]$req['time']
$door = [string]$req['door']; $mode = [string]$req['mode']; $cred = [string]$req['cred']
if (@('api', 'ssh') -notcontains $door) { Finish $nonce $false 'unknown door' }
if (@('off', 'local', 'open') -notcontains $mode) { Finish $nonce $false 'unknown mode' }
if (@('$admin', '$global') -notcontains $cred) { Finish $nonce $false 'unknown credential' }
if ($time -notmatch '^\d{1,12}$') { Finish $nonce $false 'the time is malformed' }
$now = [int64](((Get-Date) - [datetime]'1970-01-01').TotalSeconds)     # LOCAL seconds, as SD counts them
$age = $now - [int64]$time
if ($age -gt 300 -or $age -lt -60) { Finish $nonce $false ('the request is ' + $age + ' seconds old') }
$seen = @()
if (Test-Path -LiteralPath $Used) { $seen = @([IO.File]::ReadAllLines($Used)) }
if ($seen -contains $nonce) { Finish $nonce $false 'the nonce was used before' }
[IO.File]::WriteAllLines($Used, [string[]](@($seen | Select-Object -Last 199) + $nonce))

# The proof: the verifier is field 5 of $cred's record (StoredKey, base64).  A directory file's record keeps its fields on separate lines.
# A door's is over $admin (or $global).
if ($true) {
    $credFile = Join-Path (Join-Path (Join-Path $AppDir 'sdsys') '$cred') $cred
    if (-not (Test-Path -LiteralPath $credFile -PathType Leaf)) { Finish $nonce $false ('no ' + $cred + ' credential') }
    $raw = ([IO.File]::ReadAllText($credFile, [Text.Encoding]::GetEncoding(28591))) -replace "`r`n", "`n"
    $fields = @($raw -split ("[`n" + [char]254 + "]"))     # one field per line (or per field mark, if the record kept them)
    if ($fields.Count -lt 5 -or $fields[0].Trim() -ne '2') { Finish $nonce $false ('the ' + $cred + ' record is not a version 2 (SCRAM) record') }
    try {
        $stored = [Convert]::FromBase64String($fields[4].Trim())
        $proof = [Convert]::FromBase64String([string]$req['proof'])
    } catch { Finish $nonce $false 'the proof or the verifier is not base64' }
    if ($stored.Length -ne 32 -or $proof.Length -ne 32) { Finish $nonce $false 'the proof or the verifier is not 32 bytes' }
    $authmsg = 'sd-solo-doors|v1|' + $door + '|' + $mode + '|' + $nonce + '|' + $time
    $hmac = New-Object Security.Cryptography.HMACSHA256 (, $stored)
    $sig = $hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($authmsg))
    $ck = New-Object byte[] 32
    for ($k = 0; $k -lt 32; $k++) { $ck[$k] = $proof[$k] -bxor $sig[$k] }
    $h = ([Security.Cryptography.SHA256]::Create()).ComputeHash($ck)
    $diff = 0
    for ($k = 0; $k -lt 32; $k++) { $diff = $diff -bor ($h[$k] -bxor $stored[$k]) }
    if ($diff -ne 0) { Finish $nonce $false 'the proof does not match the administrator password' }
}

Log ('accepted door=' + $door + ' mode=' + $mode + ' cred=' + $cred)

# The change, through the installer's own steps (solo-machine.ps1 -Action Doors), one copy of each.
$res = [IO.Path]::GetTempFileName()
$r = & $Ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $AppDir 'solo-machine.ps1') -Action Doors -Door $door -Mode $mode `
        -ForUser $ForUser -AppDir $AppDir -Result $res 2>&1
$code = $LASTEXITCODE
$report = @()
if (Test-Path -LiteralPath $res) { $report = @([IO.File]::ReadAllLines($res)); Remove-Item -LiteralPath $res -ErrorAction SilentlyContinue }
foreach ($l in $report) { [void]$lines.Add($l) }
$pass = ($code -eq 0) -and (@($report | Where-Object { $_ -eq 'VERDICT      : PASS' }).Count -gt 0)
if (-not $pass) { Finish $nonce $false ('solo-machine.ps1 -Action Doors exited ' + $code) }
[void]$lines.Add(('SOLO ' + $door.ToUpper() + ' LISTENER ' + $mode))
Finish $nonce $true ('door=' + $door + ' mode=' + $mode)
