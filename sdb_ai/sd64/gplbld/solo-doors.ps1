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
#   version=1  door=api|ssh  mode=off|local|open  nonce=<base64>  time=<seconds>  cred=$ADMIN|$GLOBAL  proof=<base64>
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

# A firewall rule's scope: open, restricted or none, through the script's own -ScopeFile verdict (the same test its -Show uses).
function Get-Scope([string]$Script) {
    $f = [IO.Path]::GetTempFileName()
    try {
        $r = Invoke-Script $Script @('-ScopeFile', $f)
        if ($r.Code -ne 0) { return '' }
        return ([IO.File]::ReadAllText($f)).Trim()
    } finally { Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue }
}

function Test-Listening([int]$Port) { return @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue).Count -gt 0 }

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
        $scope = Get-Scope 'api-firewall.ps1'
        $mode = if (-not $on) { 'off' } elseif ($scope -eq 'open') { 'open' } else { 'local' }
        Write-Output ('api mode: ' + $mode)
    }
    Write-Output ('api listening: ' + $(if (Test-Listening $ApiPort) { 'yes' } else { 'no' }))

    # ssh: Solo's own sshd, run by a SYSTEM task; not set up at all when there is no task.
    # An unelevated caller may not be shown a SYSTEM task (not measured), so "not set up" also needs the machine ssh folder absent
    # and nothing on the port; a task that cannot be seen while either is there reads as set up.
    $t = Get-ScheduledTask -TaskName $SshTaskName -ErrorAction SilentlyContinue
    $folder = Test-Path -LiteralPath (Join-Path $env:ProgramData 'SDCoreSolo\ssh')
    if (-not $t -and -not $folder -and -not (Test-Listening $SshPort)) { Write-Output 'ssh mode: notsetup' }
    elseif ($t -and $t.State -eq 'Disabled') { Write-Output 'ssh mode: off' }
    else {
        $scope = Get-Scope 'solo-ssh-firewall.ps1'
        Write-Output ('ssh mode: ' + $(if ($scope -eq 'open') { 'open' } else { 'local' }))
    }
    Write-Output ('ssh listening: ' + $(if (Test-Listening $SshPort) { 'yes' } else { 'no' }))
    # Where the helper answers, and whether the helper is there: the verb reads both.
    Write-Output ('doors dir: ' + $DoorsDir)
    Write-Output ('doors helper: ' + $(if ((Test-Path -LiteralPath $DoorsDir) -and (Get-ScheduledTask -TaskName 'SD Core Solo Doors' -ErrorAction SilentlyContinue)) { 'yes' } else { 'no' }))
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
$door = [string]$req['door']; $mode = [string]$req['mode']; $cred = [string]$req['cred']; $time = [string]$req['time']
if (@('api', 'ssh') -notcontains $door) { Finish $nonce $false 'unknown door' }
if (@('off', 'local', 'open') -notcontains $mode) { Finish $nonce $false 'unknown mode' }
if (@('$ADMIN', '$GLOBAL') -notcontains $cred) { Finish $nonce $false 'unknown credential' }
if ($time -notmatch '^\d{1,12}$') { Finish $nonce $false 'the time is malformed' }
$now = [int64](((Get-Date) - [datetime]'1970-01-01').TotalSeconds)     # LOCAL seconds, as SD counts them
$age = $now - [int64]$time
if ($age -gt 300 -or $age -lt -60) { Finish $nonce $false ('the request is ' + $age + ' seconds old') }
$seen = @()
if (Test-Path -LiteralPath $Used) { $seen = @([IO.File]::ReadAllLines($Used)) }
if ($seen -contains $nonce) { Finish $nonce $false 'the nonce was used before' }
[IO.File]::WriteAllLines($Used, [string[]](@($seen | Select-Object -Last 199) + $nonce))

# The verifier: field 5 of $cred's record (StoredKey, base64).  A directory file's record keeps its fields on separate lines.
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
