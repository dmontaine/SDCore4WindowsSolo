# witness-solo-vm.ps1 - the Solo VM part of the 18 Nov 2026 sitting (SDCore4Windows .claude/vm-sitting-20261118.md, part V-S): what an
# uninstall-Keep-reinstall and an upgrade must carry across, recorded as text and compared.
#
#   powershell -ExecutionPolicy Bypass -File \\vboxsvr\xfer\witness-solo-vm.ps1 -Phase <phase> [-User <windows user>]
#
#   -Phase before          on the installed Solo, before the uninstall with KEEP (SOLO 72): records the state below
#   -Phase afterreinstall  after the Keep uninstall and the reinstall: compares with "before" (SOLO 72)
#   -Phase beforeupgrade   on an OLD Solo (WS1.2-0) before the new installer runs over it (260, 266, 335)
#   -Phase afterupgrade    after the new installer: compares with "beforeupgrade"
#
# AN ELEVATED PowerShell IN THE VM (the ssh host key's folder, %ProgramData%\SDCoreSolo\ssh, is administrators only).  -User names the
# Windows user Solo is installed for when that is not the one running this (default: this user).  It reads files and changes nothing.
# The sign-ins with the OLD passwords are NOT done here - Solo's sessions run as the ordinary user; they are the sitting's typed steps.
#
# WHAT IS RECORDED (state file \\vboxsvr\xfer\solo-vm-<phase>.txt, one "key = value" a line, readable on the host):
#   the ssh host key's public half (SHA-256 of the file), each $cred record (name and SHA-256), sd.conf (SHA-256), the audit trail
#   (length, and SHA-256 of its first <before's length> bytes on the later reading - so "joined" means the old trail is still its
#   start), the account folder's record count, voc_template's records (count and one SHA-256 over names + contents), the account's
#   examples (examples.bp record count).
# THE COMPARISONS (PASS / FAIL, each printed with both values):
#   afterreinstall vs before   host key same; every $cred record same; sd.conf same; audit starts with the old trail and is not shorter
#   afterupgrade vs beforeupgrade   host key same; $cred records all present (ids compared without case: 260 is about upper-case ids);
#                                   voc_template REPLACED (its hash differs); examples.bp still has records (335)
# Exit 0 every comparison PASS (or a recording phase that found everything), 1 a FAIL, 2 could not run.
#
# START-HISTORY:
# 18 Nov 26  New, for the sitting of 18 Nov (SOLO 72; 260, 266, 335).  NOT RUN.
# END-HISTORY

param(
    [Parameter(Mandatory = $true)][ValidateSet('before', 'afterreinstall', 'beforeupgrade', 'afterupgrade')][string]$Phase,
    [string]$User = $env:USERNAME,
    [string]$OutDir = '\\vboxsvr\xfer'
)
$ErrorActionPreference = 'Stop'
function Say([string]$s) { Write-Host $s; [void]$script:out.Add($s) }
$script:out = New-Object System.Collections.ArrayList
function Bail([string]$why) { Say ('CANNOT RUN: ' + $why); Say 'VERDICT: CANNOT RUN'; Save; exit 2 }
function Save { try { [IO.File]::WriteAllLines((Join-Path $OutDir ('solo-vm-' + $Phase + '.log')), [string[]]$script:out.ToArray(), (New-Object Text.UTF8Encoding($false))) } catch { Write-Host ('(log not written: ' + $_.Exception.Message + ')') } }
function Hash([string]$p) { if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } return 'ABSENT' }
function PrefixHash([string]$p, [long]$n) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return 'ABSENT' }
    $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
    try {
        if ($fs.Length -lt $n) { return 'SHORTER' }
        $buf = New-Object byte[] $n; $got = 0
        while ($got -lt $n) { $r = $fs.Read($buf, $got, [int]($n - $got)); if ($r -le 0) { break }; $got += $r }
        $sha = [Security.Cryptography.SHA256]::Create()
        return (($sha.ComputeHash($buf, 0, $got) | ForEach-Object { $_.ToString('X2') }) -join '')
    } finally { $fs.Close() }
}
function DirHash([string]$d) {
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { return @{ Count = -1; Hash = 'ABSENT' } }
    $files = @(Get-ChildItem -LiteralPath $d -File -Recurse | Sort-Object FullName)
    $sb = New-Object Text.StringBuilder
    foreach ($f in $files) { [void]$sb.Append($f.FullName.Substring($d.Length)).Append('=').Append((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash).Append(';') }
    $sha = [Security.Cryptography.SHA256]::Create()
    return @{ Count = $files.Count; Hash = (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString())) | ForEach-Object { $_.ToString('X2') }) -join '') }
}

Say ('=== witness-solo-vm -Phase ' + $Phase + '   ' + (Get-Date -Format s))
Say ('script : ' + $PSCommandPath)
Say ('machine: ' + $env:COMPUTERNAME + '   run by: ' + $env:USERNAME + '   Solo user: ' + $User)
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Bail 'not elevated - the host key folder is administrators only' }
if (-not (Test-Path -LiteralPath $OutDir)) { Bail ('the output folder ' + $OutDir + ' is not reachable (the xfer share)') }
$prof = (Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -match ('\\' + [regex]::Escape($User) + '$') } | Select-Object -First 1).LocalPath
if (-not $prof) { $prof = Join-Path (Split-Path $env:USERPROFILE) $User }
$Root = Join-Path $prof 'SDCoreSolo'
$Sdsys = Join-Path $Root 'sdsys'
$hostKeyPub = Join-Path $env:ProgramData 'SDCoreSolo\ssh\ssh_host_ed25519_key.pub'
$exe = Join-Path $Root 'usr\bin\sd-solo.exe'
Say ('Solo   : ' + $Root + '   sd-solo.exe exists: ' + (Test-Path -LiteralPath $exe) + $(if (Test-Path -LiteralPath $exe) { '   version ' + (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion + '   written ' + (Get-Item -LiteralPath $exe).LastWriteTime } else { '' }))
if (-not (Test-Path -LiteralPath $Sdsys)) { Bail ('no ' + $Sdsys + ' - Solo is not installed for ' + $User + ' (or the Keep uninstall removed it)') }

# --- record -----------------------------------------------------------------------------------------------------------------
$st = [ordered]@{}
$st['hostkey.pub'] = Hash $hostKeyPub
$credDir = Join-Path $Sdsys '$cred'
foreach ($f in @(Get-ChildItem -LiteralPath $credDir -File -ErrorAction SilentlyContinue | Sort-Object Name)) { $st['cred.' + $f.Name] = Hash $f.FullName }
$st['sd.conf'] = Hash (Join-Path $Root 'sd.conf')
$audit = Join-Path $Sdsys 'audit'
$st['audit.length'] = $(if (Test-Path -LiteralPath $audit) { (Get-Item -LiteralPath $audit).Length } else { -1 })
$st['audit.sha'] = PrefixHash $audit ([long]$st['audit.length'])   # the whole trail as it is now; a later phase hashes its first audit.length bytes
$acct = Join-Path $Root 'user_accounts\sduser'
$st['account.files'] = $(if (Test-Path -LiteralPath $acct) { @(Get-ChildItem -LiteralPath $acct -File -Recurse -ErrorAction SilentlyContinue).Count } else { -1 })
$vt = DirHash (Join-Path $Sdsys 'voc_template'); $st['voc_template.count'] = $vt.Count; $st['voc_template.hash'] = $vt.Hash
$ex = Join-Path $acct 'examples.bp'
$st['examples.bp.count'] = $(if (Test-Path -LiteralPath $ex) { @(Get-ChildItem -LiteralPath $ex -File -ErrorAction SilentlyContinue).Count } else { -1 })

Say ''
Say '--- recorded ---'
foreach ($k in $st.Keys) { Say ('  ' + $k + ' = ' + $st[$k]) }
$stateFile = Join-Path $OutDir ('solo-vm-' + $Phase + '.txt')
[IO.File]::WriteAllLines($stateFile, [string[]]@($st.Keys | ForEach-Object { $_ + ' = ' + $st[$_] }), (New-Object Text.UTF8Encoding($false)))
Say ('state file: ' + $stateFile)

$fails = 0; $passes = 0
function Cmp([string]$Row, [string]$Label, [bool]$Ok, [string]$Shown) {
    if ($Ok) { Say ('  PASS  ' + $Row + ': ' + $Label + '   (' + $Shown + ')'); $script:passes++ } else { Say ('  FAIL  ' + $Row + ': ' + $Label + '   (' + $Shown + ')'); $script:fails++ }
}
function Read-State([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { Bail ('no earlier state file ' + $p + ' - run that phase first') }
    $h = [ordered]@{}
    foreach ($l in [IO.File]::ReadAllLines($p)) { $i = $l.IndexOf(' = '); if ($i -gt 0) { $h[$l.Substring(0, $i)] = $l.Substring($i + 3) } }
    return $h
}

if ($Phase -eq 'before' -or $Phase -eq 'beforeupgrade') {
    if ($st['hostkey.pub'] -eq 'ABSENT') { Say '  NOTE: no ssh host key (was ssh not ticked at install?) - the host-key comparison will have nothing to compare' }
    if (@($st.Keys | Where-Object { $_ -like 'cred.*' }).Count -eq 0) { Bail 'no $cred record at all - nothing to carry across' }
    Say ''; Say 'VERDICT: RECORDED - now do the uninstall / upgrade, then run the matching after-phase'; Save; exit 0
}

if ($Phase -eq 'afterreinstall') {
    $b = Read-State (Join-Path $OutDir 'solo-vm-before.txt')
    Say ''; Say '--- SOLO 72: uninstall Keep, reinstall - compared with "before" ---'
    Cmp 'SOLO 72' 'the same ssh host key (public half)' ($b['hostkey.pub'] -ne 'ABSENT' -and $b['hostkey.pub'] -eq $st['hostkey.pub']) ('before ' + $b['hostkey.pub'].Substring(0, [Math]::Min(16, $b['hostkey.pub'].Length)) + ', now ' + $st['hostkey.pub'].Substring(0, [Math]::Min(16, $st['hostkey.pub'].Length)))
    foreach ($k in @($b.Keys | Where-Object { $_ -like 'cred.*' })) { Cmp 'SOLO 72' ('the register record ' + $k.Substring(5) + ' is the same (the passwords carried)') ($st.Contains($k) -and $st[$k] -eq $b[$k]) $(if ($st.Contains($k)) { 'same file: ' + ($st[$k] -eq $b[$k]) } else { 'GONE' }) }
    Cmp 'SOLO 72' 'sd.conf is the same' ($b['sd.conf'] -eq $st['sd.conf'] -and $st['sd.conf'] -ne 'ABSENT') ('same: ' + ($b['sd.conf'] -eq $st['sd.conf']))
    $oldLen = [long]$b['audit.length']
    $pre = PrefixHash $audit $oldLen
    Say ('  audit: before ' + $oldLen + ' bytes (SHA-256 ' + $b['audit.sha'] + '); now ' + $st['audit.length'] + ' bytes, its first ' + $oldLen + ' bytes SHA-256 ' + $pre)
    Cmp 'SOLO 72' 'the audit trail is joined: the old trail is the start of the new one, byte for byte' ($oldLen -gt 0 -and $pre -eq $b['audit.sha']) $(if ($pre -eq 'SHORTER') { 'the trail is now SHORTER than before' } else { 'prefix matches: ' + ($pre -eq $b['audit.sha']) })
    Say ('  account files: before ' + $b['account.files'] + ', now ' + $st['account.files'])
    Cmp 'SOLO 72' 'the account folder came back with its files' ([int]$st['account.files'] -ge [int]$b['account.files'] -and [int]$b['account.files'] -gt 0) ('before ' + $b['account.files'] + ', now ' + $st['account.files'])
}

if ($Phase -eq 'afterupgrade') {
    $b = Read-State (Join-Path $OutDir 'solo-vm-beforeupgrade.txt')
    Say ''; Say '--- 260, 266, 335: an upgrade over WS1.2-0 - compared with "beforeupgrade" ---'
    Cmp '260' 'the same ssh host key' ($b['hostkey.pub'] -eq $st['hostkey.pub']) ('same: ' + ($b['hostkey.pub'] -eq $st['hostkey.pub']))
    $oldIds = @($b.Keys | Where-Object { $_ -like 'cred.*' } | ForEach-Object { $_.Substring(5) })
    $newIds = @($st.Keys | Where-Object { $_ -like 'cred.*' } | ForEach-Object { $_.Substring(5) })
    Say ('  $cred before: ' + ($oldIds -join ' ') + '   after: ' + ($newIds -join ' '))
    foreach ($o in $oldIds) { Cmp '260' ('register record ' + $o + ' is still there (any case)') (@($newIds | Where-Object { $_ -ieq $o }).Count -ge 1) $(if (@($newIds | Where-Object { $_ -ieq $o }).Count) { 'now ' + (@($newIds | Where-Object { $_ -ieq $o }) -join ',') } else { 'GONE' }) }
    Cmp '266' 'voc_template was REPLACED by the upgrade (its records differ)' ($b['voc_template.hash'] -ne $st['voc_template.hash'] -and $st['voc_template.count'] -gt 0) ('before ' + $b['voc_template.count'] + ' records, now ' + $st['voc_template.count'] + '; same content: ' + ($b['voc_template.hash'] -eq $st['voc_template.hash']))
    Cmp '335' 'the account''s examples.bp still has records after the upgrade' ([int]$st['examples.bp.count'] -gt 0) ('before ' + $b['examples.bp.count'] + ', now ' + $st['examples.bp.count'])
    Say '  NOT HERE (typed steps): sign-in and ADMIN with the OLD passwords (260); update.accounts all does not refresh the administrator''s VOC twice (266)'
}

Say ''
Say ('=== ' + $passes + ' PASS, ' + $fails + ' FAIL')
if ($passes + $fails -eq 0) { Say 'VERDICT: NOTHING COMPARED'; Save; exit 2 }
if ($fails) { Say 'VERDICT: FAIL'; Save; exit 1 }
Say 'VERDICT: PASS'
Save
exit 0
