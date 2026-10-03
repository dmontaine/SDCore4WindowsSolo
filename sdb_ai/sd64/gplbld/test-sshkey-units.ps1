# test-sshkey-units.ps1 - free-tier guard for solo-sshkey.ps1 (SOLO 24, rewritten for SOLO 28).
# Drives the helper, with solo-sshd.ps1 beside it, against a SCRATCH app folder and a SCRATCH
# profile (USERPROFILE is overridden in the child process), so it needs no tree, no elevation,
# no network and touches nothing real.  It never starts an sshd.  Prints each command and its
# output; a row that matched only an echo of its own input would be a false pass, so every row
# anchors on RESULT= / ERROR= / the file it wrote.
#
# SOLO 28: the key file is Solo's OWN, <app>\ssh\authorized_keys, read by Solo's own sshd on port
# 4251 (solo-sshd.ps1) - no longer the user's ~\.ssh\authorized_keys behind a "Match User" block in
# the system sshd_config.  The rows about that block, its position ahead of "Match Group
# administrators" and the elevated installer's recorded sdsys\ssh-hostkey are gone with the model
# they guarded; the rows below replace them.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcKey = Join-Path $here 'solo-sshkey.ps1'
$srcSshd = Join-Path $here 'solo-sshd.ps1'
foreach ($f in @($srcKey, $srcSshd)) { if (-not (Test-Path $f)) { Write-Host "NO TREE: $f missing"; exit 2 } }
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path $ssh)) { Write-Host "NO TREE: $ssh missing (needed to make test keys)"; exit 2 }

$origProfile = $env:USERPROFILE   # Run overrides it for the child; "& this-script" runs in the CALLER's process, so it is put back at the end
$root = Join-Path $env:TEMP ('sdsshkey-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$app = Join-Path $root 'app'; $prof = Join-Path $root 'profile'
New-Item -ItemType Directory -Path (Join-Path $app 'sdsys'), $prof | Out-Null
Copy-Item $srcKey (Join-Path $app 'solo-sshkey.ps1')
Copy-Item $srcSshd (Join-Path $app 'solo-sshd.ps1')
$helper = Join-Path $app 'solo-sshkey.ps1'
Write-Host "scratch root: $root"

$akf = Join-Path $app 'ssh\authorized_keys'
$oldAk = Join-Path $prof '.ssh\authorized_keys'

function New-Pub([int]$n) {
    $k = Join-Path $root ("k$n")
    & $ssh -q -t ed25519 -N '""' -f $k -C "test$n" | Out-Null
    return (Get-Content "$k.pub" -Raw).Trim()
}
$pubs = 1..6 | ForEach-Object { New-Pub $_ }
$fp = @{}
foreach ($i in 0..5) {
    $r = & $ssh -l -f (Join-Path $root ("k" + ($i + 1) + ".pub"))
    $fp[$i] = ($r -split '\s+')[1]
}

function Run([string]$name, [string[]]$a) {
    $env:USERPROFILE = $prof
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $helper @a 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host ('--- ' + $name + ' (exit ' + $code + ')'); Write-Host $out.TrimEnd()
    return @{ Out = $out; Code = $code }
}

$fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label"; $script:fail++ }
}

$r = Run 'ADD key 1' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'ADD installs, RESULT=ADDED, fingerprint matches ssh-keygen' ($r.Code -eq 0 -and $r.Out -match 'RESULT=ADDED' -and $r.Out.Contains('FPR=' + $fp[0]) -and $r.Out -match 'COUNT=1')
$line = (Get-Content $akf -Raw).Trim()
Check 'the line went into SOLO''S OWN file <app>\ssh\authorized_keys: restrict + key + our tag, comment replaced' ($line -match '^restrict ssh-ed25519 \S+ sdcoresolo-managed$' -and $line -notmatch 'test1')
Check 'and nothing was written to the user''s ~\.ssh\authorized_keys' (-not (Test-Path $oldAk))
Check 'the answer names the port, 4251, and the user' ($r.Out -match '(?m)^PORT=4251\s*$' -and $r.Out -match '(?m)^OSUSER=\S+')

# The host-key fingerprint is Solo's OWN sshd's, read from the key solo-sshd.ps1 made.
$hostFpr = ((& $ssh -l -f (Join-Path $app 'ssh\ssh_host_ed25519_key.pub')) -split '\s+')[1]
Check "HOSTKEY is the fingerprint ssh-keygen gives for Solo's own host key (an independent instrument)" ($r.Out -match ('(?m)^HOSTKEY=' + [regex]::Escape($hostFpr) + '\s*$'))

$r = Run 'ADD key 1 again' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'second ADD is PRESENT and adds nothing' ($r.Out -match 'RESULT=PRESENT' -and @(Get-Content $akf).Count -eq 1)

# A key the owner put in the same file must survive everything.
$userKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUSERSOWNKEYUSERSOWNKEYUSERSOWNKEYUSERSOWN me@laptop'
[IO.File]::AppendAllText($akf, $userKey + "`n")
foreach ($i in 1..3) { $null = Run "ADD key $($i + 1)" @('-Verb', 'ADD', '-Key', $pubs[$i]) }
$r = Run 'ADD key 5 (the fifth)' @('-Verb', 'ADD', '-Key', $pubs[4])
Check 'cap of 4: the fifth ADD is refused and changes nothing' ($r.Code -eq 1 -and $r.Out -match 'ERROR=already 4' -and ((Get-Content $akf) | Where-Object { $_ -match 'sdcoresolo-managed' }).Count -eq 4)

$r = Run 'LIST' @('-Verb', 'LIST')
Check 'LIST shows the 4 fingerprints and not the owner''s key' ($r.Out -match 'RESULT=LISTED' -and $r.Out -match 'COUNT=4' -and ([regex]::Matches($r.Out, 'FPR=SHA256:')).Count -eq 4)

$r = Run 'REMOVE key 2' @('-Verb', 'REMOVE', '-Fingerprint', $fp[1])
Check 'REMOVE deletes only that key' ($r.Out -match 'RESULT=REMOVED' -and $r.Out -match 'COUNT=3')
$r = Run 'REMOVE key 2 again' @('-Verb', 'REMOVE', '-Fingerprint', $fp[1])
Check 'REMOVE of an absent key is ABSENT' ($r.Out -match 'RESULT=ABSENT')
Check "the owner's own key line is untouched" ((Get-Content $akf) -contains $userKey)
$r = Run 'REMOVE the owner key by a fingerprint that is not ours' @('-Verb', 'REMOVE', '-Fingerprint', 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
Check 'a fingerprint that is not ours removes nothing' ($r.Out -match 'RESULT=ABSENT' -and (Get-Content $akf) -contains $userKey)

$r = Run 'ADD garbage' @('-Verb', 'ADD', '-Key', 'ssh-ed25519 !!!notbase64!!!')
Check 'a key that is not base64 is refused' ($r.Code -eq 1 -and $r.Out -match 'ERROR=the key is not base64')
$r = Run 'ADD wrong type' @('-Verb', 'ADD', '-Key', 'ssh-dss AAAA')
Check 'an unsupported key type is refused' ($r.Code -eq 1 -and $r.Out -match 'ERROR=unsupported key type')

# The old route is MIGRATED the first time the helper runs after an upgrade: the master's key lines in
# ~\.ssh\authorized_keys move into Solo's own file, and the owner's own keys there stay.
$oldOurs = 'restrict ' + (($pubs[5] -split '\s+')[0]) + ' ' + (($pubs[5] -split '\s+')[1]) + ' sdcoresolo-managed'
$oldOwn = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLDOWNKEYOLDOWNKEYOLDOWNKEYOLDOWNKEYOLDO me@old'
New-Item -ItemType Directory -Path (Join-Path $prof '.ssh') | Out-Null
[IO.File]::WriteAllText($oldAk, ($oldOwn + "`n" + $oldOurs + "`n"))
$r = Run 'LIST after an old managed key appeared in ~\.ssh' @('-Verb', 'LIST')
Check 'the old managed line was migrated: LIST now counts it (4), it is in Solo''s file' ($r.Out -match 'COUNT=4' -and ((Get-Content $akf) -contains $oldOurs))
Check 'and the owner''s own key in ~\.ssh\authorized_keys stayed there, the managed line left it' ((Get-Content $oldAk) -contains $oldOwn -and (Get-Content $oldAk) -notcontains $oldOurs)

# Refusals that must change nothing.
$before = (Get-Content $akf -Raw)
Remove-Item (Join-Path $app 'solo-sshd.ps1') -Force
$r = Run 'ADD with solo-sshd.ps1 missing' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'no solo-sshd.ps1: refused with an ERROR, the key file unchanged' ($r.Code -eq 1 -and $r.Out -match 'ERROR=solo-sshd.ps1 is missing' -and (Get-Content $akf -Raw) -eq $before)
Copy-Item $srcSshd (Join-Path $app 'solo-sshd.ps1')

$r = Run 'a verb nobody defined' @('-Verb', 'FROB')
Check 'an unknown verb is refused by the parameter check, nothing changed' ($r.Code -ne 0 -and (Get-Content $akf -Raw) -eq $before)

$env:USERPROFILE = $origProfile
Remove-Item $root -Recurse -Force
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-sshkey units: ALL PASS'; exit 0 }
Write-Host "solo-sshkey units: $fail FAILED"; exit 1
