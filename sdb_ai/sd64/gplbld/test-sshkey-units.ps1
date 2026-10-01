# test-sshkey-units.ps1 - free-tier guard for solo-sshkey.ps1 (SOLO 24).
# Drives the helper against a SCRATCH profile and a SCRATCH sshd_config (USERPROFILE and
# ProgramData are overridden in a child process), so it needs no tree, no elevation and
# touches nothing real.  Prints each command and its output; a row that matched only an
# echo of its own input would be a false pass, so every row anchors on RESULT= / ERROR=.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$helper = Join-Path $here 'solo-sshkey.ps1'
if (-not (Test-Path $helper)) { Write-Host "NO TREE: $helper missing"; exit 2 }
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path $ssh)) { Write-Host "NO TREE: $ssh missing (needed to make test keys)"; exit 2 }

$root = Join-Path $env:TEMP ('sdsshkey-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $root | Out-Null
$prof = Join-Path $root 'profile'; $pd = Join-Path $root 'pd'
New-Item -ItemType Directory -Path $prof, (Join-Path $pd 'ssh') | Out-Null
Write-Host "scratch root: $root"

$begin = '# BEGIN SD Core Solo - added by its installer, removed by its uninstaller'
$end = '# END SD Core Solo'
$good = @('Subsystem sftp sftp-server.exe', $begin, 'Match User "scratch"', '    ForceCommand "x.exe"',
          '    AuthorizedKeysFile .ssh/authorized_keys', '    DisableForwarding yes', $end,
          'Match Group administrators', '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys')
$cfg = Join-Path $pd 'ssh\sshd_config'
function Set-Cfg([string[]]$l) { [IO.File]::WriteAllLines($cfg, $l) }
Set-Cfg $good

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
    $env:USERPROFILE = $prof; $env:ProgramData = $pd
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
$line = (Get-Content (Join-Path $prof '.ssh\authorized_keys') -Raw).Trim()
Check 'the line is restrict + key + our tag, comment replaced' ($line -match '^restrict ssh-ed25519 \S+ sdcoresolo-managed$' -and $line -notmatch 'test1')

$r = Run 'ADD key 1 again' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'second ADD is PRESENT and adds nothing' ($r.Out -match 'RESULT=PRESENT' -and @(Get-Content (Join-Path $prof '.ssh\authorized_keys')).Count -eq 1)

# A key the user owns must survive everything.
$akf = Join-Path $prof '.ssh\authorized_keys'
[IO.File]::AppendAllText($akf, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUSERSOWNKEYUSERSOWNKEYUSERSOWNKEYUSERSOWN me@laptop`n")
foreach ($i in 1..3) { $null = Run "ADD key $($i + 1)" @('-Verb', 'ADD', '-Key', $pubs[$i]) }
$r = Run 'ADD key 5 (the fifth)' @('-Verb', 'ADD', '-Key', $pubs[4])
Check 'cap of 4: the fifth ADD is refused and changes nothing' ($r.Code -eq 1 -and $r.Out -match 'ERROR=already 4' -and ((Get-Content $akf) | Where-Object { $_ -match 'sdcoresolo-managed' }).Count -eq 4)

$r = Run 'LIST' @('-Verb', 'LIST')
Check 'LIST shows the 4 fingerprints and not the user key' ($r.Out -match 'RESULT=LISTED' -and $r.Out -match 'COUNT=4' -and ([regex]::Matches($r.Out, 'FPR=SHA256:')).Count -eq 4)

$r = Run 'REMOVE key 2' @('-Verb', 'REMOVE', '-Fingerprint', $fp[1])
Check 'REMOVE deletes only that key' ($r.Out -match 'RESULT=REMOVED' -and $r.Out -match 'COUNT=3')
$r = Run 'REMOVE key 2 again' @('-Verb', 'REMOVE', '-Fingerprint', $fp[1])
Check 'REMOVE of an absent key is ABSENT' ($r.Out -match 'RESULT=ABSENT')
Check "the user's own key line is untouched" ((Get-Content $akf) -contains 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUSERSOWNKEYUSERSOWNKEYUSERSOWNKEYUSERSOWN me@laptop')
$r = Run 'REMOVE the user key by its own fingerprint' @('-Verb', 'REMOVE', '-Fingerprint', 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
Check 'a fingerprint that is not ours removes nothing' ($r.Out -match 'RESULT=ABSENT')

$r = Run 'ADD garbage' @('-Verb', 'ADD', '-Key', 'ssh-ed25519 !!!notbase64!!!')
Check 'a key that is not base64 is refused' ($r.Code -eq 1 -and $r.Out -match 'ERROR=the key is not base64')
$r = Run 'ADD wrong type' @('-Verb', 'ADD', '-Key', 'ssh-dss AAAA')
Check 'an unsupported key type is refused' ($r.Code -eq 1 -and $r.Out -match 'ERROR=unsupported key type')

# Install-state refusals: nothing may be written when sshd would not honour the line.
Remove-Item $akf -Force
Set-Cfg @('Subsystem sftp sftp-server.exe')
$r = Run 'ADD with no Solo block' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'no Solo block: refused, nothing written' ($r.Code -eq 1 -and $r.Out -match 'ERROR=ssh is not set up' -and -not (Test-Path $akf))
Set-Cfg @('Subsystem sftp sftp-server.exe', 'Match Group administrators', '  AuthorizedKeysFile x', $begin, 'Match User "scratch"', '    ForceCommand "x.exe"',
          '    AuthorizedKeysFile .ssh/authorized_keys', $end)
$r = Run 'ADD with the block AFTER the Group block' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'block behind another Match: refused (sshd would never read the file)' ($r.Code -eq 1 -and $r.Out -match 'not ahead of the other Match' -and -not (Test-Path $akf))
Set-Cfg @($begin, 'Match User "scratch"', '    ForceCommand "x.exe"', $end)
$r = Run 'ADD with no AuthorizedKeysFile line' @('-Verb', 'ADD', '-Key', $pubs[0])
Check 'block without the key-file override: refused' ($r.Code -eq 1 -and $r.Out -match 'does not read the user key file' -and -not (Test-Path $akf))

# The host-key fingerprint comes from the file the elevated installer records beside the
# helper (the ProgramData .pub is unreadable unelevated).  Copy the helper next to a
# scratch sdsys\ssh-hostkey and read it back.
$app = Join-Path $root 'app'
New-Item -ItemType Directory -Path (Join-Path $app 'sdsys') | Out-Null
Copy-Item $helper (Join-Path $app 'solo-sshkey.ps1')
$fakeFp = 'SHA256:' + ('A' * 43)
[IO.File]::WriteAllText((Join-Path $app 'sdsys\ssh-hostkey'), $fakeFp + "`r`n")
$helperOrig = $helper; $helper = Join-Path $app 'solo-sshkey.ps1'
Set-Cfg $good
$r = Run 'LIST with the recorded host key' @('-Verb', 'LIST')
Check 'HOSTKEY is the fingerprint the installer recorded' ($r.Out -match ('(?m)^HOSTKEY=' + [regex]::Escape($fakeFp) + '\s*$') -and $r.Out -match 'RESULT=LISTED')
[IO.File]::WriteAllText((Join-Path $app 'sdsys\ssh-hostkey'), "not a fingerprint`r`n")
$r = Run 'LIST with a corrupt record' @('-Verb', 'LIST')
Check 'a corrupt record is ignored, never echoed' ($r.Out -notmatch 'not a fingerprint' -and $r.Out -match 'RESULT=LISTED')
$helper = $helperOrig

Remove-Item $root -Recurse -Force
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-sshkey units: ALL PASS'; exit 0 }
Write-Host "solo-sshkey units: $fail FAILED"; exit 1
