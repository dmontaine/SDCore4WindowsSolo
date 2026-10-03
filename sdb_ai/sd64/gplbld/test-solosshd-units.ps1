# test-solosshd-units.ps1 - free-tier guard for solo-sshd.ps1 (SOLO 28).
# Drives the script against a SCRATCH app folder and a SCRATCH profile (USERPROFILE is
# overridden for the child process), so it needs no tree, no elevation, no network and
# touches nothing real.  It never starts an sshd.  Every row prints the command and the
# output it matched on, and anchors on RESULT= / ERROR= / the file it wrote - a row that
# matched only an echo of its own input would be a false pass.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run (no ssh-keygen to make test keys).
#
# WHAT IT PROTECTS: the sshd configuration Solo's per-user sshd runs on (fixed port 4251,
# StrictModes yes, public-key only, AllowUsers the owner, ForceCommand sd-solo.exe), that it is
# accepted by sshd -t, that preparing it twice changes nothing, that a tampered file is put
# back, that the master's old key lines move out of ~\.ssh\authorized_keys without touching the
# owner's own keys, and that -Stop can never reach the system sshd.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'solo-sshd.ps1'
if (-not (Test-Path $src)) { Write-Host "NO TREE: $src missing"; exit 2 }
$sshDirOs = Join-Path $env:SystemRoot 'System32\OpenSSH'
$keygen = Join-Path $sshDirOs 'ssh-keygen.exe'
$sshdExe = Join-Path $sshDirOs 'sshd.exe'
if (-not (Test-Path $keygen)) { Write-Host "NO TREE: $keygen missing (needed to make test keys)"; exit 2 }
$haveSshd = Test-Path $sshdExe

$origProfile = $env:USERPROFILE   # Run overrides it for the child; "& this-script" runs in the CALLER's process, so it is put back at the end
$root = Join-Path $env:TEMP ('sdsolosshd-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$app = Join-Path $root 'app'; $prof = Join-Path $root 'profile'
New-Item -ItemType Directory -Path (Join-Path $app 'sdsys'), $prof | Out-Null
Copy-Item $src (Join-Path $app 'solo-sshd.ps1')
$helper = Join-Path $app 'solo-sshd.ps1'
Write-Host "scratch root: $root   (sshd.exe present: $haveSshd)"

$fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label"; $script:fail++ }
}
function Skip([string]$label, [string]$why) { Write-Host "SKIP  $label  ($why)" }

function Run([string]$name, [string[]]$a) {
    $env:USERPROFILE = $prof
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $helper @a 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host ('--- ' + $name + ' (exit ' + $code + ')'); Write-Host $out.TrimEnd()
    return @{ Out = $out; Code = $code }
}
function Sha([string]$p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
function New-Pub([int]$n) {
    $k = Join-Path $root ("k$n")
    & $keygen -q -t ed25519 -N '""' -f $k -C "test$n" | Out-Null
    return (Get-Content "$k.pub" -Raw).Trim()
}
function Sshd-Pids { return @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'sshd*' } | ForEach-Object { $_.Id }) }

$sshDir = Join-Path $app 'ssh'
$cfg = Join-Path $sshDir 'sshd_config'; $hk = Join-Path $sshDir 'ssh_host_ed25519_key'; $ak = Join-Path $sshDir 'authorized_keys'
$oldDir = Join-Path $prof '.ssh'; $old = Join-Path $oldDir 'authorized_keys'
$pidsBefore = Sshd-Pids
$expectUser = ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]).ToLower()

# ---- 1. -Prepare on an empty tree ------------------------------------------------------
$r = Run 'Prepare (empty tree)' @('-Prepare')
Check 'Prepare answers RESULT=PREPARED, exit 0' ($r.Code -eq 0 -and $r.Out -match '(?m)^RESULT=PREPARED\s*$')
Check 'it says PORT=4251, a user, a host-key fingerprint, the key file and MIGRATED=0' (
    $r.Out -match '(?m)^PORT=4251\s*$' -and $r.Out -match '(?m)^OSUSER=\S+' -and
    $r.Out -match '(?m)^HOSTKEY=SHA256:[A-Za-z0-9+/]{43}\s*$' -and $r.Out.Contains('KEYFILE=' + $ak) -and $r.Out -match '(?m)^MIGRATED=0\s*$')
Check 'the files exist: sshd_config, host key and its .pub, an authorized_keys of 0 bytes' (
    (Test-Path $cfg) -and (Test-Path $hk) -and (Test-Path ($hk + '.pub')) -and (Test-Path $ak) -and ((Get-Item $ak).Length -eq 0))
$fpKeygen = ((& $keygen -l -f ($hk + '.pub')) -split '\s+')[1]
Check "HOSTKEY is ssh-keygen's own fingerprint of that key (an independent instrument)" ($r.Out.Contains('HOSTKEY=' + $fpKeygen))

# ---- 2. the configuration itself -------------------------------------------------------
$c = [IO.File]::ReadAllText($cfg)
Write-Host '--- the configuration written:'; Write-Host $c.TrimEnd()
function Has([string]$line) { return ($c -split "`n") -contains $line }
$fw = { param($p) ($p -replace '\\', '/') }
Check 'Port 4251, and ListenAddress is not set (the firewall rule decides who may reach it)' ((Has 'Port 4251') -and ($c -notmatch '(?m)^\s*ListenAddress'))
Check 'public-key only: PasswordAuthentication no, KbdInteractiveAuthentication no, AuthenticationMethods publickey' (
    (Has 'PasswordAuthentication no') -and (Has 'KbdInteractiveAuthentication no') -and (Has 'AuthenticationMethods publickey') -and (Has 'PubkeyAuthentication yes'))
Check 'StrictModes yes (measured: it refuses a key file others can write)' (Has 'StrictModes yes')
Check 'AllowUsers names exactly the user it was prepared for' (Has ('AllowUsers ' + $expectUser))
Check 'DisableForwarding yes, and no sftp Subsystem and no Match block' ((Has 'DisableForwarding yes') -and ($c -notmatch '(?m)^\s*Match\s') -and ($c -notmatch '(?m)^\s*Subsystem'))
Check 'HostKey, AuthorizedKeysFile and PidFile are ABSOLUTE paths inside the app folder\ssh' (
    (Has ('HostKey ' + (& $fw $hk))) -and (Has ('AuthorizedKeysFile ' + (& $fw $ak))) -and (Has ('PidFile ' + (& $fw (Join-Path $sshDir 'sshd.pid')))))
Check 'ForceCommand runs THIS app folder''s sd-solo.exe, quoted' (Has ('ForceCommand "' + (Join-Path $app 'usr\bin\sd-solo.exe') + '"'))
Check 'the file is LF only, ASCII only' (([IO.File]::ReadAllBytes($cfg) | Where-Object { $_ -eq 13 -or $_ -gt 127 }).Count -eq 0)

# ---- 3. sshd -t accepts it, and a control proves sshd -t is not vacuous -----------------
if ($haveSshd) {
    $o = & $sshdExe -t -f $cfg 2>&1 | Out-String
    Check 'sshd -t accepts the generated configuration' ($LASTEXITCODE -eq 0)
    $bad = Join-Path $root 'bad_config'
    [IO.File]::WriteAllText($bad, "ThisIsNotAKeyword yes`n")
    $o2 = & $sshdExe -t -f $bad 2>&1 | Out-String
    Check 'CONTROL: sshd -t REJECTS a config with an unknown keyword, so the row above means something' ($LASTEXITCODE -ne 0)
} else { Skip 'sshd -t rows' 'no sshd.exe on this machine' }

# ---- 4. idempotent, and a tampered file is put back --------------------------------------
$h1 = Sha $hk; $c1 = Sha $cfg
$r = Run 'Prepare again' @('-Prepare')
Check 'the host key is not remade (same bytes) and the config is unchanged' ((Sha $hk) -eq $h1 -and (Sha $cfg) -eq $c1 -and $r.Out -match 'RESULT=PREPARED')
[IO.File]::WriteAllText($cfg, "Port 22`nPasswordAuthentication yes`n")
$r = Run 'Prepare after the config was tampered with' @('-Prepare')
Check 'a tampered sshd_config is rewritten to the original' ((Sha $cfg) -eq $c1)
Remove-Item ($hk + '.pub') -Force
$r = Run 'Prepare with the .pub missing' @('-Prepare')
Check 'a missing half of the host key makes a whole new pair' ((Test-Path $hk) -and (Test-Path ($hk + '.pub')) -and $r.Out -match 'HOSTKEY=SHA256:')

# ---- 5. migration of the master's old key lines -------------------------------------------
$pubs = 1..4 | ForEach-Object { New-Pub $_ }
function Line([int]$i) { $p = $pubs[$i] -split '\s+'; return ('restrict ' + $p[0] + ' ' + $p[1] + ' sdcoresolo-managed') }
$userKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUSERSOWNKEYUSERSOWNKEYUSERSOWNKEYUSERSOWN me@laptop'
New-Item -ItemType Directory -Path $oldDir | Out-Null
$oldText = @($userKey, (Line 0), (Line 1)) -join "`n"
[IO.File]::WriteAllText($old, $oldText + "`n")
$ownNew = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOWNERSNEWFILEOWNERSNEWFILEOWNERSNEWFILEOWNE mine@desk'
[IO.File]::AppendAllText($ak, $ownNew + "`n")
$r = Run 'Prepare with two old managed keys planted' @('-Prepare')
$newLines = @(Get-Content $ak); $oldLines = @(Get-Content $old)
Check 'MIGRATED=2' ($r.Out -match '(?m)^MIGRATED=2\s*$')
Check 'both managed lines are now in Solo''s own file, and the owner''s own line there is untouched' (($newLines -contains (Line 0)) -and ($newLines -contains (Line 1)) -and ($newLines -contains $ownNew))
Check 'the old file keeps only the owner''s key' ($oldLines.Count -eq 1 -and $oldLines[0] -eq $userKey)
Check 'a backup of the old file holds all three original lines' ((Test-Path ($old + '.sdcoresolo-backup')) -and ((Get-Content ($old + '.sdcoresolo-backup')).Count -eq 3))
$r = Run 'Prepare again after migrating' @('-Prepare')
Check 'migrating twice moves nothing and changes nothing' ($r.Out -match '(?m)^MIGRATED=0\s*$' -and @(Get-Content $ak).Count -eq 3)
[IO.File]::AppendAllText($old, (Line 0) + "`n")
$r = Run 'Prepare with a managed line that is already in the new file' @('-Prepare')
Check 'a duplicate is not added twice, but is taken out of the old file' ($r.Out -match '(?m)^MIGRATED=0\s*$' -and @(Get-Content $ak).Count -eq 3 -and @(Get-Content $old).Count -eq 1)

# ---- 6. the stale pinned fingerprint of the SYSTEM sshd is removed -------------------------
[IO.File]::WriteAllText((Join-Path $app 'sdsys\ssh-hostkey'), 'SHA256:' + ('A' * 43) + "`r`n")
$r = Run 'Prepare with the old sdsys\ssh-hostkey present' @('-Prepare')
Check 'the stale sdsys\ssh-hostkey (the system sshd''s pin) is removed' (-not (Test-Path (Join-Path $app 'sdsys\ssh-hostkey')))

# ---- 7. argument discipline and the things it must NOT do ----------------------------------
$r = Run 'no switch' @()
Check 'no switch: ERROR, exit 1, nothing started' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=give exactly one')
$r = Run 'two switches' @('-Prepare', '-Show')
Check 'two switches: ERROR, exit 1' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=give exactly one')
$h = Sha $cfg
$r = Run 'Show' @('-Show')
Check '-Show reports PORT=4251 and changes nothing' ($r.Out -match 'PORT=4251 listening=' -and (Sha $cfg) -eq $h -and $r.Code -eq 0)
$r = Run 'Run with no sd-solo.exe' @('-Run')
Check '-Run with nothing to force is REFUSED (ERROR, exit 1) and starts no sshd' (
    $r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=no (sd-solo\.exe|sshd\.exe)' -and ((Sshd-Pids) -join ',') -eq ($pidsBefore -join ',') -and
    @(Get-NetTCPConnection -State Listen -LocalPort 4251 -ErrorAction SilentlyContinue).Count -eq 0)
$r = Run 'Stop with none of ours running' @('-Stop')
Check '-Stop with nothing of ours running answers RESULT=NONE' ($r.Code -eq 0 -and $r.Out -match '(?m)^RESULT=NONE\s*$' -and $r.Out -match '(?m)^STOPPED=0\s*$')
Check 'and the system sshd is exactly as it was (same sshd* processes before and after every row)' (((Sshd-Pids) -join ',') -eq ($pidsBefore -join ','))

# ---- 8. the two scripts that name the port agree ---------------------------------------------
$fwSrc = Join-Path $here 'solo-ssh-firewall.ps1'
$portHere = [regex]::Match([IO.File]::ReadAllText($src), '(?m)^\$Port = (\d+)').Groups[1].Value
if (Test-Path $fwSrc) {
    $portFw = [regex]::Match([IO.File]::ReadAllText($fwSrc), '(?m)^\$Port = (\d+)').Groups[1].Value
    Check ("solo-sshd.ps1 and solo-ssh-firewall.ps1 name the same port ($portHere / $portFw), and it is 4251") ($portHere -eq $portFw -and $portHere -eq '4251')
} else { Check 'solo-ssh-firewall.ps1 exists to compare the port with' $false }

# ---- 9. a boot task with NO USERPROFILE in its environment (S4U) -------------------------------
# Join-Path throws on an empty string, which would stop -Run before sshd started.  The fallback asks the
# OS for the folder - the REAL profile, so this row reads the real ~\.ssh\authorized_keys.  It only runs
# when that file holds no Solo-tagged line (a tagged line would be migrated, i.e. WRITTEN), and it
# compares the real file's hash before and after.
$realProfile = [Environment]::GetFolderPath('UserProfile')
$realAk = Join-Path $realProfile '.ssh\authorized_keys'
$realTagged = (Test-Path -LiteralPath $realAk) -and (@(Get-Content -LiteralPath $realAk | Where-Object { $_ -match 'sdcoresolo-managed' }).Count -gt 0)
if ($realTagged) {
    Skip 'Prepare with no USERPROFILE' 'the real ~\.ssh\authorized_keys has a Solo-tagged line, which the row would migrate'
} else {
    $realHash = $(if (Test-Path -LiteralPath $realAk) { Sha $realAk } else { '(absent)' })
    Remove-Item Env:\USERPROFILE -ErrorAction SilentlyContinue
    Write-Host ('USERPROFILE in the child: [' + $env:USERPROFILE + ']  (must be empty); OS says the folder is ' + $realProfile)
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $helper -Prepare 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host ('--- Prepare with no USERPROFILE (exit ' + $code + ')'); Write-Host $out.TrimEnd()
    $realAfter = $(if (Test-Path -LiteralPath $realAk) { Sha $realAk } else { '(absent)' })
    Check 'with no USERPROFILE, -Prepare still answers RESULT=PREPARED, exit 0, and does not die on an empty path' (
        [string]::IsNullOrEmpty($env:USERPROFILE) -and $code -eq 0 -and $out -match '(?m)^RESULT=PREPARED\s*$' -and $out -notmatch 'Cannot bind argument')
    Check 'and the real ~\.ssh\authorized_keys is byte-identical afterwards' ($realAfter -eq $realHash)
}

$env:USERPROFILE = $origProfile
Remove-Item $root -Recurse -Force
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-sshd units: ALL PASS'; exit 0 }
Write-Host "solo-sshd units: $fail FAILED"; exit 1
