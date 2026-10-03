# test-solosshd-units.ps1 - free-tier guard for solo-sshd.ps1 (SOLO 28).
# Drives the script against a SCRATCH app folder, a SCRATCH profile and a SCRATCH ProgramData (USERPROFILE and
# ProgramData are overridden for the child process), so it needs no tree, no elevation, no network and touches
# nothing real.  It never starts an sshd.  Every row prints the command and the output it matched on, and
# anchors on RESULT= / ERROR= / the file it wrote - a row that matched only an echo of its own input would be a
# false pass.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run (no ssh-keygen to make test keys).
#
# WHAT IT PROTECTS: Solo's sshd runs as SYSTEM (the owner's ruling: Windows account name + password, which a
# per-user sshd cannot give a session - CreateProcessAsUserW 1314), so what a SYSTEM process trusts must be
# admin-only.  Rows: the user-level -Prepare makes ONLY the user's own key file and deletes what the first
# per-user build left, reads the host-key fingerprint from the machine folder and writes nothing there; the
# config -PrintConfig prints is password-AND-key, fixed port 4251, StrictModes yes, AllowUsers the owner,
# ForceCommand sd-solo.exe, and sshd -t accepts it; a login name or app path that could add a line to it is
# refused; -Install and -Uninstall refuse unelevated and change nothing; and the permission READ-BACK
# (Get-AclProblems, lifted from the script) flags a user-writable folder, a user-readable private key and a
# non-admin owner - proved on bad, partly good and mutant folders.  The elevated -Install itself cannot run here.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'solo-sshd.ps1'
if (-not (Test-Path $src)) { Write-Host "NO TREE: $src missing"; exit 2 }
$sshDirOs = Join-Path $env:SystemRoot 'System32\OpenSSH'
$keygen = Join-Path $sshDirOs 'ssh-keygen.exe'
$sshdExe = Join-Path $sshDirOs 'sshd.exe'
if (-not (Test-Path $keygen)) { Write-Host "NO TREE: $keygen missing (needed to make test keys)"; exit 2 }
$haveSshd = Test-Path $sshdExe

# "& this-script" runs in the CALLER's process, so what Run overrides is put back at the end.
$origProfile = $env:USERPROFILE
$origPD = $env:ProgramData
$root = Join-Path $env:TEMP ('sdsolosshd-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$app = Join-Path $root 'app'; $prof = Join-Path $root 'profile'; $pd = Join-Path $root 'programdata'
New-Item -ItemType Directory -Path (Join-Path $app 'sdsys'), $prof, $pd | Out-Null
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
    $env:ProgramData = $pd
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
function Tree([string]$p) { if (Test-Path $p) { return @(Get-ChildItem -LiteralPath $p -Recurse -Force | ForEach-Object { $_.FullName.Substring($p.Length) }) -join '|' } else { return '(absent)' } }

$sshDir = Join-Path $app 'ssh'
$ak = Join-Path $sshDir 'authorized_keys'
$mdir = Join-Path $pd 'SDCoreSolo\ssh'
$oldDir = Join-Path $prof '.ssh'; $old = Join-Path $oldDir 'authorized_keys'
$pidsBefore = Sshd-Pids
# PORT 4251 IS FIXED AND SHARED WITH THE REAL MACHINE, so what holds it NOW decides which rows can run.  On a
# machine with a running Solo, its sshd (started by a SYSTEM task) holds 4251 and an ordinary shell cannot
# inspect it - measured 2 Oct 2026 - so "-Stop answers NONE" is not true there, and the guard says so instead of
# failing for the wrong reason.
$rowsBefore = @(Get-NetTCPConnection -State Listen -LocalPort 4251 -ErrorAction SilentlyContinue).Count
$holders = @(Get-NetTCPConnection -State Listen -LocalPort 4251 -ErrorAction SilentlyContinue | ForEach-Object { $_.OwningProcess } | Sort-Object -Unique)
$blindBefore = @($holders | Where-Object { $p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $_) -ErrorAction SilentlyContinue; (-not $p) -or (-not $p.CommandLine) }).Count
Write-Host ('port 4251 on this machine: ' + $rowsBefore + ' listening socket(s), held by ' + $holders.Count + ' process(es), ' + $blindBefore + ' not inspectable from this shell')
$expectUser = ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]).ToLower()

# ---- 1. -Prepare on an empty tree: only the user's own file ------------------------------------
$r = Run 'Prepare (empty tree)' @('-Prepare')
Check 'Prepare answers RESULT=PREPARED, exit 0' ($r.Code -eq 0 -and $r.Out -match '(?m)^RESULT=PREPARED\s*$')
Check 'it says PORT=4251, the user, the key file, the MACHINE config path and MIGRATED=0' (
    $r.Out -match '(?m)^PORT=4251\s*$' -and $r.Out -match ('(?m)^OSUSER=' + [regex]::Escape($expectUser) + '\s*$') -and
    $r.Out.Contains('KEYFILE=' + $ak) -and $r.Out.Contains('CONFIG=' + (Join-Path $mdir 'sshd_config')) -and $r.Out -match '(?m)^MIGRATED=0\s*$')
Check 'HOSTKEY is EMPTY while no machine host key exists (it reads one, it never makes one)' ($r.Out -match '(?m)^HOSTKEY=\s*$')
Check 'the key file exists and is empty' ((Test-Path $ak) -and (Get-Item $ak).Length -eq 0)
Check '<app>\ssh holds ONLY authorized_keys - no config, no host key, no pid, no log' ((Tree $sshDir) -eq '\authorized_keys')
Check 'and nothing at all was written under the machine folder (ProgramData)' ((Tree $pd) -eq '(absent)' -or (Tree $pd) -eq '')

$h = Sha $ak
$r = Run 'Prepare again' @('-Prepare')
Check 'preparing twice changes nothing' ($r.Code -eq 0 -and (Sha $ak) -eq $h)

# ---- 2. HOSTKEY is read from the machine folder, checked with an independent instrument -----------
New-Item -ItemType Directory -Path $mdir -Force | Out-Null
& $keygen -q -t ed25519 -N '""' -f (Join-Path $mdir 'ssh_host_ed25519_key') | Out-Null
$hostFpr = ((& $keygen -l -f (Join-Path $mdir 'ssh_host_ed25519_key.pub')) -split '\s+')[1]
$r = Run 'Prepare with a machine host key present' @('-Prepare')
Check "HOSTKEY is the fingerprint ssh-keygen gives for the machine folder's key (an independent instrument)" ($r.Out -match ('(?m)^HOSTKEY=' + [regex]::Escape($hostFpr) + '\s*$'))
Check 'and it did not touch the machine folder' ((Tree $mdir) -eq '\ssh_host_ed25519_key|\ssh_host_ed25519_key.pub')

# ---- 3. what the first per-user build left in <app>\ssh is deleted, the owner's keys stay ----------
$userKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUSERSOWNKEYUSERSOWNKEYUSERSOWNKEYUSERSOWN me@laptop'
[IO.File]::WriteAllText($ak, $userKey + "`n")
foreach ($n in @('sshd_config', 'ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', 'sshd.pid', 'sshd.log')) { [IO.File]::WriteAllText((Join-Path $sshDir $n), 'left by the first build') }
$r = Run 'Prepare over the first build''s files' @('-Prepare')
Check 'the first build''s config, host key, pid and log are gone' ((Tree $sshDir) -eq '\authorized_keys')
Check 'and the owner''s own key in authorized_keys is untouched' ((Get-Content $ak) -contains $userKey)

# ---- 4. the master's old managed key lines move out of ~\.ssh, the owner's stay ----------------------
$pubs = 1..3 | ForEach-Object { New-Pub $_ }
function Line([int]$i) { $p = $pubs[$i] -split '\s+'; return ('restrict ' + $p[0] + ' ' + $p[1] + ' sdcoresolo-managed') }
New-Item -ItemType Directory -Path $oldDir | Out-Null
$oldOwn = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLDOWNKEYOLDOWNKEYOLDOWNKEYOLDOWNKEYOLDO me@old'
[IO.File]::WriteAllText($old, (@($oldOwn, (Line 0), (Line 1)) -join "`n") + "`n")
$r = Run 'Prepare with two old managed keys planted' @('-Prepare')
$newLines = @(Get-Content $ak); $oldLines = @(Get-Content $old)
Check 'MIGRATED=2' ($r.Out -match '(?m)^MIGRATED=2\s*$')
Check 'both managed lines are now in Solo''s own file, and the owner''s own line there is untouched' (($newLines -contains (Line 0)) -and ($newLines -contains (Line 1)) -and ($newLines -contains $userKey))
Check 'the old file keeps only the owner''s key, and a backup holds all three original lines' ($oldLines.Count -eq 1 -and $oldLines[0] -eq $oldOwn -and (Test-Path ($old + '.sdcoresolo-backup')) -and ((Get-Content ($old + '.sdcoresolo-backup')).Count -eq 3))
$r = Run 'Prepare again after migrating' @('-Prepare')
Check 'migrating twice moves nothing and changes nothing' ($r.Out -match '(?m)^MIGRATED=0\s*$' -and @(Get-Content $ak).Count -eq 3)
[IO.File]::WriteAllText((Join-Path $app 'sdsys\ssh-hostkey'), 'SHA256:' + ('A' * 43) + "`r`n")
$r = Run 'Prepare with the old sdsys\ssh-hostkey present' @('-Prepare')
Check 'the stale sdsys\ssh-hostkey (the system sshd''s pin) is removed' (-not (Test-Path (Join-Path $app 'sdsys\ssh-hostkey')))

# ---- 5. the configuration: password AND key, port fixed, accepted by sshd -t -------------------------
$r = Run 'PrintConfig' @('-PrintConfig', '-OsUser', $expectUser)
$cfgText = $r.Out
Check 'the config sets Port 4251, StrictModes yes, PasswordAuthentication yes and PubkeyAuthentication yes' (
    $cfgText -match '(?m)^Port 4251\s*$' -and $cfgText -match '(?m)^StrictModes yes\s*$' -and $cfgText -match '(?m)^PasswordAuthentication yes\s*$' -and $cfgText -match '(?m)^PubkeyAuthentication yes\s*$')
Check 'it allows ONLY the owner, forces sd-solo.exe from the app folder, and forbids forwarding' (
    $cfgText -match ('(?m)^AllowUsers ' + [regex]::Escape($expectUser) + '\s*$') -and $cfgText.Contains('ForceCommand "' + (Join-Path $app 'usr\bin\sd-solo.exe') + '"') -and $cfgText -match '(?m)^DisableForwarding yes\s*$')
Check 'the host key and pid file are in the MACHINE folder, the optional key file is in the user''s' (
    $cfgText.Contains('HostKey ' + ((Join-Path $mdir 'ssh_host_ed25519_key') -replace '\\', '/')) -and $cfgText.Contains('PidFile ' + ((Join-Path $mdir 'sshd.pid') -replace '\\', '/')) -and
    $cfgText.Contains('AuthorizedKeysFile ' + ((Join-Path $sshDir 'authorized_keys') -replace '\\', '/')))
Check 'it does NOT force key-only: no "PasswordAuthentication no" and no AuthenticationMethods line' ($cfgText -notmatch '(?m)^PasswordAuthentication no' -and $cfgText -notmatch '(?m)^AuthenticationMethods')
if ($haveSshd) {
    $tcfg = Join-Path $root 'test_sshd_config'
    [IO.File]::WriteAllText($tcfg, ($cfgText.TrimEnd() + "`n"), (New-Object Text.UTF8Encoding($false)))
    $tp = Start-Process -FilePath $sshdExe -ArgumentList @('-t', '-f', ('"' + $tcfg + '"')) -NoNewWindow -Wait -PassThru -RedirectStandardError (Join-Path $root 't.err') -RedirectStandardOutput (Join-Path $root 't.out')
    Write-Host ('--- sshd -t on that config (exit ' + $tp.ExitCode + ')  ' + ((Get-Content (Join-Path $root 't.err') -ErrorAction SilentlyContinue) -join ' | '))
    Check 'sshd -t accepts the printed configuration (exit 0, nothing on stderr)' ($tp.ExitCode -eq 0 -and ((Get-Content (Join-Path $root 't.err') -ErrorAction SilentlyContinue) -join '').Trim() -eq '')
} else { Skip 'sshd -t on the printed configuration' 'no sshd.exe on this computer' }

# ---- 6. inputs that could add a line to a config a SYSTEM process reads are refused -------------------
foreach ($bad in @('don evil', 'don/x', 'a;b')) {
    $r = Run ('PrintConfig with login name [' + $bad + ']') @('-PrintConfig', '-OsUser', $bad)
    Check ('login name [' + $bad + '] is refused with ERROR=, exit 1, and no config printed') ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=refusing a login name' -and $r.Out -notmatch '(?m)^Port ')
}
$r = Run 'PrintConfig with no login name' @('-PrintConfig')
Check 'no login name is refused' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=give -OsUser')

# ---- 7. -Install and -Uninstall need an administrator and change nothing without one ---------------
$before = Tree $pd
$r = Run 'Install, unelevated' @('-Install', '-OsUser', $expectUser)
Check '-Install unelevated: ERROR=...ELEVATED, exit 1, and the machine folder is exactly as it was' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=.*ELEVATED' -and (Tree $pd) -eq $before)
$r = Run 'Uninstall, unelevated' @('-Uninstall')
Check '-Uninstall unelevated: ERROR=...ELEVATED, exit 1, and the machine folder is still there' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=.*ELEVATED' -and (Test-Path (Join-Path $mdir 'ssh_host_ed25519_key')))

$srcText = [IO.File]::ReadAllText($src)
Check '-Uninstall refuses to delete anything but an ...\SDCoreSolo folder with an ssh child (the recursive delete is guarded in the source)' (
    $srcText -match "Split-Path -Leaf \`$parent\) -ne 'SDCoreSolo'" -and $srcText -match "Split-Path -Leaf \`$machineDir\) -ne 'ssh'" -and $srcText -match 'refusing to delete')

# ---- 8. argument discipline and the things -Stop must NOT do --------------------------------------
$r = Run 'no switch' @()
Check 'no switch: ERROR, exit 1, nothing started' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=give exactly one')
$r = Run 'two switches' @('-Prepare', '-Show')
Check 'two switches: ERROR, exit 1' ($r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=give exactly one')
$h = Sha $ak
$r = Run 'Show' @('-Show')
Check '-Show reports PORT=4251, the machine folder, and changes nothing' ($r.Out -match 'PORT=4251 listening=' -and $r.Out -match 'MACHINEDIR=' -and (Sha $ak) -eq $h -and $r.Code -eq 0)
$r = Run 'Stop with none of ours running' @('-Stop')
if ($blindBefore -eq 0) {
    Check '-Stop with nothing of ours running answers RESULT=NONE' ($r.Code -eq 0 -and $r.Out -match '(?m)^RESULT=NONE\s*$' -and $r.Out -match '(?m)^STOPPED=0\s*$')
    Skip '-Stop REFUSES when a holder of 4251 cannot be inspected' 'nothing of that kind holds 4251 on this machine'
} else {
    Skip '-Stop with nothing of ours running answers RESULT=NONE' ('a process this shell cannot inspect holds 4251 here (' + $blindBefore + '), so NONE would be a guess')
    Check '-Stop REFUSES, not NONE, when a holder of 4251 cannot be inspected: ERROR=...cannot inspect..., exit 1, STOPPED=0, and the port is still held' (
        $r.Code -eq 1 -and $r.Out -match '(?m)^ERROR=.*cannot inspect' -and $r.Out -match '(?m)^STOPPED=0\s*$' -and $r.Out -notmatch 'RESULT=NONE' -and
        @(Get-NetTCPConnection -State Listen -LocalPort 4251 -ErrorAction SilentlyContinue).Count -eq $rowsBefore)
}
Check 'and the system sshd is exactly as it was (same sshd* processes before and after every row)' (((Sshd-Pids) -join ',') -eq ($pidsBefore -join ','))

# ---- 9. the two scripts that name the port agree ---------------------------------------------------
$fwSrc = Join-Path $here 'solo-ssh-firewall.ps1'
$portHere = [regex]::Match([IO.File]::ReadAllText($src), '(?m)^\$Port = (\d+)').Groups[1].Value
if (Test-Path $fwSrc) {
    $portFw = [regex]::Match([IO.File]::ReadAllText($fwSrc), '(?m)^\$Port = (\d+)').Groups[1].Value
    Check ("solo-sshd.ps1 and solo-ssh-firewall.ps1 name the same port ($portHere / $portFw), and it is 4251") ($portHere -eq $portFw -and $portHere -eq '4251')
} else { Check 'solo-ssh-firewall.ps1 exists to compare the port with' $false }

# ---- 10. a task with NO USERPROFILE in its environment (Join-Path throws on an empty string) --------
$realProfile = [Environment]::GetFolderPath('UserProfile')
$realAk = Join-Path $realProfile '.ssh\authorized_keys'
$realTagged = (Test-Path -LiteralPath $realAk) -and (@(Get-Content -LiteralPath $realAk | Where-Object { $_ -match 'sdcoresolo-managed' }).Count -gt 0)
if ($realTagged) {
    Skip 'Prepare with no USERPROFILE' 'the real ~\.ssh\authorized_keys has a Solo-tagged line, which the row would migrate'
} else {
    $realHash = $(if (Test-Path -LiteralPath $realAk) { Sha $realAk } else { '(absent)' })
    Remove-Item Env:\USERPROFILE -ErrorAction SilentlyContinue
    $env:ProgramData = $pd
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
$env:ProgramData = $origPD

# ---- 11. THE PERMISSION READ-BACK: Get-AclProblems is lifted from the script, so the real code is tested -------
$tok = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$tok, [ref]$errs)
$lifted = 0
# Invoke-Icacls reports through Stop-With, which exits the script; here it must only say so and throw.
function Stop-With([string]$m) { Write-Host ('  Stop-With: ' + $m); throw $m }
foreach ($name in @('Get-SidOf', 'Get-AclProblems', 'Invoke-Icacls', 'Remove-ExtraAces')) {
    $fn = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
    if ($fn.Count -ne 1) { Write-Host "NO TREE: expected exactly one $name in solo-sshd.ps1, found $($fn.Count)"; exit 2 }
    . ([scriptblock]::Create($fn[0].Extent.Text))
    $lifted++
}
$SidSystem = 'S-1-5-18'; $SidAdmins = 'S-1-5-32-544'; $SidUsers = 'S-1-5-32-545'
Write-Host ("lifted $lifted functions for the read-back rows")
$aclDir = Join-Path $root 'acl'
New-Item -ItemType Directory -Path $aclDir | Out-Null
$aclFile = Join-Path $aclDir 'key'
[IO.File]::WriteAllText($aclFile, 'x')
$p1 = @(Get-AclProblems $aclDir $false)
Write-Host ('  fresh folder, problems: ' + ($p1 -join ' ;; '))
Check 'a FRESH user-owned folder is flagged: the user owns it AND can write in it' ($p1.Count -ge 2 -and @($p1 | Where-Object { $_ -match 'owner is' }).Count -ge 1 -and @($p1 | Where-Object { $_ -match 'can write' }).Count -ge 1)
$null = & icacls.exe $aclDir '/inheritance:r' '/grant:r' ('*' + $SidSystem + ':(OI)(CI)F') ('*' + $SidAdmins + ':(OI)(CI)F') ('*' + $SidUsers + ':(OI)(CI)RX') 2>&1
$p2 = @(Get-AclProblems $aclDir $false)
Write-Host ('  admin-only ACL, still user-owned, problems: ' + ($p2 -join ' ;; '))
Check 'with the install''s ACL (SYSTEM+Administrators full, Users read) ONLY the owner is left to flag - the unelevated guard cannot change it' ($p2.Count -eq 1 -and $p2[0] -match 'owner is')
$null = & icacls.exe $aclDir '/grant' ('*' + $SidUsers + ':(OI)(CI)M') 2>&1
$p3 = @(Get-AclProblems $aclDir $false)
Write-Host ('  MUTANT, Users granted Modify, problems: ' + ($p3 -join ' ;; '))
Check 'MUTANT: Users granted Modify on the folder is flagged "can write"' (@($p3 | Where-Object { $_ -match 'Users.*can write' }).Count -ge 1)
$null = & icacls.exe $aclFile '/inheritance:r' '/grant:r' ('*' + $SidSystem + ':F') ('*' + $SidAdmins + ':F') 2>&1
$p4 = @(Get-AclProblems $aclFile $true)
Check 'a private key readable by SYSTEM and Administrators only has no access problem (only the owner, which the guard cannot set)' ($p4.Count -eq 1 -and $p4[0] -match 'owner is')
$null = & icacls.exe $aclFile '/grant' ('*' + $SidUsers + ':R') 2>&1
$p5 = @(Get-AclProblems $aclFile $true)
Write-Host ('  MUTANT, Users granted read on the private key, problems: ' + ($p5 -join ' ;; '))
Check 'MUTANT: Users granted READ on the private key is flagged "has access to a private key"' (@($p5 | Where-Object { $_ -match 'has access to a private key' }).Count -ge 1)

# ---- 12. THE DEFECT THE FIRST ELEVATED RUN FOUND (2 Oct 2026): ssh-keygen leaves the user who ran it an explicit ACE ----
# Real ssh-keygen output, in a scratch folder.  "icacls /inheritance:r /grant:r" leaves explicit ACEs alone, so the
# install's read-back refused "ace\Don has access to a private key" and "can write".  Remove-ExtraAces is the fix.
$kgDir = Join-Path $root 'keygen'
New-Item -ItemType Directory -Path $kgDir | Out-Null
$kgKey = Join-Path $kgDir 'k'
& $keygen -q -t ed25519 -N '""' -f $kgKey | Out-Null
$k0 = @(Get-AclProblems $kgKey $true)
Write-Host ('  ssh-keygen''s own private key, problems: ' + (($k0 | ForEach-Object { ($_ -split ': ', 2)[1] }) -join ' ;; '))
if (@($k0 | Where-Object { $_ -match 'has access to a private key' }).Count -eq 0) {
    Skip 'ssh-keygen leaves an extra ACE on its private key' 'it left none on this computer, so the fix is not exercised'
} else {
    Check 'ssh-keygen leaves the user who ran it an ACE on the private key (the defect, reproduced with the real tool)' $true
    # WITHOUT the fix: the sequence the first build of -Install used.
    $null = & icacls.exe $kgKey '/inheritance:r' '/grant:r' ('*' + $SidSystem + ':F') ('*' + $SidAdmins + ':F') 2>&1
    $k1 = @(Get-AclProblems $kgKey $true)
    Check 'WITHOUT Remove-ExtraAces the old sequence still leaves that ACE (this is why the function exists)' (@($k1 | Where-Object { $_ -match 'has access to a private key' }).Count -ge 1)
    # WITH the fix: the sequence -Install uses now.
    Remove-ExtraAces $kgKey @($SidSystem, $SidAdmins)
    $k2 = @(Get-AclProblems $kgKey $true)
    Write-Host ('  after Remove-ExtraAces, problems: ' + (($k2 | ForEach-Object { ($_ -split ': ', 2)[1] }) -join ' ;; '))
    Check 'WITH Remove-ExtraAces nobody but SYSTEM and Administrators has access to the private key (only the owner, which the guard cannot set, is left)' ($k2.Count -eq 1 -and $k2[0] -match 'owner is')
}
$kgPub = $kgKey + '.pub'
$null = & icacls.exe $kgPub '/inheritance:r' '/grant:r' ('*' + $SidSystem + ':F') ('*' + $SidAdmins + ':F') ('*' + $SidUsers + ':R') 2>&1
Remove-ExtraAces $kgPub @($SidSystem, $SidAdmins, $SidUsers, 'S-1-1-0')
$p6 = @(Get-AclProblems $kgPub $false)
Write-Host ('  public key after the same cut, problems: ' + (($p6 | ForEach-Object { ($_ -split ': ', 2)[1] }) -join ' ;; '))
Check 'the public key ends up writable by SYSTEM and Administrators only (still readable by users); only the owner is left to flag' ($p6.Count -eq 1 -and $p6[0] -match 'owner is')

$null = & icacls.exe $aclDir '/reset' '/T' '/C' '/Q' 2>&1
$null = & icacls.exe $kgDir '/reset' '/T' '/C' '/Q' 2>&1
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $root) { Write-Host "NOTE: could not remove the scratch folder $root" }
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-sshd units: ALL PASS'; exit 0 }
Write-Host "solo-sshd units: $fail FAILED"; exit 1
