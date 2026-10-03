# test-solomachine-units.ps1 - free-tier guard for what solo-machine.ps1 does to the SYSTEM sshd
# (SOLO 28).  solo-machine.ps1 is elevated and cannot run here, so this loads its OWN function
# definitions out of the file by parsing it (nothing is re-typed) and runs them against a SCRATCH
# ProgramData, with Get-Service, Restart-Service and the sshd.exe it calls replaced by stubs - so no
# real service, no real sshd_config and no firewall rule can be touched.  No tree, no elevation.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run.
#
# WHAT IT PROTECTS: the one path that touches a USER'S EXISTING machine on an upgrade - taking the
# "Match User" block an earlier build wrote OUT of the system sshd_config - and the promise made in the
# script's header that it never writes a block any more and never changes the system sshd's startup type.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'solo-machine.ps1'
if (-not (Test-Path $src)) { Write-Host "NO TREE: $src missing"; exit 2 }

$fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label"; $script:fail++ }
}

# ---- 1. the file parses, and the old writer is GONE ---------------------------------------------
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$t, [ref]$e)
$names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
Write-Host ("functions: " + ($names -join ', '))
Check 'solo-machine.ps1 parses with 0 errors' ($e.Count -eq 0)
Check 'the new functions exist: Remove-OldSshBlock, Register-SshTask, Remove-SshTask' (($names -contains 'Remove-OldSshBlock') -and ($names -contains 'Register-SshTask') -and ($names -contains 'Remove-SshTask'))
Check 'the old writer Set-SshBlock is gone' ($names -notcontains 'Set-SshBlock')
$text = [IO.File]::ReadAllText($src)
# Strip comment lines so a sentence ABOUT the old code does not read as the old code.
$code = (($text -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Check 'no code writes a "Match User" line any more' ($code -notmatch "Match User")
Check 'no code sets the system sshd service to start at boot (no -StartupType Automatic, no Set-Service sshd)' ($code -notmatch 'StartupType\s+Automatic' -and $code -notmatch 'Set-Service\s+sshd')
# The lookbehinds matter: "Restart-Service sshd" - which Remove-OldSshBlock runs, deliberately, only after it
# really removed a block - contains "start-Service sshd", and "solo-ssh-firewall.ps1" contains "ssh-firewall.ps1".
Check 'no code starts the system sshd service (no Start-Service sshd)' ($code -notmatch '(?<![A-Za-z])Start-Service\s+sshd')
Check 'it no longer calls the port-22 script (ssh-firewall.ps1) or creates Microsoft''s OpenSSH-Server-In-TCP rule' ($code -notmatch '(?<!solo-)ssh-firewall\.ps1' -and $code -notmatch 'New-NetFirewallRule')
Check 'it names Solo''s own scripts: solo-sshd.ps1 and solo-ssh-firewall.ps1' ($code -match 'solo-sshd\.ps1' -and $code -match 'solo-ssh-firewall\.ps1')
$portHere = [regex]::Match($text, '(?m)^\$SshPort = (\d+)').Groups[1].Value
$portSshd = [regex]::Match([IO.File]::ReadAllText((Join-Path $here 'solo-sshd.ps1')), '(?m)^\$Port = (\d+)').Groups[1].Value
Check ("the port solo-machine.ps1 checks ($portHere) is solo-sshd.ps1's ($portSshd), and 4251") ($portHere -eq $portSshd -and $portHere -eq '4251')

# ---- 2. load the three functions it needs, with stubs for everything that could touch the machine ---
$scratch = Join-Path $env:TEMP ('sdsolomachine-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$pd = Join-Path $scratch 'pd'; $sshDir = Join-Path $pd 'ssh'
New-Item -ItemType Directory -Path $sshDir | Out-Null
$cfg = Join-Path $sshDir 'sshd_config'
$origProgramData = $env:ProgramData   # put back at the end: "& script.ps1" runs in THIS process
$env:ProgramData = $pd

$Begin = [regex]::Match($text, "(?m)^\`$Begin = '([^']+)'").Groups[1].Value
$End   = [regex]::Match($text, "(?m)^\`$End\s+= '([^']+)'").Groups[1].Value
Check 'the block markers were read out of the file (so this test cannot drift from it)' ($Begin -like '# BEGIN SD Core Solo*' -and $End -eq '# END SD Core Solo')

$loaded = ($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                   ($n.Name -eq 'Remove-OurBlock' -or $n.Name -eq 'Remove-OldSshBlock') }, $true) |
           ForEach-Object { $_.Extent.Text }) -join "`n`n"
. ([scriptblock]::Create($loaded))

# Stubs, defined AFTER the real definitions so they win.
$script:notes = New-Object System.Collections.ArrayList
$script:fails = New-Object System.Collections.ArrayList
function Note([string]$s) { [void]$script:notes.Add($s) }
function Fail([string]$s) { [void]$script:fails.Add($s) }
$script:restarts = 0
$script:svcStatus = 'Running'
function Get-Service { param($n, $ErrorAction) return [pscustomobject]@{ Status = $script:svcStatus; StartType = 'Automatic' } }
function Restart-Service { param($n) $script:restarts++ }
# Set-Service and Start-Service are stubbed AND counted, never reset: nothing in these runs may start or
# reconfigure the system sshd, and a stub keeps a mutant (or a future edit) from doing it for real from an
# elevated shell.
$script:setTotal = 0; $script:startTotal = 0
function Set-Service { param($n, $StartupType) $script:setTotal++ }
function Start-Service { param($n) $script:startTotal++ }
$okSshd = Join-Path $scratch 'sshd-ok.cmd';   [IO.File]::WriteAllText($okSshd, "@exit /b 0`r`n")
$badSshd = Join-Path $scratch 'sshd-bad.cmd'; [IO.File]::WriteAllText($badSshd, "@echo Bad configuration option 1>&2`r`n@exit /b 1`r`n")
$script:sshdPath = $okSshd
function Find-Sshd { return $script:sshdPath }

function Reset-Run { $script:notes.Clear(); $script:fails.Clear(); $script:restarts = 0 }
function Sha([string]$p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
$oldBlock = @($Begin, 'Match User "don"', '    ForceCommand "C:\Users\Don\SDCoreSolo\usr\bin\sd-solo.exe"',
              '    AuthorizedKeysFile .ssh/authorized_keys', '    DisableForwarding yes', $End)
$stock = @('# stock', 'Subsystem sftp sftp-server.exe', 'Match Group administrators', '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys')
function Show-Run([string]$name) {
    Write-Host ('--- ' + $name + ': ' + (($script:notes | ForEach-Object { $_.Trim() }) -join ' / ') + $(if ($script:fails.Count) { ' FAILS: ' + ($script:fails -join '; ') } else { '' }))
}
$userHostKey = '' ; $null = $userHostKey

# ---- 3. no sshd_config at all ---------------------------------------------------------------------
Reset-Run; Remove-OldSshBlock; Show-Run 'no sshd_config'
Check 'no sshd_config: says there is nothing to remove, fails nothing, restarts nothing' (($script:notes -join '|') -match 'no old block to remove' -and $script:fails.Count -eq 0 -and $script:restarts -eq 0)

# ---- 4. a config with NO Solo block: byte-identical, no restart -------------------------------------
[IO.File]::WriteAllLines($cfg, $stock)
$h = Sha $cfg
Reset-Run; Remove-OldSshBlock; Show-Run 'config without a block'
Check 'a config with no block is not rewritten (same bytes), no backup is made, the system sshd is not restarted' (
    (Sha $cfg) -eq $h -and -not (Test-Path ($cfg + '.sdcoresolo-backup')) -and $script:restarts -eq 0 -and $script:fails.Count -eq 0)

# ---- 5. the old block, written exactly as the old code wrote it ---------------------------------------
$withBlock = @($stock[0], $stock[1]) + $oldBlock + @($stock[2], $stock[3])
[IO.File]::WriteAllLines($cfg, $withBlock)
Reset-Run; Remove-OldSshBlock; Show-Run 'config with the old block'
$after = @(Get-Content $cfg)
Check 'the old block is REMOVED, every other line is kept in order' (($after -join "`n") -eq ($stock -join "`n"))
Check 'a backup of the original was made, holding the block' ((Test-Path ($cfg + '.sdcoresolo-backup')) -and ((Get-Content ($cfg + '.sdcoresolo-backup')) -contains $Begin))
Check 'the system sshd was restarted exactly once (it was Running), and nothing failed' ($script:restarts -eq 1 -and $script:fails.Count -eq 0 -and ($script:notes -join '|') -match 'PASS  the old SD Core Solo block is gone')
Reset-Run; Remove-OldSshBlock; Show-Run 'run again after removal'
Check 'running it again changes nothing (idempotent): same bytes, no restart' ((@(Get-Content $cfg) -join "`n") -eq ($stock -join "`n") -and $script:restarts -eq 0)

# ---- 6. a stopped system sshd is NOT started or restarted ------------------------------------------------
[IO.File]::WriteAllLines($cfg, $withBlock)
$script:svcStatus = 'Stopped'
Reset-Run; Remove-OldSshBlock; Show-Run 'old block, system sshd stopped'
Check 'with the system sshd STOPPED the block is still removed and the service is left stopped (no restart)' (((@(Get-Content $cfg)) -notcontains $Begin) -and $script:restarts -eq 0)
$script:svcStatus = 'Running'

# ---- 7. sshd -t rejects the result: the original is put back ----------------------------------------------
[IO.File]::WriteAllLines($cfg, $withBlock)
$h = Sha $cfg
$script:sshdPath = $badSshd
Reset-Run; Remove-OldSshBlock; Show-Run 'sshd -t rejects the new file'
Check 'when sshd -t rejects the new config the ORIGINAL is restored byte for byte, a FAIL is raised, nothing is restarted' (
    (Sha $cfg) -eq $h -and $script:fails.Count -eq 1 -and $script:restarts -eq 0)
$script:sshdPath = $okSshd

# ---- 8. the script refuses an unelevated caller before changing anything -----------------------------------
$res = Join-Path $scratch 'result.txt'
$o = & powershell -NoProfile -ExecutionPolicy Bypass -File $src -Action Remove -ForUser 'nobody\nobody' -AppDir (Join-Path $scratch 'app') -Result $res 2>&1 | Out-String
$code = $LASTEXITCODE
Write-Host ('--- solo-machine.ps1 -Action Remove run unelevated (exit ' + $code + ')'); if (Test-Path $res) { Get-Content $res | ForEach-Object { Write-Host ('    ' + $_) } }
$isElev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isElev) { Write-Host 'SKIP  the unelevated-refusal row (this shell is elevated)' }
else { Check 'unelevated: exit 2, "REFUSED : not elevated", "nothing was changed"' ($code -eq 2 -and (Test-Path $res) -and ((Get-Content $res -Raw) -match 'REFUSED\s+: not elevated') -and ((Get-Content $res -Raw) -match 'nothing was changed')) }

Check ('across every run above the system sshd was NEVER started or given a startup type (Start-Service ' + $script:startTotal + ' times, Set-Service ' + $script:setTotal + ' times)') ($script:startTotal -eq 0 -and $script:setTotal -eq 0)
$env:ProgramData = $origProgramData

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-machine units: ALL PASS'; exit 0 }
Write-Host "solo-machine units: $fail FAILED"; exit 1
