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

# ---- 1b. SOLO 28: Solo's ssh task runs sshd.exe ITSELF, as SYSTEM, from an admin-only config ---------------
# A SYSTEM task must never run a script (or read a config) a user can edit, so the rows below read the code of
# Register-SshTask / Remove-SshTask - comments stripped - for what it registers and in what order.
function Get-FnCode([string]$name) {
    $f = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
    if ($f.Count -ne 1) { return '' }
    return (($f[0].Extent.Text -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
}
$regCode = Get-FnCode 'Register-SshTask'
$remCode = Get-FnCode 'Remove-SshTask'
Check 'Register-SshTask registers the task as SYSTEM (ServiceAccount, RunLevel Highest) and NOT as the user (no S4U)' (
    $regCode -match "-UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest" -and $regCode -notmatch 'S4U' -and $regCode -notmatch '-UserId \$ForUser')
Check 'its action is sshd.exe itself with -D -f <machine config>, NOT PowerShell and NOT solo-sshd.ps1 -Run' (
    $regCode -match 'New-ScheduledTaskAction -Execute \$sshd ' -and $regCode -match "'-D -f " -and $regCode -notmatch '-Execute \$Ps' -and $regCode -notmatch "'-Run'" -and $regCode -notmatch '\s-Run\b')
$iInstall = $regCode.IndexOf("'-Install'"); $iRegister = $regCode.IndexOf('Register-ScheduledTask')
Check 'it has solo-sshd.ps1 -Install make the admin-only folder, with -OsUser, BEFORE it registers the task' ($iInstall -ge 0 -and $regCode -match "'-Install', '-OsUser'" -and $iRegister -gt $iInstall)
Check 'it requires the task''s sshd to be owned by SYSTEM, and compares the host key with the MACHINE folder''s .pub' ($regCode -match "NT AUTHORITY\\SYSTEM" -and $regCode -match 'MachineSshDir' -and $regCode -match 'ssh_host_ed25519_key\.pub')
Check 'Remove-SshTask calls solo-sshd.ps1 -Uninstall (stop, and delete the machine folder) and fails if the folder is left' ($remCode -match "'-Uninstall'" -and $remCode -match 'Fail \(''the machine ssh folder')
Check 'the machine folder comes from the OS (GetFolderPath), not from an environment variable' ($text -match '\$MachineSshDir = Join-Path \(\[Environment\]::GetFolderPath\(''CommonApplicationData''\)\)')
$ln = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SshLoginName' }, $true))
if ($ln.Count -eq 1) {
    . ([scriptblock]::Create($ln[0].Extent.Text))
    $saveCN = $env:COMPUTERNAME; $env:COMPUTERNAME = 'ACE'
    $ForUser = 'ACE\Don'; $l1 = Get-SshLoginName
    $ForUser = 'CORP\Alice'; $l2 = Get-SshLoginName
    $ForUser = 'Bob'; $l3 = Get-SshLoginName
    $env:COMPUTERNAME = $saveCN
    Write-Host ("login names: ACE\Don -> [$l1]   CORP\Alice -> [$l2]   Bob -> [$l3]")
    Check 'the login name sshd allows: a local account is its lower-case name, a domain account is name@domain' ($l1 -eq 'don' -and $l2 -eq 'alice@corp' -and $l3 -eq 'bob')
} else { Check 'Get-SshLoginName exists exactly once' $false }

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

# ---- 9. SOLO 38: the startup task for a user Windows will not give an S4U task --------------------------------
# Measured 6 Oct 2026 (a guest): S4U is refused with "Access is denied" for a STANDARD user, whoever registers it
# (that user unelevated, an administrator, SYSTEM), at startup or at log on; an Interactive task at log on is
# accepted.  Register-SoloTask is loaded out of the file and run with the Task Scheduler cmdlets that change
# anything (Register-, Unregister-, Start-, Stop-ScheduledTask) and the process lookups replaced by stubs, so no
# task is made.  The New-ScheduledTask* cmdlets are the real ones: they only build objects.
$fnTask = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Register-SoloTask' }, $true))
if ($fnTask.Count -ne 1) { Check 'Register-SoloTask exists exactly once' $false }
else {
    . ([scriptblock]::Create($fnTask[0].Extent.Text))
    # THE MODULE IS LOADED BEFORE THE STUBS ARE DEFINED.  The first New-ScheduledTask* call auto-loads
    # ScheduledTasks, and that load REPLACED the stubs (their Source became "ScheduledTasks"): the first version of
    # this section ran the real Register-/Unregister-ScheduledTask against the real task "SD Core Solo" and was
    # saved from deleting it only by being unelevated.  So: import first, define the stubs after, name the task
    # something that can never be the real one, and refuse to run a case unless every mutating command resolves to
    # a stub (a function with no Source) - see the gate below.
    Import-Module ScheduledTasks -ErrorAction SilentlyContinue
    $TaskName = 'ZZ-SoloMachine-UnitTest-NotARealTask'
    $ForUser = 'ACE\don'
    $Ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'   # solo-machine.ps1 defines this at its top
    $AppDir = Join-Path $scratch 'app'
    $sdexe = Join-Path $AppDir 'usr\bin\sd-solo.exe'
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $AppDir 'solo-start.ps1'), '# stand-in: the real one is solo-start.ps1')
    $script:registered = New-Object System.Collections.ArrayList
    $script:current = $null; $script:refuseS4U = $false; $script:refuseAll = $false; $script:taskKind = ''
    function Register-ScheduledTask {
        [CmdletBinding()] param($TaskName, $Action, $Principal, $Trigger, $Settings)
        [void]$script:registered.Add([pscustomobject]@{ Logon = [string]$Principal.LogonType; User = [string]$Principal.UserId; Trigger = [string]$Trigger.CimClass.CimClassName
                                                        Exec = [string]$Action.Execute; Args = [string]$Action.Arguments })
        if ($script:refuseAll -or ($script:refuseS4U -and [string]$Principal.LogonType -eq 'S4U')) { throw 'Access is denied.' }
        $script:current = [pscustomobject]@{ State = 'Ready'; Principal = [pscustomobject]@{ UserId = [string]$Principal.UserId; LogonType = [string]$Principal.LogonType }
                                             Actions = @([pscustomobject]@{ Execute = $Action.Execute; Arguments = $Action.Arguments }) }
    }
    function Get-ScheduledTask { [CmdletBinding()] param($TaskName) return $script:current }
    function Get-ScheduledTaskInfo { [CmdletBinding()] param($TaskName) return [pscustomobject]@{ LastRunTime = (Get-Date); LastTaskResult = 0 } }
    function Start-ScheduledTask { [CmdletBinding()] param($TaskName) }
    function Stop-ScheduledTask { [CmdletBinding()] param($TaskName) }
    function Unregister-ScheduledTask { [CmdletBinding()] param($TaskName, $Confirm) }
    function Get-CimInstance { [CmdletBinding()] param($ClassName, $Filter)
        return [pscustomobject]@{ Name = 'sdwind.exe'; ExecutablePath = (Join-Path (Split-Path $sdexe) 'sdwind.exe'); ProcessId = 4242; SessionId = 2 } }
    function Invoke-CimMethod { [CmdletBinding()] param($InputObject, $MethodName) return [pscustomobject]@{ Domain = 'ACE'; User = 'don' } }

    $stubNames = 'Register-ScheduledTask', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo', 'Start-ScheduledTask', 'Stop-ScheduledTask', 'Unregister-ScheduledTask', 'Get-CimInstance', 'Invoke-CimMethod'
    $unstubbed = @($stubNames | Where-Object { $c = Get-Command $_ -ErrorAction SilentlyContinue; -not ($c -and $c.CommandType -eq 'Function' -and -not $c.Source) })
    Check ('every command Register-SoloTask uses that changes or reads the machine is this test''s own stub (a REAL one would touch the real task); not stubbed: [' + ($unstubbed -join ', ') + ']') ($unstubbed.Count -eq 0)
    $script:unsafe = ($unstubbed.Count -ne 0)

    function Run-Task([bool]$refuseS4U, [bool]$refuseAll) {
        if ($script:unsafe) { return 'NOT RUN: a stub is not in effect, so running Register-SoloTask could touch the real Task Scheduler' }
        Reset-Run; $script:registered.Clear(); $script:current = $null; $script:taskKind = ''
        $script:refuseS4U = $refuseS4U; $script:refuseAll = $refuseAll
        $threw = ''
        try { Register-SoloTask } catch { $threw = $_.Exception.Message }
        return $threw
    }
    $r = @()
    $threw = Run-Task $false $false
    Write-Host ('--- S4U accepted: ' + (($script:registered | ForEach-Object { $_.Logon + '/' + $_.Trigger }) -join ', ') + ' kind=' + $script:taskKind + ' / ' + (($script:notes | ForEach-Object { $_.Trim() }) -join ' / '))
    Check 'S4U accepted (an administrator user): ONE registration, S4U with a boot trigger, kind "startup", no fallback note, no failure' (
        $threw -eq '' -and $script:registered.Count -eq 1 -and $script:registered[0].Logon -eq 'S4U' -and $script:registered[0].Trigger -eq 'MSFT_TaskBootTrigger' -and
        $script:taskKind -eq 'startup' -and (($script:notes -join '|') -notmatch 'signs in') -and $script:fails.Count -eq 0 -and ($script:notes -join '|') -match 'PASS  the SD server \(sdwind\.exe\) is running as ACE\\don')
    $threw = Run-Task $true $false
    Write-Host ('--- S4U refused: ' + (($script:registered | ForEach-Object { $_.Logon + '/' + $_.Trigger }) -join ', ') + ' kind=' + $script:taskKind + ' / ' + (($script:notes | ForEach-Object { $_.Trim() }) -join ' / '))
    Check 'S4U refused (a standard user): the S4U attempt first, then an INTERACTIVE task with a LOG-ON trigger for the same user, kind "sign-in"' (
        $threw -eq '' -and $script:registered.Count -eq 2 -and $script:registered[0].Logon -eq 'S4U' -and $script:registered[1].Logon -eq 'Interactive' -and
        $script:registered[1].Trigger -eq 'MSFT_TaskLogonTrigger' -and $script:registered[1].User -eq 'ACE\don' -and $script:taskKind -eq 'sign-in')
    Check 'S4U refused: the report names Windows'' refusal and its reason, says SD starts at sign-in, and the step PASSES (no failure raised)' (
        $script:fails.Count -eq 0 -and ($script:notes -join '|') -match 'Windows refused a startup task.*Access is denied' -and ($script:notes -join '|') -match 'at sign-in' -and
        ($script:notes -join '|') -match 'SD starts when ACE\\don signs in; it does not start before that' -and ($script:notes -join '|') -match 'PASS  the SD server \(sdwind\.exe\)')
    # The SIGN-IN task must not run sd-solo.exe itself: an Interactive task shows the program's console, sdwind
    # stays attached to it, and closing the window stopped SD (measured, 6 Oct 2026).  It runs a HIDDEN PowerShell
    # that starts SD with Start-Process -WindowStyle Hidden.  The S4U task (session 0, no desktop) is unchanged.
    $threw = Run-Task $true $false
    Check 'the S4U startup task still runs sd-solo.exe -start itself (session 0 has no window to show; unchanged)' (
        $script:registered.Count -eq 2 -and $script:registered[0].Exec -eq $sdexe -and $script:registered[0].Args -eq '-start')
    $conhostExe = Join-Path $env:SystemRoot 'System32\conhost.exe'
    Check 'the SIGN-IN task runs conhost.exe --headless around PowerShell (no window, no Windows Terminal flash), which runs solo-start.ps1 from the tree - never sd-solo.exe itself' (
        $script:registered[1].Exec -eq $conhostExe -and
        $script:registered[1].Args -ceq ('--headless "' + $Ps + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $AppDir 'solo-start.ps1') + '"') -and
        $script:registered[1].Exec -ne $sdexe)
    # A user name with a space and an apostrophe: the helper's path is a double-quoted -File argument, passed whole.
    $appSave = $AppDir; $sdSave = $sdexe
    $AppDir = Join-Path $scratch "O'Brien x"
    $sdexe = Join-Path $AppDir 'usr\bin\sd-solo.exe'
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $AppDir 'solo-start.ps1'), '# stand-in')
    $threw = Run-Task $true $false
    Check 'a path with a space and an apostrophe is passed to -File whole, in double quotes' (
        $threw -eq '' -and $script:registered[1].Args -ceq ('--headless "' + $Ps + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $AppDir 'solo-start.ps1') + '"'))
    # No helper in the tree = a loud failure, never a task that starts nothing.
    Remove-Item -LiteralPath (Join-Path $AppDir 'solo-start.ps1') -Force
    $threw = Run-Task $true $false
    Check 'solo-start.ps1 missing from the tree: the registration throws (so the step FAILS) and no sign-in task is made' (
        $threw -match 'solo-start\.ps1 is not in' -and $script:registered.Count -eq 1 -and $null -eq $script:current)
    $AppDir = $appSave; $sdexe = $sdSave

    $threw = Run-Task $false $true
    Write-Host ('--- both refused: ' + (($script:registered | ForEach-Object { $_.Logon + '/' + $_.Trigger }) -join ', ') + ' threw=[' + $threw + ']')
    Check 'both refused: both were tried, S4U first, and the error is thrown to the caller (it is not swallowed into a pass)' (
        $script:registered.Count -eq 2 -and $script:registered[0].Logon -eq 'S4U' -and $script:registered[1].Logon -eq 'Interactive' -and $threw -match 'Access is denied')
}
# The caller records a throw as a failed step and CARRIES ON: a startup-task failure must not skip the ssh steps
# (measured: it did, and ssh was never tried).  Read from the file with comments stripped.
$codeNoComments = (($text -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"   # NOT $code: section 8 reuses that name for an exit code
Check 'the main flow wraps Register-SoloTask in try/catch that calls Fail, so a throw does not reach the outer catch and skip the ssh steps' (
    $codeNoComments -match '(?s)try \{ Register-SoloTask \}\s*catch \{\s*Fail \(''ERROR '' \+ \$_\.Exception\.Message\.Trim\(\)\)')

Check ('across every run above the system sshd was NEVER started or given a startup type (Start-Service ' + $script:startTotal + ' times, Set-Service ' + $script:setTotal + ' times)') ($script:startTotal -eq 0 -and $script:setTotal -eq 0)
$env:ProgramData = $origProgramData

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'solo-machine units: ALL PASS'; exit 0 }
Write-Host "solo-machine units: $fail FAILED"; exit 1
