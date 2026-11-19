# witness-solo-host.ps1 - the HOST half of the 18 Nov 2026 sitting: SD Core Solo rows that need a current Solo install and a person
# to type its passwords, but no VM.  Sitting plan: SDCore4Windows .claude/vm-sitting-20261118.md, part H.
#
#   powershell -ExecutionPolicy Bypass -File C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\witness-solo-host.ps1 -Only <section[,section]>
#   powershell -ExecutionPolicy Bypass -File C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\witness-solo-host.ps1 -List
#
# AN ORDINARY, UNELEVATED PowerShell on the HOST, as the Windows user Solo is installed for.  It asks (Read-Host, no echo) only for
# the passwords the chosen sections need: the ACCOUNT password (every section), the ADMINISTRATOR password (voc, lock, xfer), the
# GLOBAL password (api), the WINDOWS password of this user (xfer: Solo's sshd checks it).  None is printed, logged or put on a
# command line; a password seen in SD's output is masked and fails the run.
#
# SECTIONS (run in this order):
#   oscopy   SOLO 67   OSCOPY a b; again (refused: exists, 12068); OSCOPY a b OVERWRITE.  Fixture files zzoscopy_a/_b in the account.
#   voc      SOLO 50   ADMIN, LIST.VOC.REMOVED answers, RESTORE.VOC of a name never removed answers in words, VOC unchanged.
#   lock     247       ADMIN, LOCK.TRACER ON, a program that takes and lets go an update lock, the report shows both lines, OFF.
#   runjob   SOLO 81   one-shot "run.job zznosuchjob" with NOTHING on its input signs in by the kept password (audit "login password
#                      ... via=stored", not 15186) and RUN.JOB answers; control: one-shot WHERE with nothing on its input is refused 15186.
#   api      SOLO 60   API (scram-probe.py, port 4249): the GLOBAL password as sduser is VERIFIED (the control), as sdsys is REFUSED with
#                      "Invalid username or password" and the audit has "api refused user=sdsys reason=no credential".
#   xfer     299 (B)   sd.conf XFER=1 (a copy kept), SET.XFER.ACCESS ON; an ssh session to Solo's sshd (127.0.0.1:4251) types RECEIVE;
#                      sftp puts a text file and a binary one; Enter closes.  PASS: text file in xfer.in with the same SHA-256, binary
#                      not kept, audit open/connect/file/refused/close.  Put back: SET.XFER.ACCESS OFF, the original sd.conf.
#   stop     203       a session held open (SLEEP 300), then "sd-solo -stop": the session's process is gone within 20 s and no sd-solo.exe
#                      of this tree survives; then "sd-solo -start" and SD answers again.  LAST: it ends every Solo session.
# Exit 0 every check passed, 1 a check failed, 2 could not run.  Log: %LOCALAPPDATA%\SD-verify\witness-solo-host-<time>.log.
#
# START-HISTORY:
# 18 Nov 26  New, for the sitting of 18 Nov (rows SOLO 67, SOLO 50, 247, SOLO 81, SOLO 60, 299, 203).  Session driving copied from
#            verify-solo.ps1 (cmd.exe, output to a file, ASCII stdin with no preamble, spare OFFs, 90 s limit).  NOT RUN.
# END-HISTORY

param(
    [string[]]$Only = @(),
    [switch]$List
)
$ErrorActionPreference = 'Stop'

$Sections = @('oscopy', 'voc', 'lock', 'runjob', 'api', 'xfer', 'stop')
if ($List) { $Sections | ForEach-Object { Write-Host $_ }; exit 0 }
$want = @($Only | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
if ($want.Count -eq 0) { Write-Host ('Give -Only <section[,section]> (or -List).  Sections: ' + ($Sections -join ', ')); exit 2 }
foreach ($w in $want) { if ($Sections -notcontains $w) { Write-Host ("No section called '" + $w + "'.  Sections: " + ($Sections -join ', ')); exit 2 } }
$want = @($Sections | Where-Object { $want -contains $_ })   # the fixed order, whatever order was typed

$Gplbld  = $PSScriptRoot
$Root    = Join-Path $env:USERPROFILE 'SDCoreSolo'
$SdExe   = Join-Path $Root 'usr\bin\sd-solo.exe'
$WindExe = Join-Path $Root 'usr\bin\sdwind.exe'
$Sdsys   = Join-Path $Root 'sdsys'
$Audit   = Join-Path $Sdsys 'audit'
$Conf    = Join-Path $Root 'sd.conf'
$Acct    = 'sduser'
$AcctDir = Join-Path $Root ('user_accounts\' + $Acct)
$Scram   = Join-Path $Gplbld 'scram-probe.py'
$WinUser = "$env:USERNAME".Trim().ToLower()
$LogDir  = Join-Path $env:LOCALAPPDATA 'SD-verify'
$null = New-Item -ItemType Directory -Force -Path $LogDir
$LogFile = Join-Path $LogDir ('witness-solo-host-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$Work    = Join-Path $env:TEMP ('sd-witness-solo-' + $PID)
$null = New-Item -ItemType Directory -Force -Path $Work

$script:log = New-Object System.Collections.ArrayList
$script:fails = @(); $script:passes = 0; $script:secrets = @(); $script:leaked = $false; $script:sessionNo = 0
function Say([string]$s) { Write-Host $s; [void]$script:log.Add($s) }
function Save-Log { try { [IO.File]::WriteAllLines($LogFile, [string[]]$script:log.ToArray(), (New-Object Text.UTF8Encoding($false))) } catch { } }
function Check([string]$Row, [string]$Label, [bool]$Ok, [string]$Why) {
    if ($Ok) { Say ('  PASS  ' + $Row + ': ' + $Label); $script:passes++ }
    else { Say ('  FAIL  ' + $Row + ': ' + $Label + '   (' + $Why + ')'); $script:fails += ($Row + ': ' + $Label) }
}
function Bail([string]$Why) {
    Say ('CANNOT RUN: ' + $Why); Say 'VERDICT: CANNOT RUN - nothing further was measured'
    if ($script:oldInEnc) { try { [Console]::InputEncoding = $script:oldInEnc } catch { } }
    Save-Log; exit 2
}
function Get-Lines([string]$t) { return ,@($t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function CountOf($L, [string]$Rx) { return @($L | Where-Object { $_ -match $Rx }).Count }
function Read-AuditText {
    if (-not (Test-Path -LiteralPath $Audit)) { return '' }
    $fs = [IO.File]::Open($Audit, 'Open', 'Read', 'ReadWrite')
    try { return (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() }
}
function Get-AuditMark { return (Read-AuditText).Length }
function Get-AuditSince([int]$Mark) {
    $t = Read-AuditText
    if ($t.Length -lt $Mark) { return ,@(Get-Lines $t) }   # the trail was rotated: everything is new
    return ,@(Get-Lines ($t.Substring($Mark)))
}
function Show-Audit($Lines) { Say '    --- audit since the mark ---'; foreach ($l in $Lines) { Say ('    | ' + (Mask $l)) }; if ($Lines.Count -eq 0) { Say '    | (no line)' } }
function Mask([string]$t) {
    foreach ($s in $script:secrets) {
        if ($s -and $t.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $script:leaked = $true; $t = $t -replace [regex]::Escape($s), '********' }
    }
    return $t
}
function Read-Password([string]$Prompt) {
    $ss = Read-Host -AsSecureString $Prompt
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

# One sd-solo session (verify-solo.ps1's Invoke-Sd): cmd.exe, output to a FILE (sdwind would hold a pipe open), stdin as ASCII bytes
# with no preamble, two spare OFFs on an interactive session (SOLO 16), 90 s and then killed with its tree.  $Shown describes the
# input; the input itself is never printed.
function Invoke-Sd([string]$Label, [string]$SdArgs, [string]$InputText, [string]$Shown) {
    $script:sessionNo++
    $out = Join-Path $Work ('{0:d2}-{1}.txt' -f $script:sessionNo, $Label)
    Say ''
    Say ('  $ ' + $SdExe + ' ' + $SdArgs + '   [input: ' + $Shown + ']')
    if ($SdArgs -eq '' -and $InputText) { $InputText += "OFF`nOFF`n" }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c ""' + $SdExe + '" ' + $SdArgs + ' >"' + $out + '" 2>&1"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $Work
    $p = [Diagnostics.Process]::Start($psi)
    if ($p.StandardInput.Encoding.GetPreamble().Length -ne 0) { Say '    REFUSED TO SEND: the stdin writer writes a preamble'; $InputText = '' }
    if ($InputText) {
        $bytes = [Text.Encoding]::ASCII.GetBytes($InputText)
        $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length); $p.StandardInput.BaseStream.Flush()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(90000)) { $null = & taskkill.exe /PID $p.Id /T /F 2>$null; Say '    TIMED OUT after 90 s - killed with its tree' }
    else { Say ('    exit ' + $p.ExitCode) }
    $text = ''
    if (Test-Path -LiteralPath $out) {
        $fs = [IO.File]::Open($out, 'Open', 'Read', 'ReadWrite')
        try { $text = (New-Object IO.StreamReader($fs, [Text.Encoding]::GetEncoding(28591))).ReadToEnd() } finally { $fs.Close() }
    }
    $text = Mask ($text -replace "`r", '')
    foreach ($l in ($text -split "`n")) {
        if (-not $l.Trim()) { continue }
        if ($l.Length -gt 2000) { $l = $l.Substring(0, 200) + ' ...[CUT: ' + $l.Length + ' characters]' }
        Say ('    | ' + (($l -replace [char]27, '^[') -replace [char]7, '^G'))
    }
    return $text
}
# An interactive session: the account password, ADMIN + the administrator password when asked, TERM, the commands, OFF.
function Invoke-Session([string]$Label, [string[]]$Cmds, [switch]$Admin) {
    $lines = @($script:acctPw); $shown = @('account password')
    if ($Admin) { $lines += @('ADMIN', $script:adminPw); $shown += @('ADMIN', 'administrator password') }
    $lines += @('TERM 200,9999') + $Cmds + @('OFF'); $shown += @('TERM 200,9999') + $Cmds + @('OFF')
    return (Invoke-Sd $Label '' (($lines -join "`n") + "`n") ($shown -join ', '))
}

# --- what this run uses ---------------------------------------------------------------------------------------------------------
Say ('=== witness-solo-host ' + (Get-Date -Format s))
Say ('script    : ' + $PSCommandPath)
Say ('sections  : ' + ($want -join ', '))
Say ('Solo tree : ' + $Root)
Say ('sd-solo   : ' + $SdExe + '   exists: ' + (Test-Path -LiteralPath $SdExe) + $(if (Test-Path -LiteralPath $SdExe) { '   written ' + (Get-Item -LiteralPath $SdExe).LastWriteTime } else { '' }))
Say ('account   : ' + $AcctDir + '   exists: ' + (Test-Path -LiteralPath $AcctDir))
Say ('audit     : ' + $Audit + '   exists: ' + (Test-Path -LiteralPath $Audit))
Say ('log       : ' + $LogFile)
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Bail 'this PowerShell is ELEVATED; Solo runs as the ordinary user - use an ordinary window.' }
if (-not (Test-Path -LiteralPath $SdExe)) { Bail 'no sd-solo.exe - SD Core Solo is not installed for this user.' }
if (-not (Test-Path -LiteralPath $AcctDir)) { Bail ('no account folder ' + $AcctDir) }
if (-not (Test-Path -LiteralPath $Audit)) { Bail ('no audit trail ' + $Audit + ' - every section reads it') }

Say ''
Say '--- assert-current (the install must match source) ---'
& (Join-Path $Gplbld 'assert-current.ps1') | ForEach-Object { Say ('  ' + $_) }
if ($LASTEXITCODE -ne 0) { Bail 'assert-current refuses - the installed Solo does not match source.' }

$needAdmin = @($want | Where-Object { @('voc', 'lock', 'xfer') -contains $_ }).Count -gt 0
$script:acctPw = Read-Password 'Account password (the one every Solo session asks for)'
if (-not $script:acctPw) { Bail 'no account password typed' }
$script:secrets += $script:acctPw
$script:adminPw = ''
if ($needAdmin) { $script:adminPw = Read-Password 'Administrator password (ADMIN)'; if (-not $script:adminPw) { Bail 'no administrator password typed' }; $script:secrets += $script:adminPw }
$script:globalPw = ''
if ($want -contains 'api') { $script:globalPw = Read-Password 'Global password'; if (-not $script:globalPw) { Bail 'no global password typed' }; $script:secrets += $script:globalPw }
$script:winPw = ''
if ($want -contains 'xfer') { $script:winPw = Read-Password ('Windows password of ' + $WinUser + ' (Solo''s sshd checks it)'); if (-not $script:winPw) { Bail 'no Windows password typed' }; $script:secrets += $script:winPw }
Say ('passwords : account typed' + $(if ($needAdmin) { ', administrator typed' } else { '' }) + $(if ($script:globalPw) { ', global typed' } else { '' }) + $(if ($script:winPw) { ', Windows typed' } else { '' }) + ' (none shown)')

$script:oldInEnc = [Console]::InputEncoding
try { [Console]::InputEncoding = New-Object Text.ASCIIEncoding } catch { }

# A first session proves the account password before anything is changed: it must land in the account and unlock nothing it should not.
$t = Invoke-Session 'password-check' @('WHERE')
if ((CountOf (Get-Lines $t) ('(?i)[\\/]user_accounts[\\/]' + $Acct + '$')) -lt 1) { Bail 'the account password did not sign in (no WHERE line in the account) - nothing was changed' }
if ($needAdmin) {
    $t = Invoke-Session 'admin-check' @('ADMIN OFF') -Admin
    if ((CountOf (Get-Lines $t) '^Administrator commands unlocked') -lt 1) { Bail 'ADMIN did not unlock with that administrator password - nothing was changed' }
}

try {
# ================================================================================================================ oscopy (SOLO 67)
if ($want -contains 'oscopy') {
    Say ''; Say '=== oscopy - SOLO 67: OSCOPY a b, again (exists), OVERWRITE'
    $a = Join-Path $AcctDir 'zzoscopy_a.txt'; $b = Join-Path $AcctDir 'zzoscopy_b.txt'
    foreach ($f in @($a, $b)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    [IO.File]::WriteAllText($a, "first`r`n", (New-Object Text.ASCIIEncoding))
    Say ('  fixture: ' + $a + ' (first); ' + $b + ' absent: ' + (-not (Test-Path -LiteralPath $b)))
    $t1 = Invoke-Session 'oscopy-1' @('OSCOPY zzoscopy_a.txt zzoscopy_b.txt')
    $b1 = if (Test-Path -LiteralPath $b) { [IO.File]::ReadAllText($b) } else { '' }
    Check 'SOLO 67' 'OSCOPY a b copies (12066) and b holds a''s text' (((CountOf (Get-Lines $t1) 'zzoscopy_a\.txt copied to .*zzoscopy_b\.txt') -eq 1) -and $b1 -eq "first`r`n") ('b ' + $(if ($b1) { 'holds ' + $b1.Length + ' bytes' } else { 'absent' }))
    [IO.File]::WriteAllText($a, "second`r`n", (New-Object Text.ASCIIEncoding))
    $t2 = Invoke-Session 'oscopy-2' @('OSCOPY zzoscopy_a.txt zzoscopy_b.txt')
    $b2 = [IO.File]::ReadAllText($b)
    Check 'SOLO 67' 'OSCOPY a b again is refused (12068: give overwrite or append) and b is unchanged' (((CountOf (Get-Lines $t2) 'already exists: give overwrite or append') -eq 1) -and $b2 -eq "first`r`n" -and (CountOf (Get-Lines $t2) 'copied to') -eq 0) ('b now ' + $b2.Trim())
    $t3 = Invoke-Session 'oscopy-3' @('OSCOPY zzoscopy_a.txt zzoscopy_b.txt OVERWRITE')
    $b3 = [IO.File]::ReadAllText($b)
    Check 'SOLO 67' 'OSCOPY a b OVERWRITE copies and b holds the new text' (((CountOf (Get-Lines $t3) 'zzoscopy_a\.txt copied to .*zzoscopy_b\.txt') -eq 1) -and $b3 -eq "second`r`n") ('b now ' + $b3.Trim())
    foreach ($f in @($a, $b)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    Say ('  cleanup: a left ' + (Test-Path -LiteralPath $a) + ', b left ' + (Test-Path -LiteralPath $b))
}

# ================================================================================================================ voc (SOLO 50)
if ($want -contains 'voc') {
    Say ''; Say '=== voc - SOLO 50: LIST.VOC.REMOVED and RESTORE.VOC answer for the administrator'
    # RESTORE.VOC takes "account id"; a name never removed has no saved copy, so it answers 12921 and writes nothing.
    $t = Invoke-Session 'voc' @('LIST.VOC.REMOVED', ('RESTORE.VOC ' + $Acct + ' ZZNEVERREMOVED')) -Admin
    $L = Get-Lines $t
    Check 'SOLO 50' 'neither verb is unknown to the account (no "not in your VOC")' ((CountOf $L '(?i)is not in your VOC') -eq 0) 'a verb is not in the VOC'
    Check 'SOLO 50' 'neither is refused for want of the administrator (2001)' ((CountOf $L 'Command requires administrator privileges') -eq 0) '2001 is in the output'
    Check 'SOLO 50' 'LIST.VOC.REMOVED answers with its count line (12910)' ((CountOf $L 'VOC record\(s\) that SD no longer ships') -eq 1) 'no 12910 line'
    Check 'SOLO 50' 'RESTORE.VOC of a name never removed answers "No saved copy" (12921) and puts nothing back (no 12920)' (((CountOf $L ('No saved copy of ZZNEVERREMOVED for account ' + $Acct)) -eq 1) -and ((CountOf $L '^Put back ') -eq 0)) 'no 12921 line, or a 12920 line'
}

# ================================================================================================================ lock (247)
if ($want -contains 'lock') {
    Say ''; Say '=== lock - 247: LOCK.TRACER ON, a lock taken and let go, the report shows it, OFF'
    $bpDir = Join-Path $AcctDir 'bp'
    $prog = Join-Path $bpDir 'zzlocktr'
    if (Test-Path -LiteralPath $prog) { Bail ('a program zzlocktr is already in ' + $bpDir + ' - left by an earlier run?') }
    [IO.File]::WriteAllText($prog, ((@('open ''VOC'' to f else stop ''ZZLOCKTR NO VOC''', 'readu r from f, ''ZZLOCKTR.REC'' else null', 'release f, ''ZZLOCKTR.REC''', 'crt ''ZZLOCKTR DONE''', 'end') -join "`n") + "`n"), (New-Object Text.ASCIIEncoding))
    try {
        $t = Invoke-Session 'locktracer' @('LOCK.TRACER ON', 'BASIC BP zzlocktr', 'RUN BP zzlocktr', 'LOCK.TRACER NO.PAGE', 'LOCK.TRACER OFF') -Admin
        $L = Get-Lines $t
        Check '247' 'LOCK.TRACER ON says lock tracing is on (12364)' ((CountOf $L '^lock tracing is on$') -eq 1) 'no "lock tracing is on" line'
        Check '247' 'the program ran' ((CountOf $L '^ZZLOCKTR DONE$') -eq 1) 'no ZZLOCKTR DONE (did it compile?)'
        Check '247' 'the report shows the lock on ZZLOCKTR.REC (a line naming it)' ((CountOf $L 'ZZLOCKTR\.REC') -ge 1 -and (CountOf $L '^no locks have been logged|^there is no lock trace') -eq 0) 'no report line with ZZLOCKTR.REC'
        Check '247' 'LOCK.TRACER OFF says lock tracing is off (12365)' ((CountOf $L '^lock tracing is off$') -eq 1) 'no "lock tracing is off" line'
        Check '247' 'no refusal: not "for the administrator", not "could not be started"' ((CountOf $L 'lock tracing is for the administrator|lock tracing could not be started') -eq 0) 'a refusal line is present'
        $trace = Join-Path $Sdsys 'locktrace'
        Say ('  ' + $trace + ' exists: ' + (Test-Path -LiteralPath $trace) + $(if (Test-Path -LiteralPath $trace) { ', ' + (Get-Item -LiteralPath $trace).Length + ' bytes' } else { '' }))
    } finally {
        foreach ($f in @($prog, (Join-Path $AcctDir 'bp.out\zzlocktr'))) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
        Say ('  cleanup: bp\zzlocktr left ' + (Test-Path -LiteralPath $prog))
    }
}

# ================================================================================================================ runjob (SOLO 81)
if ($want -contains 'runjob') {
    Say ''; Say '=== runjob - SOLO 81: the kept password still signs in run.job; a plain one-shot is still refused'
    $mark = Get-AuditMark
    $t = Invoke-Sd 'runjob' 'run.job zznosuchjob' '' 'nothing'
    $L = Get-Lines $t
    $a = Get-AuditSince $mark; Show-Audit $a
    Check 'SOLO 81' 'run.job with nothing on its input is NOT refused with 15186' ((CountOf $L 'The kept password signs in only') -eq 0) 'the 15186 sentence is in the output'
    Check 'SOLO 81' 'the audit has the kept-password sign-in ("login password account=sduser via=stored", nothing after it)' ((CountOf $a ('login password account=' + $Acct + ' via=stored\s*$')) -eq 1) 'no such line'
    Check 'SOLO 81' 'RUN.JOB itself answered (15938 no job, or 15948 jobs off) - it ran in a signed-in session' ((CountOf $L 'No job is named zznosuchjob|Scheduled jobs are off on this computer') -eq 1) 'neither RUN.JOB answer'
    $mark = Get-AuditMark
    $t = Invoke-Sd 'oneshot-control' 'WHERE' '' 'nothing'
    $a = Get-AuditSince $mark; Show-Audit $a
    Check 'SOLO 81' 'CONTROL: a plain one-shot (WHERE) with nothing on its input is refused with 15186 and audited' (((CountOf (Get-Lines $t) 'The kept password signs in only') -ge 1) -and ((CountOf $a 'via=stored refused reason=not a scheduled job') -eq 1)) 'not refused as delivered - is set.stored.access on?'
}

# ================================================================================================================ api (SOLO 60)
if ($want -contains 'api') {
    Say ''; Say '=== api - SOLO 60: the global password is never taken under the name SDSYS'
    $py = (Get-Command py.exe -ErrorAction SilentlyContinue)
    if (-not $py) { Bail 'no py.exe (the Python launcher) - scram-probe.py cannot run' }
    if (-not (Test-Path -LiteralPath $Scram)) { Bail ('no ' + $Scram) }
    function Invoke-Scram([string]$User, [string]$Pw, [string]$Label) {
        $argsText = '-3 "' + $Scram + '" --user ' + $User + ' --account ' + $Acct + ' --port 4249 -- WHO'
        Say ''; Say ('  $ ' + $py.Source + ' ' + $argsText + '   [SD_SCRAM_PASSWORD: ' + $Label + ', not shown]')
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $py.Source; $psi.Arguments = $argsText; $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['SD_SCRAM_PASSWORD'] = $Pw; $psi.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
        $p = [Diagnostics.Process]::Start($psi)
        $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(90000)) { $null = & taskkill.exe /PID $p.Id /T /F 2>$null; Say '    TIMED OUT after 90 s - killed' } else { Say ('    exit ' + $p.ExitCode) }
        $text = Mask ((($o.Result) + ($e.Result)) -replace "`r", '')
        foreach ($l in ($text -split "`n")) { if ($l.Trim()) { Say ('    | ' + $l) } }
        return $text
    }
    $tc = Invoke-Scram $Acct $script:globalPw 'the global password'
    Check 'SOLO 60' 'CONTROL: the global password as sduser logs in (SCRAM: server signature VERIFIED)' ((CountOf (Get-Lines $tc) '^SCRAM: server signature VERIFIED') -eq 1) 'not verified - wrong global password typed? the sdsys result below proves nothing then'
    $mark = Get-AuditMark
    $ts = Invoke-Scram 'sdsys' $script:globalPw 'the global password'
    Start-Sleep -Seconds 1
    $a = Get-AuditSince $mark; Show-Audit $a
    Check 'SOLO 60' 'the global password as sdsys is REFUSED with "Invalid username or password"' (((CountOf (Get-Lines $ts) '^SCRAM: login REFUSED at request') -eq 1) -and ((CountOf (Get-Lines $ts) 'Invalid username or password') -ge 1) -and ((CountOf (Get-Lines $ts) 'VERIFIED') -eq 0)) 'see the probe output'
    Check 'SOLO 60' 'the audit has "api refused user=sdsys reason=no credential"' ((CountOf $a 'api refused user=sdsys reason=no credential') -eq 1) 'no such audit line'
}

# ================================================================================================================ xfer (299)
if ($want -contains 'xfer') {
    Say ''; Say '=== xfer - 299: RECEIVE over Solo''s ssh login, a text file in, a binary one refused'
    $sftpExe = Get-Command sftp.exe -ErrorAction SilentlyContinue; $sshExe = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($null -eq $sftpExe -or $null -eq $sshExe) { Bail 'no ssh.exe or sftp.exe (Windows'' OpenSSH client) on PATH' }
    Say ('  sftp: ' + $sftpExe.Source + '   ssh: ' + $sshExe.Source + '   (Windows'' own client, not Git''s)')
    if ($sshExe.Source -notmatch '(?i)\\System32\\OpenSSH\\') { Bail ('ssh.exe resolves to ' + $sshExe.Source + ', not Windows'' OpenSSH (memory: Git''s ssh measures the wrong client)') }
    $tcp = New-Object Net.Sockets.TcpClient
    try { $tcp.Connect('127.0.0.1', 4251); Say '  127.0.0.1:4251 accepts a connection (Solo''s sshd is listening)' } catch { Bail 'nothing listens on 127.0.0.1:4251 - Solo''s sshd is not running (ssh off?)' } finally { $tcp.Close() }
    $inDir = Join-Path $AcctDir 'xfer.in'
    $confBak = Join-Path $Work 'sd.conf.before-xfer'
    Copy-Item -LiteralPath $Conf -Destination $confBak -Force
    $lines = @(Get-Content -LiteralPath $Conf)
    Say ('  sd.conf XFER lines before: ' + $(if (@($lines | Where-Object { $_ -match '^\s*XFER\s*=' }).Count) { (@($lines | Where-Object { $_ -match '^\s*XFER\s*=' }) -join ' | ') } else { '(none)' }))
    $opts = @('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL', '-o', 'ConnectTimeout=20', '-o', 'LogLevel=ERROR',
              '-o', 'PreferredAuthentications=password', '-o', 'NumberOfPasswordPrompts=1', '-p', '4251')
    $ask = Join-Path $Work 'askpass.cmd'
    [IO.File]::WriteAllText($ask, "@echo off`r`necho %SDPROBEPW%`r`n", (New-Object Text.ASCIIEncoding))
    function Start-Client([string]$Exe, [string[]]$ArgList) {
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe; $psi.Arguments = ($ArgList -join ' '); $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['SDPROBEPW'] = $script:winPw
        $psi.EnvironmentVariables['SSH_ASKPASS'] = $ask; $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'force'; $psi.EnvironmentVariables['DISPLAY'] = 'localhost:0'
        Say ('  > ' + $Exe + ' ' + $psi.Arguments)
        $p = [Diagnostics.Process]::Start($psi)
        return @{ P = $p; Out = $p.StandardOutput.ReadToEndAsync(); Err = $p.StandardError.ReadToEndAsync() }
    }
    try {
        $new = @($lines | Where-Object { $_ -notmatch '^\s*XFER\s*=' }) + 'XFER=1'
        [IO.File]::WriteAllLines($Conf, [string[]]$new, (New-Object Text.ASCIIEncoding))
        Say ('  sd.conf XFER lines after : ' + (@(Get-Content -LiteralPath $Conf | Where-Object { $_ -match '^\s*XFER\s*=' }) -join ' | ') + '   (each sd-solo reads sd.conf at its start; no restart)')
        $t = Invoke-Session 'xfer-on' @('SET.XFER.ACCESS ON') -Admin
        Check '299' 'SET.XFER.ACCESS ON says the account may move files: yes (15074)' ((CountOf (Get-Lines $t) ('Account ' + $Acct + ' may move files over its ssh login \(receive / send\): yes')) -eq 1) 'no 15074 "yes" line'

        $txt = Join-Path $Work 'orders.csv'
        [IO.File]::WriteAllText($txt, "id,qty,price`r`n1,4,9.95`r`n2,1,120.00`r`nwitness 299 Solo 18 Nov 26`r`n", (New-Object Text.ASCIIEncoding))
        $bin = Join-Path $Work 'logo.bin'; [IO.File]::WriteAllBytes($bin, [byte[]](0, 1, 2, 3, 255, 254, 10))
        $txtHash = (Get-FileHash -LiteralPath $txt -Algorithm SHA256).Hash
        Say ('  orders.csv sha256 ' + $txtHash)
        foreach ($n in @('orders.csv', 'logo.bin')) { $f = Join-Path $inDir $n; if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
        $mark = Get-AuditMark
        # The ssh session: Windows password to sshd (askpass), then SD's own prompt takes the ACCOUNT password on stdin.  Lines end CR
        # only, as a terminal sends them (witness-vm-xfer's first run: CR LF left an LF that RECEIVE read as Enter).
        $h = Start-Client $sshExe.Source ($opts + @(($WinUser + '@127.0.0.1')))
        $h.P.StandardInput.NewLine = "`r"
        Start-Sleep -Seconds 4
        $h.P.StandardInput.WriteLine($script:acctPw); $h.P.StandardInput.WriteLine('TERM 200,9999'); $h.P.StandardInput.WriteLine('RECEIVE'); $h.P.StandardInput.Flush()
        Start-Sleep -Seconds 10
        # sftp takes the port as -P (ssh's -p is "preserve" to sftp).
        $sftpOpts = @($opts | ForEach-Object { if ($_ -ceq '-p') { '-P' } else { $_ } })
        $c = Start-Client $sftpExe.Source ($sftpOpts + @(($WinUser + '@127.0.0.1')))
        foreach ($l in @(('put "' + $txt + '"'), ('put "' + $bin + '"'), 'quit')) { Say ('    sftp> ' + $l); $c.P.StandardInput.WriteLine($l) }
        $c.P.StandardInput.Close()
        if ($c.P.WaitForExit(60000)) {
            Say ('    --- sftp (exit ' + $c.P.ExitCode + ') ---')
            foreach ($l in ((Mask ($c.Out.Result + "`n" + $c.Err.Result)) -split "`n")) { if ($l.Trim()) { Say ('    | ' + $l.TrimEnd()) } }
        } else { Say ('  sftp did not end within 60 s (pid ' + $c.P.Id + ', left alone)') }
        Start-Sleep -Seconds 3
        $h.P.StandardInput.WriteLine(''); $h.P.StandardInput.Flush()        # Enter closes the transfer slot
        Start-Sleep -Seconds 6
        try { $h.P.StandardInput.WriteLine('OFF'); $h.P.StandardInput.Close() } catch { }
        if ($h.P.WaitForExit(30000)) {
            Say ('    --- the ssh session (RECEIVE), exit ' + $h.P.ExitCode + ' ---')
            foreach ($l in ((Mask ($h.Out.Result + "`n" + $h.Err.Result)) -split "`n")) { if ($l.Trim()) { Say ('    | ' + (($l.TrimEnd() -replace [char]27, '^[') -replace [char]7, '^G')) } }
        } else { Say ('  the ssh client (pid ' + $h.P.Id + ') is still running; its output is not read (left alone)') }
        Start-Sleep -Seconds 2
        $a = Get-AuditSince $mark; Show-Audit $a
        $got = Join-Path $inDir 'orders.csv'
        $gotHash = if (Test-Path -LiteralPath $got) { (Get-FileHash -LiteralPath $got -Algorithm SHA256).Hash } else { '' }
        Say ('  xfer.in\orders.csv: ' + $(if ($gotHash) { 'sha256 ' + $gotHash } else { 'ABSENT' }))
        Check '299' 'the text file arrived in xfer.in byte for byte (same SHA-256)' ($gotHash -ne '' -and $gotHash -eq $txtHash) ('got ' + $(if ($gotHash) { $gotHash } else { 'nothing' }))
        Check '299' 'the binary file was not kept' (-not (Test-Path -LiteralPath (Join-Path $inDir 'logo.bin'))) 'logo.bin is in xfer.in'
        foreach ($w in @(@('xfer open dir=in', 'the audit has the opening'), @('xfer connect dir=in', 'the audit has the connection'),
                         @('xfer file dir=in', 'the audit has the text file'), @('name=orders.csv', 'the file line names orders.csv'),
                         @('reason=not plain text', 'the audit has the binary file refused as not plain text'), @('xfer close dir=in', 'the audit has the closing'))) {
            Check '299' $w[1] ((CountOf $a ([regex]::Escape($w[0]))) -ge 1) ('no audit line with "' + $w[0] + '"')
        }
        Say '  NOT MEASURED: WinSCP''s .filepart (no WinSCP here; untried on Linux too)'
    } finally {
        Say ''; Say '  --- put back: SET.XFER.ACCESS OFF, the original sd.conf ---'
        $null = Invoke-Session 'xfer-off' @('SET.XFER.ACCESS OFF') -Admin
        Copy-Item -LiteralPath $confBak -Destination $Conf -Force
        Say ('  sd.conf XFER lines now: ' + $(if (@(Get-Content -LiteralPath $Conf | Where-Object { $_ -match '^\s*XFER\s*=' }).Count) { (@(Get-Content -LiteralPath $Conf | Where-Object { $_ -match '^\s*XFER\s*=' }) -join ' | ') } else { '(none)' }) + '   (the copy taken before, put back byte for byte)')
        foreach ($n in @('orders.csv', 'logo.bin')) { $f = Join-Path $inDir $n; if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    }
}

# ================================================================================================================ stop (203)
if ($want -contains 'stop') {
    Say ''; Say '=== stop - 203: sd-solo -stop ends a session that is still running (SIGKILL after ten seconds), then SD starts again'
    function Get-SoloProcs { return ,@(Get-CimInstance Win32_Process -Filter "Name='sd-solo.exe' or Name='sdwind.exe'" | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) }) }
    function Show-Procs([string]$When) { $ps = Get-SoloProcs; Say ('  ' + $When + ': ' + $(if ($ps.Count) { ($ps | ForEach-Object { $_.Name + '(' + $_.ProcessId + ')' }) -join ' ' } else { 'none of this tree' })); return ,$ps }
    $null = Show-Procs 'before'
    $held = Join-Path $Work 'held.txt'
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c ""' + $SdExe + '" >"' + $held + '" 2>&1"'
    $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.WorkingDirectory = $Work
    Say ('  $ ' + $SdExe + '   [input: account password, SLEEP 300 - and the input is held open]')
    $hp = [Diagnostics.Process]::Start($psi)
    $bytes = [Text.Encoding]::ASCII.GetBytes($script:acctPw + "`nSLEEP 300`n")
    $hp.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length); $hp.StandardInput.BaseStream.Flush(); [Array]::Clear($bytes, 0, $bytes.Length)
    Start-Sleep -Seconds 6
    $mid = Show-Procs 'held session started'
    $heldSd = @($mid | Where-Object { $_.Name -eq 'sd-solo.exe' })
    if ($heldSd.Count -lt 1) { Check '203' 'a session is held open before the stop' $false 'no sd-solo.exe of this tree after 6 s' }
    else {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $null = Invoke-Sd 'stop' '-stop' '' 'nothing'
        $gone = $false
        while ($sw.Elapsed.TotalSeconds -lt 25) { if (@(Get-SoloProcs | Where-Object { $_.Name -eq 'sd-solo.exe' }).Count -eq 0) { $gone = $true; break }; Start-Sleep -Milliseconds 500 }
        Say ('  every sd-solo.exe of this tree gone: ' + $gone + ' (' + [int]$sw.Elapsed.TotalSeconds + ' s after "-stop" began)')
        $null = Show-Procs 'after the stop'
        Check '203' 'the held session ended within 25 s of sd-solo -stop, and no sd-solo.exe of this tree survives' $gone ('still running: ' + ((Get-SoloProcs | ForEach-Object { $_.Name + '(' + $_.ProcessId + ')' }) -join ' '))
        Check '203' 'sdwind.exe of this tree is gone too' (@(Get-SoloProcs | Where-Object { $_.Name -eq 'sdwind.exe' }).Count -eq 0) 'sdwind still running'
    }
    try { $hp.StandardInput.Close() } catch { }
    if (-not $hp.WaitForExit(10000)) { Say ('  the held cmd.exe (pid ' + $hp.Id + ') has not ended; left alone') }
    if (Test-Path -LiteralPath $held) { Say '    --- the held session said ---'; foreach ($l in ((Mask ([IO.File]::ReadAllText($held) -replace "`r", '')) -split "`n")) { if ($l.Trim()) { Say ('    | ' + (($l -replace [char]27, '^[') -replace [char]7, '^G')) } } }
    $null = Invoke-Sd 'start' '-start' '' 'nothing'
    Start-Sleep -Seconds 3
    $null = Show-Procs 'after -start'
    $t = Invoke-Session 'after-start' @('WHERE')
    Check '203' 'SD answers again after -start (a session lands in the account)' ((CountOf (Get-Lines $t) ('(?i)[\\/]user_accounts[\\/]' + $Acct + '$')) -ge 1) 'no WHERE line - start Solo again by signing out and in'
}
} finally {
    if ($script:oldInEnc) { try { [Console]::InputEncoding = $script:oldInEnc } catch { } }
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

Say ''
if ($script:leaked) { $script:fails += 'a password appeared in SD''s output (masked in this log)' }
Say ('=== ' + $script:passes + ' PASS, ' + $script:fails.Count + ' FAIL   (sections: ' + ($want -join ', ') + ')')
foreach ($f in $script:fails) { Say ('  FAILED: ' + $f) }
if ($script:passes -eq 0 -and $script:fails.Count -eq 0) { Say 'VERDICT: NOTHING MEASURED - no check ran'; Save-Log; exit 2 }
if ($script:fails.Count) { Say 'VERDICT: FAIL'; Save-Log; exit 1 }
Say 'VERDICT: PASS - every check in the chosen sections passed'
Save-Log
exit 0
