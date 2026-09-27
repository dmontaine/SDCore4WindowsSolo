# verify-solo.ps1 - SD Core Solo's suite, first version.  SOLO 9.
#
#   powershell -ExecutionPolicy Bypass -File <repo>\sdb_ai\sd64\gplbld\verify-solo.ps1
#
# Run straight after cycle.ps1, from an ORDINARY UNELEVATED PowerShell, against
# the INSTALLED tree (%USERPROFILE%\SDCoreSolo) and the daemon its scheduled task
# started.  It asks once, hidden, for the account password and the
# administrator password (and the global one in managed mode).  None is stored,
# logged or put on a command line: each goes only to sd's standard input, and
# any output that contains one fails the run.
#
# Exit 0 every leg passed, 1 a leg failed, 2 refused before measuring anything.
# The log: %LOCALAPPDATA%\SD-verify\verify-solo-<stamp>.log.
#
# THE LEGS, one per ruling (PROJECT_STATUS.md, "WHAT SD CORE SOLO IS"):
#   1. a one-shot "sd WHERE" logs in from the DPAPI-kept password ($STORED) and
#      is audited via=stored                                  (ruling 21, piece 4)
#   2. an interactive "sd" asks for the account password: a wrong one is refused
#      and audited, the right one lands in the account                (ruling 21)
#   3. the account and grant commands are not in the account's VOC    (ruling 6)
#   4. the administrator gate, in one session: before ADMIN an admin verb
#      (UPDATE.ACCOUNTS) and a direct VOC write (COPY into VOC) are refused; a
#      wrong administrator password is refused; the right one unlocks; then both
#      go through; ADMIN OFF locks again.  The VOC record it makes is deleted in
#      the same session and checked gone afterwards.    (rulings 12 and 14)
#   5. the API (when sd.conf has APIPORT): a TLS 1.3 + SCRAM login with the
#      account password is VERIFIED and serves WHERE; a wrong one is REFUSED;
#      managed mode only, the global password also logs in.    (rulings 18, 19)
#   6. managed mode only: the global password at an interactive "sd" lands with
#      the administrator commands already unlocked                 (ruling 19)
#   7. the daemon runs on a standard token: Medium integrity, Administrators
#      deny-only or absent                                         (ruling 16)
# Not measured here, because they need hands or another machine: ssh landing in
# sd, SD starting at boot with nobody signed in, remote access while signed out.
#
# HOW sd IS DRIVEN, and why - each is a trap already paid for:
#   * natively, through cmd.exe, output to a FILE: sdwind would hold a pipe open
#     for ever (PROJECT_STATUS.md 6, "sd -start looks like it hangs");
#   * stdin written as ASCII bytes after setting a preamble-free
#     [Console]::InputEncoding: .NET writes the encoding's byte-order mark at
#     process start otherwise, and SD reads it as part of the password;
#   * every prompt answered and every interactive session ending in OFF: an
#     unanswered prompt is the "echo WHO | sd" hang (PROJECT_STATUS.md 6);
#   * a session that outlives 90 s is killed with its tree and FAILS the run.
# Every check anchors on the success wording SD prints and fails on the
# refusal wording too (CLAUDE.md).  Where the audit file records the outcome,
# it is counted before and after as a second reading.

$ErrorActionPreference = 'Stop'

$Gplbld  = $PSScriptRoot
$Root    = Join-Path $env:USERPROFILE 'SDCoreSolo'
$SdExe   = Join-Path $Root 'usr\bin\sd.exe'
$WindExe = Join-Path $Root 'usr\bin\sdwind.exe'
$Sdsys   = Join-Path $Root 'sdsys'
$CredDir = Join-Path $Sdsys '$cred'
$Audit   = Join-Path $Sdsys 'audit'
$Conf    = Join-Path $Root 'sd.conf'
$Scram   = Join-Path $Gplbld 'scram-probe.py'
$Acct    = "$env:USERNAME".Trim().ToLower()
$Probe   = 'ZZSOLOSUITE.COPY'

$LogDir  = Join-Path $env:LOCALAPPDATA 'SD-verify'
if (-not (Test-Path -LiteralPath $LogDir)) { $null = New-Item -ItemType Directory -Force -Path $LogDir }
$LogFile = Join-Path $LogDir ('verify-solo-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$Work    = Join-Path $env:TEMP ('sd-verify-solo-' + $PID)

$script:log      = New-Object System.Collections.ArrayList
$script:fails    = @()
$script:skips    = @()
$script:timeouts = 0
$script:leaked   = $false
$script:n        = 0
$script:secrets  = @()

function Say([string]$s) { Write-Host $s; [void]$script:log.Add($s) }
function Save-Log {
    try { [IO.File]::WriteAllLines($LogFile, [string[]]$script:log.ToArray(), (New-Object Text.UTF8Encoding($false))) } catch { }
}
function Check([string]$Label, [bool]$Ok, [string]$Why) {
    if ($Ok) { Say ('  PASS  ' + $Label) }
    else { Say ('  FAIL  ' + $Label + '   (' + $Why + ')'); $script:fails += $Label }
}
function Skip([string]$Label, [string]$Why) {
    Say ('  SKIP  ' + $Label + '   (' + $Why + ')'); $script:skips += $Label
}
function Refuse([string]$Why) {
    Say ('REFUSED: ' + $Why)
    Say 'VERDICT: REFUSED - nothing was measured'
    Save-Log
    exit 2
}
# The trimmed, non-empty lines.  The leading comma keeps a one-line result an
# array (the "return @($x) unrolls" trap).
function Get-Lines([string]$t) { return ,@($t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function First($L, [string]$Rx) { for ($i = 0; $i -lt $L.Count; $i++) { if ($L[$i] -match $Rx) { return $i } }; return -1 }
function CountOf($L, [string]$Rx) { return @($L | Where-Object { $_ -match $Rx }).Count }
function Audit-Count([string]$Rx) {
    if (-not (Test-Path -LiteralPath $Audit)) { return -1 }
    $fs = [IO.File]::Open($Audit, 'Open', 'Read', 'ReadWrite')
    try { $t = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() }
    return ([regex]::Matches($t, $Rx, 'IgnoreCase, Multiline')).Count
}
$LandsRx = '(?i)[\\/]user_accounts[\\/]' + [regex]::Escape($Acct) + '$'
function Lands([string]$t) { return ((CountOf (Get-Lines $t) $LandsRx) -gt 0) }

function Mask([string]$t) {
    foreach ($s in $script:secrets) {
        if ($s -and $t.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $script:leaked = $true
            $t = $t -replace [regex]::Escape($s), '********'
        }
    }
    return $t
}

# One sd session.  $InputShown describes the input for the log; the input
# itself is never printed.  Returns the output (passwords masked) and nothing
# else - everything shown goes through Say, which is Write-Host.
function Invoke-Sd([string]$Label, [string]$SdArgs, [string]$InputText, [string]$InputShown) {
    $script:n++
    $out = Join-Path $Work ('{0:d2}-{1}.txt' -f $script:n, $Label)
    Say ''
    Say ('  $ ' + $SdExe + ' ' + $SdArgs + '   [input: ' + $InputShown + ']')
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c ""' + $SdExe + '" ' + $SdArgs + ' >"' + $out + '" 2>&1"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $Work
    $p = [Diagnostics.Process]::Start($psi)
    $pre = $p.StandardInput.Encoding.GetPreamble().Length
    if ($pre -ne 0) {
        Say ('    REFUSED TO SEND: the stdin writer (' + $p.StandardInput.Encoding.WebName + ') writes a ' + $pre + '-byte preamble')
        $InputText = ''
    }
    if ($InputText) {
        $bytes = [Text.Encoding]::ASCII.GetBytes($InputText)
        $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $p.StandardInput.BaseStream.Flush()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(90000)) {
        $null = & taskkill.exe /PID $p.Id /T /F 2>$null
        $script:timeouts++
        Say '    TIMED OUT after 90 s - killed with its tree.  A killed session can leave its user-table slot behind.'
    }
    else { Say ('    exit ' + $p.ExitCode) }
    $text = ''
    if (Test-Path -LiteralPath $out) {
        $fs = [IO.File]::Open($out, 'Open', 'Read', 'ReadWrite')
        try { $text = (New-Object IO.StreamReader($fs, [Text.Encoding]::GetEncoding(28591))).ReadToEnd() } finally { $fs.Close() }
    }
    $text = Mask ($text -replace "`r", '')
    foreach ($l in ($text -split "`n")) { if ($l.Trim()) { Say ('    | ' + $l) } }
    return $text
}

# One scram-probe.py run: the real wire, TLS 1.3 + SCRAM.  The password goes in
# the CHILD's environment only.
function Invoke-Scram([string]$Label, [string]$Pw, [string[]]$Cmds) {
    Say ''
    Say ('  $ ' + $script:Py + ' -3 ' + $Scram + ' --user ' + $Acct + ' --account ' + $Acct + ' -- ' + ($Cmds -join ' ') + '   [SD_SCRAM_PASSWORD: ' + $Label + ', not shown]')
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $script:Py
    $psi.Arguments = '-3 "' + $Scram + '" --user ' + $Acct + ' --account ' + $Acct + ' -- ' + ($Cmds -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['SD_SCRAM_PASSWORD'] = $Pw
    $psi.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
    $p = [Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(90000)) {
        $null = & taskkill.exe /PID $p.Id /T /F 2>$null
        $script:timeouts++
        Say '    TIMED OUT after 90 s - killed.'
    }
    else { Say ('    exit ' + $p.ExitCode) }
    $text = Mask ((($o.Result) + ($e.Result)) -replace "`r", '')
    foreach ($l in ($text -split "`n")) { if ($l.Trim()) { Say ('    | ' + $l) } }
    return $text
}

function Read-Password([string]$Prompt) {
    $ss = Read-Host -AsSecureString $Prompt
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function Printable([string]$s) {
    if (-not $s) { return $false }
    foreach ($c in $s.ToCharArray()) { if ([int]$c -lt 33 -or [int]$c -gt 126) { return $false } }
    return $true
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SdSuiteTok {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr t, int c, IntPtr b, int l, out int r);
    [DllImport("advapi32.dll", SetLastError=true, EntryPoint="ConvertSidToStringSidW")] static extern bool ConvertSidToStringSid(IntPtr s, out IntPtr str);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
    static string Sid(IntPtr s) { IntPtr p; ConvertSidToStringSid(s, out p); string r = Marshal.PtrToStringUni(p); LocalFree(p); return r; }
    public static string Read(int pid) {
        IntPtr h = OpenProcess(0x1000, false, pid); if (h == IntPtr.Zero) return "OpenProcess failed " + Marshal.GetLastWin32Error();
        IntPtr t; if (!OpenProcessToken(h, 0x8, out t)) { CloseHandle(h); return "OpenProcessToken failed " + Marshal.GetLastWin32Error(); }
        string res = "";
        int n; IntPtr b = Marshal.AllocHGlobal(8192);
        if (GetTokenInformation(t, 25, b, 8192, out n)) res += "integrity=" + Sid(Marshal.ReadIntPtr(b)); else res += "integrity=?";
        if (GetTokenInformation(t, 2, b, 8192, out n)) {
            int count = Marshal.ReadInt32(b); int sz = IntPtr.Size * 2; string adm = "absent";
            for (int i = 0; i < count; i++) {
                IntPtr e = b + IntPtr.Size + i * sz;
                if (Sid(Marshal.ReadIntPtr(e)) == "S-1-5-32-544") {
                    int attr = Marshal.ReadInt32(e + IntPtr.Size);
                    adm = ((attr & 0x10) != 0 ? "deny-only" : ((attr & 0x4) != 0 ? "ENABLED" : "present-not-enabled")) + " (0x" + attr.ToString("x") + ")";
                }
            }
            res += " administrators=" + adm;
        }
        Marshal.FreeHGlobal(b); CloseHandle(t); CloseHandle(h); return res;
    }
}
'@

# ---------------------------------------------------------------------------
# 0. WHAT IS BEING MEASURED, AND THE NULL CASES REFUSED BEFORE ANYTHING RUNS

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$managed  = Test-Path -LiteralPath (Join-Path $CredDir '$GLOBAL')
$stored   = Test-Path -LiteralPath (Join-Path $CredDir '$STORED')
$apiPort  = ''
if (Test-Path -LiteralPath $Conf) {
    $m = Select-String -LiteralPath $Conf -Pattern '^\s*APIPORT\s*=\s*(\d+)' | Select-Object -First 1
    if ($m) { $apiPort = $m.Matches[0].Groups[1].Value }
}
$pyCmd = Get-Command py.exe -ErrorAction SilentlyContinue
$script:Py = $(if ($pyCmd) { $pyCmd.Source } else { '' })
$winds = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $WindExe })

Say ('=== verify-solo ' + (Get-Date -Format s))
Say ('script      : ' + $PSCommandPath)
Say ('Solo tree   : ' + $Root)
Say ('sd.exe      : ' + $SdExe + '   exists: ' + (Test-Path -LiteralPath $SdExe) + $(if (Test-Path -LiteralPath $SdExe) { '   written ' + (Get-Item -LiteralPath $SdExe).LastWriteTime } else { '' }))
Say ('account     : ' + $Acct)
Say ('mode        : ' + $(if ($managed) { 'managed (b) - $GLOBAL present' } else { 'standalone (a) - no $GLOBAL' }))
Say ('$STORED     : ' + $(if ($stored) { 'present' } else { 'ABSENT' }))
Say ('API         : ' + $(if ($apiPort) { 'APIPORT=' + $apiPort + ' in ' + $Conf } else { 'no APIPORT in ' + $Conf }))
Say ('py          : ' + $(if ($script:Py) { $script:Py } else { 'NOT FOUND' }) + '   scram-probe: ' + $Scram + '   exists: ' + (Test-Path -LiteralPath $Scram))
Say ('sdwind      : ' + $(if ($winds.Count) { ($winds | ForEach-Object { 'pid ' + $_.Id + ' session ' + $_.SessionId }) -join '; ' } else { 'NONE from this tree' }))
Say ('elevated    : ' + $elevated)
Say ('log         : ' + $LogFile)

if ($elevated) { Refuse 'this window is ELEVATED.  Run it from an ordinary unelevated PowerShell: several legs mean something only there.' }
if (-not (Test-Path -LiteralPath $SdExe)) { Refuse ('no sd.exe at ' + $SdExe + ' - nothing is installed.') }
if (-not $Acct) { Refuse 'no user name.' }
if (-not (Test-Path -LiteralPath (Join-Path $Root ('user_accounts\' + $Acct)))) { Refuse ('no account folder user_accounts\' + $Acct + ' in the install.') }
if ($winds.Count -eq 0) { Refuse 'no sdwind.exe from this tree is running.  Start it with its task: Start-ScheduledTask -TaskName "SD Core Solo"' }

Say ''
Say '== assert-current'
$acOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Gplbld 'assert-current.ps1')
$acCode = $LASTEXITCODE
foreach ($l in @($acOut)) { Say ('    | ' + $l) }
Say ('    exit ' + $acCode)
if ($acCode -ne 0) { Refuse 'assert-current did not pass, so the install is not the source.  Run cycle.ps1 first.' }

Say ''
Say '== passwords (asked once, hidden; never stored, logged or put on a command line)'
$globalPw = ''
try {
    $acctPw  = Read-Password ('Account password for ' + $Acct)
    $adminPw = Read-Password 'Administrator password (ADMIN)'
    if ($managed) { $globalPw = Read-Password 'Global password (managed mode)' }
}
catch { Refuse ('the passwords could not be asked for (' + $_.Exception.Message + ').  Run it in a PowerShell window you can type into.') }
if (-not (Printable $acctPw))  { Refuse 'the account password is empty or has a character outside printable ASCII (the installer allows 33-126 only).' }
if (-not (Printable $adminPw)) { Refuse 'the administrator password is empty or has a character outside printable ASCII.' }
if ($managed -and -not (Printable $globalPw)) { Refuse 'the global password is empty or has a character outside printable ASCII.' }
do { $wrongPw = 'zz-Not-The-Password-' + (Get-Random -Minimum 100000 -Maximum 999999) } while ($wrongPw -eq $acctPw -or $wrongPw -eq $adminPw -or $wrongPw -eq $globalPw)
$script:secrets = @($acctPw, $adminPw, $globalPw, $wrongPw) | Where-Object { $_ }
Say ('  account ' + $acctPw.Length + ' characters, administrator ' + $adminPw.Length + $(if ($managed) { ', global ' + $globalPw.Length } else { '' }) + '; the wrong one is generated')

$oldInEnc = [Console]::InputEncoding
New-Item -ItemType Directory -Force -Path $Work | Out-Null
try {
    # A preamble-free input encoding BEFORE any sd starts (the BOM trap).
    try { [Console]::InputEncoding = New-Object Text.ASCIIEncoding } catch { }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 1. a one-shot command logs in from the kept password ($STORED)'
    $rx = '^.*LOGIN PASSWORD account=' + [regex]::Escape($Acct) + ' via=stored\s*$'
    $a0 = Audit-Count $rx
    $t = Invoke-Sd 'oneshot-where' 'WHERE' '' 'none'
    $a1 = Audit-Count $rx
    Say ('    audit "via=stored" lines: ' + $a0 + ' -> ' + $a1)
    Check 'sd WHERE lands in the account with nothing on its input' ((Lands $t) -and ($t -notmatch '(?i)wrong password') -and ($t -notmatch '(?i)needs the account password')) ('want a line ending user_accounts\' + $Acct + '; $STORED ' + $(if ($stored) { 'present' } else { 'ABSENT' }))
    Check 'and the audit says via=stored, once' ($a0 -ge 0 -and $a1 -eq $a0 + 1) ('audit count ' + $a0 + ' -> ' + $a1)

    # -----------------------------------------------------------------------
    Say ''
    Say '== 2. an interactive sd asks for the account password'
    $rx = '^.*LOGIN REFUSED account=' + [regex]::Escape($Acct) + ' - wrong or missing password\s*$'
    $a0 = Audit-Count $rx
    $t = Invoke-Sd 'interactive-wrong' '' ($wrongPw + "`nOFF`n") 'a wrong password, OFF'
    $a1 = Audit-Count $rx
    Say ('    audit "LOGIN REFUSED" lines: ' + $a0 + ' -> ' + $a1)
    Check 'a wrong password is refused' (((CountOf (Get-Lines $t) '^Wrong password$') -ge 1) -and -not (Lands $t)) 'want a "Wrong password" line and no account line'
    Check 'and the refusal is audited, once' ($a0 -ge 0 -and $a1 -eq $a0 + 1) ('audit count ' + $a0 + ' -> ' + $a1)
    $t = Invoke-Sd 'interactive-right' '' ($acctPw + "`nWHERE`nOFF`n") 'the account password, WHERE, OFF'
    Check 'the account password lands in the account' ((Lands $t) -and ($t -notmatch '(?i)wrong password')) ('want a line ending user_accounts\' + $Acct + ', no "Wrong password"')

    # -----------------------------------------------------------------------
    Say ''
    Say '== 3. the account and grant commands are not there'
    foreach ($v in @('CREATE.ACCOUNT', 'DELETE.ACCOUNT', 'MODIFY.ACCOUNT', 'GRANT', 'LIST.GRANTS')) {
        $t = Invoke-Sd ('absent-' + $v) $v '' 'none'
        Check ($v + ' is not in the VOC') ((CountOf (Get-Lines $t) ('(?i)^' + [regex]::Escape($v) + ' is not in your VOC$')) -eq 1) ('want "' + $v + ' is not in your VOC"')
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 4. the administrator gate (ADMIN), in one session'
    $t = Invoke-Sd 'probe-absent-before' ('CT VOC ' + $Probe) '' 'none'
    $clean = (CountOf (Get-Lines $t) ("(?i)^Record '" + [regex]::Escape($Probe) + "' not found$")) -eq 1
    Check ('no ' + $Probe + ' in the VOC before the leg') $clean ('it is there, left by an earlier run: ADMIN, then DELETE VOC ' + $Probe)
    if ($clean) {
        $rxBad = '^.*ADMIN REFUSED reason=wrong password\s*$'
        $rxOk  = '^.*ADMIN UNLOCKED via=admin\s*$'
        $b0 = Audit-Count $rxBad; $u0 = Audit-Count $rxOk
        $copy = 'COPY FROM VOC TO VOC WHERE,' + $Probe
        $in = @($acctPw, 'WHERE', 'UPDATE.ACCOUNTS', $copy, 'ADMIN', $wrongPw, 'ADMIN', $adminPw,
                $copy, ('DELETE VOC ' + $Probe), 'UPDATE.ACCOUNTS', 'ADMIN OFF', 'OFF') -join "`n"
        $t = Invoke-Sd 'admin-gate' '' ($in + "`n") ('account password, WHERE, UPDATE.ACCOUNTS, ' + $copy + ', ADMIN + a wrong administrator password, ADMIN + the administrator password, ' + $copy + ', DELETE VOC ' + $Probe + ', UPDATE.ACCOUNTS, ADMIN OFF, OFF')
        $b1 = Audit-Count $rxBad; $u1 = Audit-Count $rxOk
        $L = Get-Lines $t
        $i2001   = First $L '^Command requires administrator privileges$'
        $i12008  = First $L '^The VOC can only be changed after ADMIN'
        $i12005  = First $L '^Wrong password - administrator commands stay locked$'
        $i12003  = First $L '^Administrator commands unlocked for this session$'
        $iCopied = First $L '^1 record\(s\) copied\.?$'
        $iDel    = First $L '^1 record\(s\) deleted$'
        $i5200   = First $L '^Copying records from NEWVOC to VOC'
        $i12004  = First $L '^Administrator commands locked$'
        Say ('    line of each answer: 2001=' + $i2001 + ' 12008=' + $i12008 + ' 12005=' + $i12005 + ' 12003=' + $i12003 + ' copied=' + $iCopied + ' deleted=' + $iDel + ' 5200=' + $i5200 + ' 12004=' + $i12004)
        Say ('    audit: ADMIN REFUSED ' + $b0 + ' -> ' + $b1 + ', ADMIN UNLOCKED ' + $u0 + ' -> ' + $u1)
        Check 'the session landed in the account' ((Lands $t) -and ((CountOf $L '^Wrong password$') -eq 0)) 'want the account line, no login refusal'
        Check 'before ADMIN, UPDATE.ACCOUNTS is refused' ((CountOf $L '^Command requires administrator privileges$') -eq 1 -and $i2001 -ge 0 -and $i2001 -lt $i12003) 'want one "Command requires administrator privileges", before the unlock'
        Check 'before ADMIN, a COPY into the VOC is refused' ((CountOf $L '^The VOC can only be changed after ADMIN') -eq 1 -and $i12008 -ge 0 -and $i12008 -lt $i12003) 'want one "The VOC can only be changed after ADMIN", before the unlock'
        Check 'a wrong administrator password is refused' ((CountOf $L '^Wrong password - administrator commands stay locked$') -eq 1 -and $i12005 -ge 0 -and $i12005 -lt $i12003 -and $b1 -eq $b0 + 1) 'want one 12005 before the unlock, and one new "ADMIN REFUSED" audit line'
        Check 'the administrator password unlocks' ((CountOf $L '^Administrator commands unlocked for this session$') -eq 1 -and $u1 -eq $u0 + 1) 'want one 12003 and one new "ADMIN UNLOCKED via=admin" audit line'
        Check 'after ADMIN, the COPY into the VOC goes through' ((CountOf $L '^1 record\(s\) copied\.?$') -eq 1 -and $iCopied -gt $i12003) 'want one "1 record(s) copied." after the unlock'
        Check 'and the copied record is deleted again' ($iDel -gt $iCopied) 'want "1 record(s) deleted" after the copy'
        Check 'after ADMIN, UPDATE.ACCOUNTS runs' ((CountOf $L '^Copying records from NEWVOC to VOC') -eq 1 -and $i5200 -gt $i12003) 'want one "Copying records from NEWVOC to VOC..." after the unlock'
        Check 'ADMIN OFF locks again' ($i12004 -gt $i5200) 'want "Administrator commands locked" last'
        $t = Invoke-Sd 'probe-absent-after' ('CT VOC ' + $Probe) '' 'none'
        Check ($Probe + ' is gone from the VOC afterwards') ((CountOf (Get-Lines $t) ("(?i)^Record '" + [regex]::Escape($Probe) + "' not found$")) -eq 1) ('it is still there: ADMIN, then DELETE VOC ' + $Probe)
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 5. the API: TLS 1.3 + SCRAM'
    if (-not $apiPort) {
        Skip 'the API legs' 'sd.conf has no APIPORT - the API was not ticked at install'
    }
    elseif (-not $script:Py -or -not (Test-Path -LiteralPath $Scram)) {
        Check 'the API legs could run' $false 'py.exe or scram-probe.py not found'
    }
    else {
        $t = Invoke-Scram 'the account password' $acctPw @('WHO', 'WHERE')
        Check 'an API login with the account password is VERIFIED' (($t -match '(?i)SCRAM: server signature VERIFIED') -and ($t -notmatch '(?i)REFUSED')) 'want "SCRAM: server signature VERIFIED", no REFUSED'
        Check 'and it serves WHERE' ((CountOf (Get-Lines $t) ('(?i)[\\/]user_accounts[\\/]' + [regex]::Escape($Acct) + '$')) -ge 1) ('want a WHERE line ending user_accounts/' + $Acct)
        $t = Invoke-Scram 'a wrong password' $wrongPw @('WHO')
        Check 'a wrong API password is REFUSED' (($t -match '(?i)SCRAM: login REFUSED at request') -and ($t -notmatch '(?i)VERIFIED')) 'want "SCRAM: login REFUSED at request ...", no VERIFIED'
        if ($managed) {
            $t = Invoke-Scram 'the global password' $globalPw @('WHO')
            Check 'an API login with the global password is VERIFIED' (($t -match '(?i)SCRAM: server signature VERIFIED') -and ($t -notmatch '(?i)REFUSED')) 'want VERIFIED'
        }
        else { Skip 'the API with the global password' 'standalone mode has no global password' }
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 6. the global password at an interactive sd (managed mode)'
    if ($managed) {
        $t = Invoke-Sd 'interactive-global' '' ($globalPw + "`nWHERE`nADMIN`nOFF`n") 'the global password, WHERE, ADMIN, OFF'
        Check 'the global password lands in the account' ((Lands $t) -and ((CountOf (Get-Lines $t) '^Wrong password$') -eq 0)) 'want the account line, no "Wrong password"'
        Check 'with the administrator commands already unlocked' ((CountOf (Get-Lines $t) '^Administrator commands are already unlocked') -eq 1) 'want ADMIN to say they are already unlocked (12006)'
    }
    else { Skip 'the global password at a console' 'standalone mode has no global password' }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 7. the daemon runs on a standard token'
    $winds = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $WindExe })
    Say ('    sdwind.exe from this tree: ' + $winds.Count)
    Check 'the daemon is still running after the legs' ($winds.Count -ge 1) 'no sdwind.exe from this tree'
    foreach ($w in $winds) {
        $r = [SdSuiteTok]::Read($w.Id)
        Say ('    pid ' + $w.Id + ' session ' + $w.SessionId + ': ' + $r)
        Check ('sdwind pid ' + $w.Id + ' is Medium integrity, Administrators not enabled') (($r -match 'integrity=S-1-16-8192(\s|$)') -and ($r -match 'administrators=(deny-only|absent)')) ('read: ' + $r)
    }
}
catch {
    Say ('ERROR: ' + $_.Exception.Message + '   at line ' + $_.InvocationInfo.ScriptLineNumber)
    $script:fails += 'exception'
}
finally {
    try { [Console]::InputEncoding = $oldInEnc } catch { }
    $acctPw = $null; $adminPw = $null; $globalPw = $null; $script:secrets = @()
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

Say ''
if ($script:leaked) { $script:fails += 'a password appeared in the output (masked above)' }
if ($script:timeouts) { $script:fails += ('' + $script:timeouts + ' session(s) timed out') }
if ($script:skips.Count) { Say ('skipped, not measured: ' + ($script:skips -join '; ')) }
if ($script:fails.Count -eq 0) {
    Say 'VERDICT: PASS - every leg that applies passed'
    Save-Log
    exit 0
}
Say ('VERDICT: FAIL - ' + ($script:fails -join '; '))
Save-Log
exit 1
