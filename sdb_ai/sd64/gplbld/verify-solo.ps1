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
#   7. BASIC's intrinsic functions and operators give the right answers:
#      gplbld/basicfuncs.sb (185 cases) compiled and run in the account's own
#      bp as ZZBASICFUNCS, then removed; its coverage of BCOMP's intrinsics
#      table checked first.  Ported from the multi-user verify-basicfuncs.ps1
#      (git show 3776c66:sdb_ai/sd64/gplbld/verify-basicfuncs.ps1).
#   8. record ids are case insensitive (RELEASE_1.1 5 D2): a probe in the
#      account's bp reads FL$NOCASE (FILEINFO 1008) = 1 on BP and on VOC, with
#      FL$TYPE 4 and 3 as the control that the values are per file, and
#      SYSTEM(91) = 1; then READs VOC's WHERE by 'where' and 'WhErE' (both
#      found - a hashed file finds a mixed-case id only if case is folded
#      before hashing) and a missing id (not found - the control that READ
#      can fail).  Ported from verify-nocase.ps1 (git show 3776c66:...).
#   9. "Suppress pagination" at a query's page prompt behaves like NO.PAGE
#      (RELEASE_1.1 28): at TERM 80,12, LIST ONLY VOC NO.PAGE is the control
#      (one heading, no prompt); LIST ONLY VOC answered S at its first prompt
#      must list the same count with no clear-screen and no heading after the
#      prompt.  Ported from verify-pagesuppress.ps1 (git show 3776c66:...).
#  10. ENTER at a prompt with a default takes the default (RELEASE_1.1 6, 27,
#      33), each with a control proving the prompt was live: a lower-case name
#      deletes an upper-case file with no prompt (D2) and the reverse (27);
#      DELETE.FILE 6135/6140 through a second VOC pointer; CATALOG 3033/3034;
#      CPROC's .D 5040; the select-list 2050 before CT; DELETE.FILE 6133 on a
#      multifile (Enter and C cancel, N deletes the dictionary only).  It makes
#      and removes ZZPROMPT* files, a catalogue entry and VOC records in the
#      account, and checks every one gone.  Ported from verify-promptenter.ps1
#      (git show 3776c66:...); its sessions add ADMIN only for COPY into VOC
#      and DELETE VOC, the two gated writes (ruling 14).
#  11. the daemon runs on a standard token: Medium integrity, Administrators
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
    if ($script:oldInEnc) { try { [Console]::InputEncoding = $script:oldInEnc } catch { } }
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
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
    # ESC shown as ^[ - printed raw, a session's clear-screen clears this console.
    foreach ($l in ($text -split "`n")) { if ($l.Trim()) { Say ('    | ' + ($l -replace [char]27, '^[')) } }
    return $text
}

# One interactive session for leg 10: the account password, ADMIN + the
# administrator password when a step writes the VOC directly (COPY into VOC,
# DELETE VOC - ruling 14), TERM 200,9999 so nothing pages, the commands, OFF.
# An empty command is Enter at a prompt, shown as <Enter>.
function Invoke-Pe([string]$Label, [string[]]$Cmds, [switch]$Admin) {
    $lines = @($acctPw); $shown = @('account password')
    if ($Admin) { $lines += @('ADMIN', $adminPw); $shown += @('ADMIN', 'administrator password') }
    $lines += @('TERM 200,9999') + $Cmds + @('OFF')
    $shown += @('TERM 200,9999') + @($Cmds | ForEach-Object { if ($_ -eq '') { '<Enter>' } else { $_ } }) + @('OFF')
    return (Invoke-Sd $Label '' (($lines -join "`n") + "`n") ($shown -join ', '))
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

# basicfuncs.sb's coverage of BCOMP's intrinsics table, read from source: every
# intrinsic is either exercised (a case label n = '<name>' or '<name>.<x>') or
# declared on a "* NOT.TESTED:" line, never both, never neither.  Verbatim from
# the multi-user verify-basicfuncs.ps1.
function Get-CoverageVerdict([string]$bcompText, [string]$probeText) {
    $known = @()
    foreach ($m in [regex]::Matches($bcompText, '(?m)^\s*intrinsics(?:<-1>)?\s*=\s*"([^"]+)"')) { $known += $m.Groups[1].Value }
    $knownSet = @{}
    foreach ($k in $known) { $knownSet[$k] = $true }
    $codeLines = @(); $declared = @(); $declaredUnknown = @()
    foreach ($line in ($probeText -split "`r?`n")) {
        if ($line -match '^\s*\*') {
            $d = [regex]::Match($line, '^\s*\*\s*NOT\.TESTED:\s*(.+)$')
            if ($d.Success) {
                foreach ($tok in ($d.Groups[1].Value -split '\s+')) {
                    if ($tok -eq '') { continue }
                    if ($knownSet.ContainsKey($tok)) { $declared += $tok } else { $declaredUnknown += $tok }
                }
            }
            continue
        }
        $codeLines += $line
    }
    $declaredSet = @{}
    foreach ($d in $declared) { $declaredSet[$d] = $true }
    $exercisedSet = @{}; $operatorLabels = @(); $strayLabels = @()
    foreach ($m in [regex]::Matches(($codeLines -join "`n"), "n\s*=\s*'([^']+)'")) {
        $lab = $m.Groups[1].Value; $best = ''
        foreach ($k in $knownSet.psbase.Keys) {
            if ($lab -eq $k -or $lab.StartsWith($k + '.')) { if ($k.Length -gt $best.Length) { $best = $k } }
        }
        if ($best -ne '') { $exercisedSet[$best] = $true }
        elseif ($lab.StartsWith('OP.')) { $operatorLabels += $lab }
        else { $strayLabels += $lab }
    }
    $both = @(); $unaccounted = @()
    foreach ($k in $known) {
        $e = $exercisedSet.ContainsKey($k); $d = $declaredSet.ContainsKey($k)
        if ($e -and $d) { $both += $k }
        if (-not $e -and -not $d) { $unaccounted += $k }
    }
    return @{ Known = $known.Count; Exercised = $exercisedSet.psbase.Count; Declared = $declaredSet.psbase.Count
              Both = @($both | Sort-Object); Unaccounted = @($unaccounted | Sort-Object)
              DeclaredUnknown = @($declaredUnknown); OperatorLabels = $operatorLabels.Count
              StrayLabels = @($strayLabels | Sort-Object) }
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

$script:oldInEnc = [Console]::InputEncoding
New-Item -ItemType Directory -Force -Path $Work | Out-Null
# A preamble-free input encoding BEFORE any sd starts (the BOM trap).
try { [Console]::InputEncoding = New-Object Text.ASCIIEncoding } catch { }

# THE ACCOUNT PASSWORD IS CHECKED ONCE BEFORE ANY LEG USES IT.  27 Sep 2026: a
# mistyped one failed legs 2, 4 and 5 - twelve rows - while $STORED (leg 1)
# still logged in, so the product was fine and the run said nothing about it.
# Refused, it is asked again (3 tries), then the run REFUSES (exit 2) with the
# session shown: a mistyped password and a broken login look the same from
# here, and the output is how to tell them apart.
Say ''
Say '== the account password, checked before any leg'
$pwOk = $false
for ($try = 1; $try -le 3; $try++) {
    $t = Invoke-Sd ('password-check-' + $try) '' ($acctPw + "`nWHERE`nOFF`n") 'the account password, WHERE, OFF'
    if (Lands $t) { $pwOk = $true; Say '    accepted'; break }
    if ($try -eq 3) { break }
    Say ('    refused (try ' + $try + ' of 3) - asking again')
    try { $acctPw = Read-Password ('Account password for ' + $Acct + ' - try ' + ($try + 1) + ' of 3') } catch { break }
    if (-not (Printable $acctPw)) { break }
    $script:secrets = @($script:secrets + $acctPw) | Where-Object { $_ }
}
if (-not $pwOk) { Refuse 'the account password was refused (the session is shown above) - mistyped, or login is broken.  Nothing else was measured.' }

try {

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
    Say '== 7. BASIC''s intrinsic functions and operators give the right answers'
    $bfSrc   = Join-Path $Gplbld 'basicfuncs.sb'
    $bcomp   = Join-Path $Gplbld '..\sdsys\gpl.bp\bcomp'
    $bpDir   = Join-Path $Root ('user_accounts\' + $Acct + '\bp')
    $outDir  = Join-Path $Root ('user_accounts\' + $Acct + '\bp.out')
    $bfName  = 'ZZBASICFUNCS'
    $bfDest  = Join-Path $bpDir $bfName
    Say ('    probe ' + $bfSrc + '   exists: ' + (Test-Path -LiteralPath $bfSrc))
    Say ('    BCOMP ' + $bcomp + '   exists: ' + (Test-Path -LiteralPath $bcomp))
    Say ('    into  ' + $bfDest + '   bp exists: ' + (Test-Path -LiteralPath $bpDir) + '   bp.out exists before: ' + (Test-Path -LiteralPath $outDir))
    if (-not (Test-Path -LiteralPath $bfSrc) -or -not (Test-Path -LiteralPath $bcomp) -or -not (Test-Path -LiteralPath $bpDir)) {
        Check 'the BASIC leg could run' $false 'basicfuncs.sb, BCOMP source or the account bp is missing'
    }
    elseif (@(Get-ChildItem -LiteralPath $bpDir -File | Where-Object { $_.Name -ieq $bfName }).Count) {
        Check 'the BASIC leg could run' $false ($bfName + ' is already in bp - left by an earlier run?  Delete it and its bp.out object by hand.')
    }
    else {
        $cov = Get-CoverageVerdict (Get-Content -LiteralPath $bcomp -Raw) (Get-Content -LiteralPath $bfSrc -Raw)
        Say ('    coverage: BCOMP intrinsics ' + $cov.Known + ', exercised ' + $cov.Exercised + ', declared untested ' + $cov.Declared + ', operator cases ' + $cov.OperatorLabels)
        Check 'V1 BCOMP''s intrinsics table parsed' ($cov.Known -ge 100) ('found ' + $cov.Known + ' names, expected well over 100')
        Check 'V2 every intrinsic is exercised or declared untested' ($cov.Unaccounted.Count -eq 0) ('named nowhere: ' + ($cov.Unaccounted -join ', '))
        Check 'V3 none is both' ($cov.Both.Count -eq 0) ('both: ' + ($cov.Both -join ', '))
        Check 'V4 every declared name is one BCOMP knows' ($cov.DeclaredUnknown.Count -eq 0) ('unknown: ' + ($cov.DeclaredUnknown -join ', '))
        Check 'V5 every case label names an intrinsic or an OP. case' ($cov.StrayLabels.Count -eq 0) ('stray: ' + ($cov.StrayLabels -join ', '))
        $madeOut = -not (Test-Path -LiteralPath $outDir)
        try {
            Copy-Item -LiteralPath $bfSrc -Destination $bfDest -Force
            # BCOMP:1540's "0 error(s)" is the only success wording; the name is
            # printed on both paths (PRE_RELEASE 105).
            $t = Invoke-Sd 'basicfuncs-compile' ('BASIC BP ' + $bfName) '' 'none'
            $L = Get-Lines $t
            $compiled = ((CountOf $L '^0 error\(s\)') -ge 1) -and ((CountOf $L '^[1-9][0-9]* error') -eq 0) -and ($t -notmatch '(?i)Compilation error')
            Check 'the probe compiles' $compiled 'want "0 error(s)" and no error count or "Compilation error"'
            if ($compiled) {
                $t = Invoke-Sd 'basicfuncs-run' ('RUN BP ' + $bfName + ' NO.PAGE') '' 'none'
                $L = Get-Lines $t
                $tot = [regex]::Match($t, '(?m)^\s*TOTAL\|(\d+)\|FAILS\|(\d+)')
                $total = $(if ($tot.Success) { [int]$tot.Groups[1].Value } else { -1 })
                $nfail = $(if ($tot.Success) { [int]$tot.Groups[2].Value } else { -1 })
                $caseLines = CountOf $L '^(OK|FAIL)\|'
                $failLines = @($L | Where-Object { $_ -match '^FAIL\|' })
                Say ('    TOTAL ' + $total + '   FAILS ' + $nfail + '   case lines ' + $caseLines + '   FAIL lines ' + $failLines.Count + '   PROBE.DONE ' + ((CountOf $L '^PROBE\.DONE$') -eq 1))
                Check 'the probe ran to its end and measured something' (((CountOf $L '^PROBE\.DONE$') -eq 1) -and $total -gt 0) 'want PROBE.DONE and TOTAL above 0 - a probe that ran nothing must fail'
                Check 'the tally agrees with the case lines printed' ($caseLines -eq $total -and $failLines.Count -eq $nfail) ('TOTAL ' + $total + ' vs ' + $caseLines + ' lines; FAILS ' + $nfail + ' vs ' + $failLines.Count + ' lines')
                Check ('every case gives the right answer (' + $total + ' cases)') ($nfail -eq 0 -and $failLines.Count -eq 0) ('failing: ' + ($failLines -join ' ;; '))
            }
        }
        finally {
            $objs = @()
            if (Test-Path -LiteralPath $outDir) { $objs = @(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ieq $bfName }) }
            foreach ($f in (@(Get-Item -LiteralPath $bfDest -ErrorAction SilentlyContinue) + $objs)) {
                if ($f) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
            }
            # NEVER REMOVE bp.out, even one this leg made.  BASIC creates it WITH a
            # VOC F-record; deleting the folder alone leaves the pointer dangling,
            # and every later BASIC in the account then fails "DATA part of file
            # already exists / Unable to open newly created output file" (27 Sep
            # 2026: this leg did exactly that, and broke the next run's compiles).
            $leftS = @(Get-ChildItem -LiteralPath $bpDir -File | Where-Object { $_.Name -ieq $bfName }).Count
            $leftO = $(if (Test-Path -LiteralPath $outDir) { @(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ieq $bfName }).Count } else { 0 })
            Say ('    cleanup: source left ' + $leftS + ', object left ' + $leftO + ', bp.out ' + $(if (Test-Path -LiteralPath $outDir) { 'present' } else { 'absent' }) + $(if ($madeOut) { ' (this leg made it)' } else { ' (was there before)' }))
            Check 'the probe is removed from the account' ($leftS -eq 0 -and $leftO -eq 0) ('delete ' + $bfName + ' from bp and bp.out by hand')
        }
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 8. record ids are case insensitive'
    $ncName = 'ZZNOCASE'
    $ncDest = Join-Path $bpDir $ncName
    Say ('    into  ' + $ncDest + '   bp exists: ' + (Test-Path -LiteralPath $bpDir) + '   bp.out exists before: ' + (Test-Path -LiteralPath $outDir))
    if (-not (Test-Path -LiteralPath $bpDir)) {
        Check 'the NOCASE leg could run' $false 'the account bp is missing'
    }
    elseif (@(Get-ChildItem -LiteralPath $bpDir -File | Where-Object { $_.Name -ieq $ncName }).Count) {
        Check 'the NOCASE leg could run' $false ($ncName + ' is already in bp - left by an earlier run?  Delete it and its bp.out object by hand.')
    }
    else {
        # 1008 is FL$NOCASE and 3 FL$TYPE (SYSCOM KEYS.H), literal so the probe
        # needs no include path from a user account.
        $ncSrc = @(
            '* ZZNOCASE - written by gplbld/verify-solo.ps1, leg 8.  Safe to delete.'
            "      OPEN 'BP' TO F.DIR ELSE STOP 'cannot open BP'"
            "      OPEN 'VOC' TO F.DH ELSE STOP 'cannot open VOC'"
            "      CRT 'DIRFILE=':FILEINFO(F.DIR, 1008)"
            "      CRT 'DHFILE=':FILEINFO(F.DH, 1008)"
            "      CRT 'DIRTYPE=':FILEINFO(F.DIR, 3)"
            "      CRT 'DHTYPE=':FILEINFO(F.DH, 3)"
            "      CRT 'ISWIN=':SYSTEM(91)"
            "      READ R FROM F.DH, 'where' THEN CRT 'READ.LOWER=1' ELSE CRT 'READ.LOWER=0'"
            "      READ R FROM F.DH, 'WhErE' THEN CRT 'READ.MIXED=1' ELSE CRT 'READ.MIXED=0'"
            "      READ R FROM F.DH, 'zz.no.such.record' THEN CRT 'READ.MISSING=1' ELSE CRT 'READ.MISSING=0'"
            "      CRT 'NOCASE.DONE'"
            '   END'
        ) -join "`n"
        $madeOut = -not (Test-Path -LiteralPath $outDir)
        try {
            [IO.File]::WriteAllText($ncDest, $ncSrc + "`n", [Text.Encoding]::ASCII)
            $t = Invoke-Sd 'nocase-compile' ('BASIC BP ' + $ncName) '' 'none'
            $L = Get-Lines $t
            $compiled = ((CountOf $L '^0 error\(s\)') -ge 1) -and ((CountOf $L '^[1-9][0-9]* error') -eq 0) -and ($t -notmatch '(?i)Compilation error')
            Check 'the NOCASE probe compiles' $compiled 'want "0 error(s)" and no error count or "Compilation error"'
            if ($compiled) {
                $t = Invoke-Sd 'nocase-run' ('RUN BP ' + $ncName) '' 'none'
                $L = Get-Lines $t
                $v = @{}
                foreach ($k in @('DIRFILE', 'DHFILE', 'DIRTYPE', 'DHTYPE', 'ISWIN', 'READ.LOWER', 'READ.MIXED', 'READ.MISSING')) {
                    $m = @($L | Where-Object { $_ -match ('^' + [regex]::Escape($k) + '=(\d+)$') })
                    $v[$k] = $(if ($m.Count -eq 1) { ($m[0] -split '=')[1] } else { '(' + $m.Count + ' lines)' })
                }
                Say ('    read: ' + (($v.GetEnumerator() | Sort-Object Name | ForEach-Object { $_.Name + '=' + $_.Value }) -join '  '))
                Check 'the probe ran to its end' ((CountOf $L '^NOCASE\.DONE$') -eq 1) 'want NOCASE.DONE - a probe that stopped early measured nothing'
                Check 'BP (a directory file) is NOCASE' ($v['DIRFILE'] -eq '1') ('FILEINFO 1008 = ' + $v['DIRFILE'])
                Check 'VOC (a hashed file) is NOCASE' ($v['DHFILE'] -eq '1') ('FILEINFO 1008 = ' + $v['DHFILE'])
                Check 'CONTROL: the values are per file (FL$TYPE 4 for BP, 3 for VOC)' ($v['DIRTYPE'] -eq '4' -and $v['DHTYPE'] -eq '3') ('FL$TYPE ' + $v['DIRTYPE'] + ' and ' + $v['DHTYPE'])
                Check 'SYSTEM(91) answers Windows' ($v['ISWIN'] -eq '1') ('SYSTEM(91) = ' + $v['ISWIN'])
                Check 'VOC finds WHERE as ''where'' and as ''WhErE''' ($v['READ.LOWER'] -eq '1' -and $v['READ.MIXED'] -eq '1') ('lower ' + $v['READ.LOWER'] + ', mixed ' + $v['READ.MIXED'])
                Check 'CONTROL: a missing id is not found' ($v['READ.MISSING'] -eq '0') ('READ.MISSING = ' + $v['READ.MISSING'])
            }
        }
        finally {
            $objs = @()
            if (Test-Path -LiteralPath $outDir) { $objs = @(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ieq $ncName }) }
            foreach ($f in (@(Get-Item -LiteralPath $ncDest -ErrorAction SilentlyContinue) + $objs)) {
                if ($f) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
            }
            # bp.out stays - see leg 7's cleanup for why.
            $leftS = @(Get-ChildItem -LiteralPath $bpDir -File | Where-Object { $_.Name -ieq $ncName }).Count
            $leftO = $(if (Test-Path -LiteralPath $outDir) { @(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ieq $ncName }).Count } else { 0 })
            Say ('    cleanup: source left ' + $leftS + ', object left ' + $leftO + ', bp.out ' + $(if (Test-Path -LiteralPath $outDir) { 'present' } else { 'absent' }) + $(if ($madeOut) { ' (this leg made it)' } else { ' (was there before)' }))
            Check 'the NOCASE probe is removed from the account' ($leftS -eq 0 -and $leftO -eq 0) ('delete ' + $ncName + ' from bp and bp.out by hand')
        }
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 9. "Suppress pagination" at a page prompt behaves like NO.PAGE'
    # Decisive rows count only what follows the first prompt: the sign-on and a
    # paginated LIST's page 1 clear the screen whatever S does (measured
    # 13 Sep 2026).  A heading repeats the sentence; the gap before "Page" is
    # spaces only, so the echoed command line cannot match.
    $esc = [char]27
    $clear = "$esc[H$esc[J"
    $heading = 'LIST ONLY VOC(?: NO\.PAGE)? {2,}Page +\d+'
    $measure = {
        param([string]$t)
        $pi = $t.IndexOf('Action (')
        $tail = $(if ($pi -ge 0) { $t.Substring($pi) } else { '' })
        $m = [regex]::Match($t, '(\d+) record\(s\) listed')
        return @{ Clears = [regex]::Matches($t, [regex]::Escape($clear)).Count
                  ClearsAfter = [regex]::Matches($tail, [regex]::Escape($clear)).Count
                  Headings = [regex]::Matches($t, $heading).Count
                  HeadingsAfter = [regex]::Matches($tail, $heading).Count
                  Prompts = [regex]::Matches($t, [regex]::Escape('Action (')).Count
                  Listed = $(if ($m.Success) { [int]$m.Groups[1].Value } else { -1 }) }
    }
    $t = Invoke-Sd 'page-control' '' ($acctPw + "`nTERM 80,12`nLIST ONLY VOC NO.PAGE`nOFF`n") 'the account password, TERM 80,12, LIST ONLY VOC NO.PAGE, OFF'
    $a = & $measure $t
    Say ('    control: listed ' + $a.Listed + ', clear-screens ' + $a.Clears + ', headings ' + $a.Headings + ', prompts ' + $a.Prompts)
    $ctlOk = ($a.Listed -ge 40 -and $a.Prompts -eq 0)
    Check 'CONTROL: NO.PAGE listed a multi-page report without a prompt' $ctlOk ('listed ' + $a.Listed + ' (want 40 or more), prompts ' + $a.Prompts + ' (want 0)')
    if ($ctlOk) {
        # keycode() takes the S alone; the newline after it reaches TCL as an
        # empty command, which is harmless.
        $t = Invoke-Sd 'page-suppress' '' ($acctPw + "`nTERM 80,12`nLIST ONLY VOC`nS`nOFF`n") 'the account password, TERM 80,12, LIST ONLY VOC, S, OFF'
        $b = & $measure $t
        Say ('    S leg  : listed ' + $b.Listed + ', clear-screens ' + $b.Clears + ' (' + $b.ClearsAfter + ' after the prompt), headings ' + $b.Headings + ' (' + $b.HeadingsAfter + ' after), prompts ' + $b.Prompts)
        Check 'the page prompt was reached exactly once' ($b.Prompts -eq 1) ('' + $b.Prompts + ' prompt(s): 0 means S was never offered, more than 1 means S did not stop the prompts')
        Check 'the S leg listed every record the control listed' ($b.Listed -eq $a.Listed) ('S leg ' + $b.Listed + ', control ' + $a.Listed)
        Check 'CONTROL: NO.PAGE draws the heading once' ($a.Headings -eq 1) ('NO.PAGE drew ' + $a.Headings)
        Check 'page 1 was drawn before the prompt' (($b.Headings - $b.HeadingsAfter) -eq 1) ('' + ($b.Headings - $b.HeadingsAfter) + ' heading(s) before the prompt')
        Check 'after S, no further page headings' ($b.HeadingsAfter -eq 0) ('' + $b.HeadingsAfter + ' after S')
        Check 'after S, no further clear-screens' ($b.ClearsAfter -eq 0) ('' + $b.ClearsAfter + ' after S - a terminal would show only the last page')
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 10. ENTER at a prompt takes its default'
    $acctDir = Join-Path $Root ('user_accounts\' + $Acct)
    $pE = 'ZZPROMPTE'; $pL = 'ZZPROMPTL'; $fD = 'zzpromptd'; $fX = 'zzpromptx'
    $pP = 'ZZPROMPTP'; $sV = 'zzpromptv'; $mM = 'zzpromptm'
    $to0 = $script:timeouts
    $who = '(?m)^\s*\d+\s+' + [regex]::Escape($Acct) + '\b'
    try {
        # --- leftovers of an earlier run (every name is this leg's own) -----
        $null = Invoke-Pe 'pe-left-1' @("DELETE.FILE $pE", 'Y', 'Y', 'Y')
        $null = Invoke-Pe 'pe-left-2' @("DELETE.FILE $($pL.ToLower())", 'Y', 'Y', 'Y')

        # --- a: a lower-case name deletes an upper-case file, no prompt (D2) --
        $t = Invoke-Pe 'pe-a-make' @('OPTION CREATE.FILE.UPCASE', "CREATE.FILE $pE")
        $upOk = ($t -match "Created DATA part as $pE") -and (@(Get-ChildItem -LiteralPath $acctDir -Directory | Where-Object { $_.Name -ceq $pE }).Count -eq 1)
        Check "a: setup - $pE made with its directory upper case" $upOk 'OPTION CREATE.FILE.UPCASE did not keep the case, so the leg cannot start from an upper-case record'
        if ($upOk) {
            $lo = $pE.ToLower()
            $t = Invoke-Pe 'pe-a-delete' @("DELETE.FILE $lo")
            Check 'a: no 6130 - found as typed' ($t -notmatch 'No VOC record found') 'DELETEF printed 6130'
            Check 'a: no 6131 prompt' ($t -notmatch 'Use file') 'DELETEF asked 6131 on a case-insensitive VOC'
            Check "a: VOC entry '$lo' deleted (6144, any case)" ($t -match "VOC entry '$lo' deleted") 'no 6144 success line'
            $t = Invoke-Pe 'pe-a-gone' @("CT VOC $lo")
            Check "a: $pE is gone - VOC and directory" (($t -match "Record '$lo' not found") -and -not (Test-Path -LiteralPath (Join-Path $acctDir $pE))) 'the VOC record or the directory survived'
        }

        # --- b: RELEASE_1.1 27, a lower-case id deleted by its upper name -----
        $loL = $pL.ToLower()
        $t = Invoke-Pe 'pe-b-make' @("CREATE.FILE $pL")
        $isLower = ($t -match "Created DATA part as $loL") -and (@(Get-ChildItem -LiteralPath $acctDir -Directory | Where-Object { $_.Name -ceq $loL }).Count -eq 1)
        Check "b: setup - $pL stored as $loL" $isLower 'no directory named exactly lower case, so the lower-case tier is not what is measured'
        if ($isLower) {
            $t = Invoke-Pe 'pe-b-delete' @("DELETE.FILE $pL")
            Check 'b: no 6130 - the lower-case tier found it' ($t -notmatch 'No VOC record found') 'DELETEF printed 6130'
            Check 'b: no 6131 prompt' ($t -notmatch 'Use file') 'DELETEF asked'
            Check "b: VOC entry '$loL' deleted (6144, any case)" ($t -match "VOC entry '$loL' deleted") 'no 6144 success line'
            $t = Invoke-Pe 'pe-b-gone' @("CT VOC $loL")
            Check 'b: the VOC record is gone' ($t -match "Record '$loL' not found") "CT VOC $loL still finds it"
        }

        # --- c: DELETE.FILE 6135 + 6140 through a second VOC pointer -------------
        $dDir = Join-Path $acctDir $fD; $dDic = Join-Path $acctDir ($fD + '.DIC')
        $null = Invoke-Pe 'pe-c-left-1' @("DELETE VOC $fX") -Admin
        $null = Invoke-Pe 'pe-c-left-2' @("DELETE.FILE $fD", 'Y', 'Y', 'Y')
        $t = Invoke-Pe 'pe-c-make' @("CREATE.FILE $fD", "COPY FROM VOC $fD,$fX", "CT VOC $fX") -Admin
        $ptrOk = ($t -match '1 record\(s\) copied') -and ($t -cmatch "(?m)^\s*2: $fD\s*$")
        Check "c: setup - $fX is a VOC pointer to $fD" $ptrOk 'COPY did not make the pointer, so DELETEF would not ask'
        if ($ptrOk) {
            $t = Invoke-Pe 'pe-c-enter' @("DELETE.FILE $fX", '', '')
            Check 'c: the transcript is a sane size' ($t.Length -lt 200000) ('' + $t.Length + ' bytes')
            Check 'c: prompt 6135 reached, showing (y/<n>)' ($t -match "OK to delete DATA portion '$fD' \(y/<n>\)\?") 'no 6135 prompt'
            Check 'c: prompt 6140 reached, showing (y/<n>)' ($t -match "OK to delete DICT portion '$fD\.DIC' \(y/<n>\)\?") 'no 6140 prompt'
            Check 'c: ENTER at both deleted nothing' (($t -notmatch "portion '[^']*' deleted") -and ($t -notmatch "VOC entry '[^']*' deleted")) 'a deletion was reported - Enter taken as YES'
            Check 'c: both portions survive on disk' ((Test-Path -LiteralPath $dDir) -and (Test-Path -LiteralPath $dDic)) 'a portion is gone after Enter'
            $t = Invoke-Pe 'pe-c-yes' @("DELETE.FILE $fX", 'Y', 'Y')
            Check "c: CONTROL - Y deletes DATA portion '$fD'" ($t -match "DATA portion '$fD' deleted") 'no 6136'
            Check "c: CONTROL - Y deletes DICT portion '$fD.DIC'" ($t -match "DICT portion '$fD\.DIC' deleted") 'no 6141'
            Check 'c: CONTROL - both portions are gone from disk' (-not (Test-Path -LiteralPath $dDir) -and -not (Test-Path -LiteralPath $dDic)) 'a portion survived an explicit Y'
        }

        # --- d: CATALOG 3033 + 3034 ------------------------------------------
        $catRec = Join-Path (Join-Path $acctDir 'cat') $pP
        [IO.File]::WriteAllText((Join-Path $bpDir $pP), ("* $pP - written by verify-solo.ps1 leg 10.  Safe to delete.`n   crt '$pP-RAN'`nend`n"), [Text.Encoding]::ASCII)
        $t = Invoke-Pe 'pe-d-make' @("BASIC BP $pP", "CATALOG BP $pP LOCAL", "CT VOC $pP")
        $localOk = ($t -match "$pP added to local catalogue") -and ($t -cmatch '(?m)^\s*2: CS\s*$')
        Check "d: setup - $pP compiled and in the LOCAL catalogue (V / CS)" $localOk 'not locally catalogued, so 3033 could not be reached'
        if ($localOk) {
            $t = Invoke-Pe 'pe-d-3033-enter' @("CATALOG BP $pP", '', "CT VOC $pP")
            Check 'd: prompt 3033 reached, showing (y/<n>)' ($t -match 'Program is also in local catalogue\. Remove \(y/<n>\)\?') 'no 3033 prompt'
            Check 'd: ENTER at 3033 kept the LOCAL entry' ($t -cmatch '(?m)^\s*2: CS\s*$') 'the V/CS record is gone after Enter'
            Check 'd: and the private entry was written' (Test-Path -LiteralPath $catRec) ('no ' + $catRec + ', so 3034 could not be reached')
            $t = Invoke-Pe 'pe-d-3034-enter' @("CATALOG BP $pP LOCAL", '')
            Check 'd: prompt 3034 reached, showing (y/<n>)' ($t -match 'Program is also in private catalogue\. Remove \(y/<n>\)\?') 'no 3034 prompt'
            Check 'd: ENTER at 3034 kept the private entry' (Test-Path -LiteralPath $catRec) 'the private record is gone after Enter'
            $t = Invoke-Pe 'pe-d-3034-yes' @("CATALOG BP $pP LOCAL", 'Y')
            Check 'd: CONTROL - Y at 3034 removes the private entry' (($t -match 'Program is also in private catalogue') -and -not (Test-Path -LiteralPath $catRec)) 'it survived an explicit Y, or no prompt'
            $t = Invoke-Pe 'pe-d-3033-yes' @("CATALOG BP $pP", 'Y', "CT VOC $pP")
            Check 'd: CONTROL - Y at 3033 removes the LOCAL entry' (($t -match 'Program is also in local catalogue') -and ($t -match "Record '$pP' not found")) 'it survived an explicit Y, or no prompt'
        }

        # --- e: CPROC's .D prompt 5040 -----------------------------------------
        $null = Invoke-Pe 'pe-e-left' @("DELETE VOC $sV") -Admin
        $sRx = '(?m)^[ \t]*001[ \t]+S[ \t]*$'
        $t = Invoke-Pe 'pe-e-make' @(".S $sV 1", ".L $sV")
        $sentOk = $t -match $sRx
        Check "e: setup - .S wrote $sV as an S-type record" $sentOk 'no "001  S" line, so .D would never ask 5040'
        if ($sentOk) {
            $t = Invoke-Pe 'pe-e-enter' @(".D $sV", '', ".L $sV")
            Check 'e: the transcript is a sane size' ($t.Length -lt 200000) ('' + $t.Length + ' bytes')
            Check 'e: prompt 5040 reached, showing (y/<n>)' ($t -match "Delete VOC record '$sV' \(y/<n>\)\?") 'no 5040 prompt'
            Check 'e: ENTER kept the sentence' (($t -match $sRx) -and ($t -notmatch "'$sV' not found in VOC")) 'gone after Enter - taken as YES'
            $t = Invoke-Pe 'pe-e-yes' @(".D $sV", 'Y', ".L $sV")
            Check 'e: CONTROL - Y deleted the sentence' (($t -match "Delete VOC record '$sV'") -and ($t -match "'$sV' not found in VOC")) '.L still lists it after an explicit Y, or no prompt'
        }

        # --- f: the select-list prompt 2050, then CT ---------------------------
        $t = Invoke-Pe 'pe-f-enter' @('SSELECT VOC SAMPLE 1', 'CT VOC', '', 'WHO')
        $first = [regex]::Match($t, "First item '([^']+)'")
        Check 'f: prompt 2050 reached, showing (y/<n>)' ($t -match "Use active select list \(First item '[^']+'\) \(y/<n>\)\?") 'no 2050 prompt carrying (y/<n>)'
        if ($first.Success) {
            $id = $first.Groups[1].Value
            Check "f: ENTER displayed nothing (no 'VOC $id')" ($t -notmatch ('(?m)^VOC ' + [regex]::Escape($id) + '\s*$')) 'the record was displayed - Enter taken as YES'
            Check 'f: the session went on to WHO' ($t -match $who) 'WHO did not answer - the prompt swallowed it'
            $t = Invoke-Pe 'pe-f-yes' @('SSELECT VOC SAMPLE 1', 'CT VOC', 'Y')
            Check "f: CONTROL - Y displays 'VOC $id'" ($t -match ('(?m)^VOC ' + [regex]::Escape($id) + '\s*$')) 'Y did not display it'
        }

        # --- g: DELETE.FILE 6133 on a multifile --------------------------------
        $mDir = Join-Path $acctDir $mM; $mDic = Join-Path $acctDir ($mM + '.DIC')
        $null = Invoke-Pe 'pe-g-left' @("DELETE.FILE $mM", 'Y', 'Y', 'Y')
        $t = Invoke-Pe 'pe-g-make' @("CREATE.FILE $($mM.ToUpper()),C1", "CREATE.FILE $($mM.ToUpper()),C2", "CT VOC $mM")
        $multiOk = ($t -match "Created DATA part as $mM/c2") -and (Test-Path -LiteralPath (Join-Path $mDir 'c1')) -and (Test-Path -LiteralPath (Join-Path $mDir 'c2')) -and (Test-Path -LiteralPath $mDic)
        Check "g: setup - $mM is a multifile (c1, c2) with a dictionary" $multiOk 'not built, so 6133 could not be reached'
        if ($multiOk) {
            foreach ($ans in @(@{ Label = 'ENTER'; Line = '' }, @{ Label = 'C'; Line = 'C' })) {
                $t = Invoke-Pe ('pe-g-' + $ans.Label) @("DELETE.FILE $mM", $ans.Line, 'WHO')
                Check ('g (' + $ans.Label + '): prompt 6133 reached, showing (y/n/<c>)') ($t -match 'Delete all data components of multifile.*\(y/n/<c>\)\?') 'no 6133 prompt'
                Check ('g (' + $ans.Label + '): nothing was deleted') (($t -notmatch "portion '[^']*' deleted") -and ($t -notmatch "VOC entry '[^']*' deleted")) 'cancel did not cancel'
                Check ('g (' + $ans.Label + '): c1, c2 and the dictionary survive') ((Test-Path -LiteralPath (Join-Path $mDir 'c1')) -and (Test-Path -LiteralPath (Join-Path $mDir 'c2')) -and (Test-Path -LiteralPath $mDic)) 'a part is gone'
                Check ('g (' + $ans.Label + '): the session went on to WHO') ($t -match $who) 'WHO did not answer'
            }
            $t = Invoke-Pe 'pe-g-no' @("DELETE.FILE $mM", 'N')
            Check "g: CONTROL - N deletes the dictionary only" (($t -match "DICT portion '$mM\.DIC' deleted") -and -not (Test-Path -LiteralPath $mDic) -and (Test-Path -LiteralPath (Join-Path $mDir 'c1'))) 'N did not delete exactly the dictionary'
        }
    }
    finally {
        # VOC RECORDS FIRST, THEN ANY FOLDER - the other order leaves a dangling
        # pointer (PROJECT_STATUS.md 6, the bp.out trap).  Every answer given.
        $null = Invoke-Pe 'pe-clean-1' @("DELETE.FILE $pE", 'Y', 'Y', 'Y')
        $null = Invoke-Pe 'pe-clean-2' @("DELETE.FILE $($pL.ToLower())", 'Y', 'Y', 'Y')
        $null = Invoke-Pe 'pe-clean-3' @("DELETE.FILE $fD", 'Y', 'Y', 'Y')
        $null = Invoke-Pe 'pe-clean-4' @("DELETE.FILE $mM", 'Y', 'Y', 'Y')
        $null = Invoke-Pe 'pe-clean-5' @("DELETE.CATALOG $pP")
        $names = @($fX, $fD, $pP, $sV, $mM, $pE.ToLower(), $pL.ToLower())
        $null = Invoke-Pe 'pe-clean-voc' @($names | ForEach-Object { "DELETE VOC $_" }) -Admin
        $t = Invoke-Pe 'pe-clean-check' @($names | ForEach-Object { "CT VOC $_" })
        foreach ($n in $names) { Check ("cleanup: no VOC record '" + $n + "' left") ($t -match "Record '$n' not found") ('CT VOC ' + $n + ' still finds it') }
        foreach ($p in @($fD, ($fD + '.DIC'), $mM, ($mM + '.DIC'), $pE, ($pE + '.DIC'), $pL.ToLower(), ($pL.ToLower() + '.DIC'))) {
            $q = Join-Path $acctDir $p
            if ((Test-Path -LiteralPath $q) -and ($t -match "Record '$([regex]::Escape($p -replace '\.DIC$',''))' not found")) { Remove-Item -LiteralPath $q -Recurse -Force -ErrorAction SilentlyContinue }
        }
        foreach ($q in @((Join-Path $bpDir $pP), (Join-Path $outDir $pP), $catRec)) {
            if ($q -and (Test-Path -LiteralPath $q)) { Remove-Item -LiteralPath $q -Force -ErrorAction SilentlyContinue }
        }
        $left = @(@((Join-Path $acctDir $fD), (Join-Path $acctDir ($fD + '.DIC')), (Join-Path $acctDir $mM), (Join-Path $acctDir ($mM + '.DIC')),
                    (Join-Path $acctDir $pE), (Join-Path $acctDir $pL.ToLower()), (Join-Path (Join-Path $acctDir 'cat') $pP),
                    (Join-Path $bpDir $pP), (Join-Path $outDir $pP)) | Where-Object { Test-Path -LiteralPath $_ })
        Check 'cleanup: no ZZPROMPT file, folder, catalogue record or source left' ($left.Count -eq 0) ($left -join ', ')
        Check 'no leg-10 session timed out' ($script:timeouts -eq $to0) ('' + ($script:timeouts - $to0) + ' timed out - a prompt re-asked for ever')
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 11. the daemon runs on a standard token'
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
    try { [Console]::InputEncoding = $script:oldInEnc } catch { }
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
