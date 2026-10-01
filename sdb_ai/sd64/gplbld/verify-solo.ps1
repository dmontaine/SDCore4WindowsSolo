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
#      (git show 3776c66:...); its sessions add ADMIN only for COPY into VOC,
#      DELETE VOC and .S/.D name, the gated writes (rulings 14, 27) - and e
#      checks .S and .D name are refused without it (12008).
#  11. SD-to-SD over the API from BASIC: a probe in the account's bp creates
#      the !sdclient class (gpl.bp/sdclient, TLS 1.3 + SCRAM) and connects to
#      this machine's own API as the account - EXECUTE WHERE lands in the
#      account, OPEN VOC and READ WHERE find a verb, a missing id is not
#      found, DISCONNECT leaves it unconnected; CONTROL: the wrong password
#      does not connect.  Both passwords reach the probe on its input, never
#      its source.  Skipped when sd.conf has no APIPORT.
#  12. the installed sdclilib.dll, loaded by full path, finds its home: its
#      SDConnectLocal reaches the server and gets the ruled refusal (12021),
#      audited once                                          (SOLO 2 owed leg 1)
#  13. an sd.exe started from Git Bash (or MSYS2) bash, whose POSIX root and
#      /dev/shm are not the Solo tree's, reaches the daemon: a one-shot WHERE
#      lands, audited via=stored.  Skipped with no bash.   (SOLO 2 owed leg 2)
#  14. end of input ends a session with no OFF: at the command prompt and at
#      PAUSE, no timeout, few BELs                        (ruling 28, SOLO 16)
#  15. no system BASIC source installed: no sdsys\gpl.bp, no VOC record for
#      it; gpl.bp.out full as the control                          (ruling 26)
#  16. the global catalogue is the SD Core server's: with ADMIN, sduser is
#      refused CATALOG GLOBAL, DELETE.CATALOG *x, SYNC.GLOBAL.CATALOG and a
#      COPY into GLOBAL.BP.OUT; managed mode, a global-password session adds a
#      program, sduser CALLs it, and the session removes it   (ruling 33)
#  17. the administrator-only verbs and the deny list: without ADMIN the eight
#      maintenance verbs are refused (CONFIG GPL/CONTRIB are not - SOLO 21);
#      DENY.VERBS is refused even with ADMIN;
#      managed, the server denies WHO, sduser is refused it without ADMIN,
#      and the server allows it again; denying SH denies ! too (SOLO 22)
#                                                (rulings 34, 35, 36)
#  18. who changes which password: SET.PASSWORD's refusals (usage, a wrong
#      current password, ADMIN without ADMIN, GLOBAL from a non-global
#      session); the account password changed without ADMIN, the
#      administrator password with ADMIN, the global one by a global session
#      - each to a temporary one, proved, and put back; the API still
#      verifies afterwards                                          (ruling 39)
#  19. the daemon runs on a standard token: Medium integrity, Administrators
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
# 28 Sep 26 - RULING 29: the account is always sduser.  It was the Windows
# user's name ($env:USERNAME), which is still recorded as $WinUser: ssh's
# Match User and the scheduled task are the Windows user's, not the account's.
$Acct    = 'sduser'
$WinUser = "$env:USERNAME".Trim().ToLower()
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
# The session counter.  Named so no loop variable can take it: at script scope
# "foreach ($n ...)" IS $script:n, and leg 10's cleanup once left it a string.
$script:sessionNo = 0
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
function Invoke-Sd([string]$Label, [string]$SdArgs, [string]$InputText, [string]$InputShown, [switch]$NoSpareOff) {
    $script:sessionNo++
    $out = Join-Path $Work ('{0:d2}-{1}.txt' -f $script:sessionNo, $Label)
    Say ''
    Say ('  $ ' + $SdExe + ' ' + $SdArgs + '   [input: ' + $InputShown + ']')
    # SPARE OFFs ON EVERY INTERACTIVE SESSION.  SOLO 16: at end of piped input
    # CPROC's command editor rings the bell in a tight loop instead of ending
    # (27 Sep 2026: an unexpected ADMIN prompt ate the one OFF; 4.9 million BEL
    # in 90 s).  Unread once the session has ended, so they cost nothing.
    # 28 Sep 26 - -NoSpareOff is for leg 14 alone, which measures the fix
    # (ruling 28): its input deliberately ends with no OFF.
    if ($NoSpareOff) { Say '    (NO spare OFF - this session measures end of input)' }
    elseif ($SdArgs -eq '' -and $InputText) { $InputText += "OFF`nOFF`n"; Say '    (+2 spare OFF lines on the input - SOLO 16)' }
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
    # A line over 2,000 characters is shown cut, with its length and BEL count:
    # a runaway session once put a 4.9 MB line of BELs in the log (SOLO 16).
    foreach ($l in ($text -split "`n")) {
        if (-not $l.Trim()) { continue }
        if ($l.Length -gt 2000) {
            $bel = ($l.Length - ($l -replace [char]7, '').Length)
            $l = $l.Substring(0, 200) + ' ...[CUT: ' + $l.Length + ' characters, ' + $bel + ' of them BEL]'
        }
        Say ('    | ' + (($l -replace [char]27, '^[') -replace [char]7, '^G'))
    }
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

# SOLO 24: one scram-probe.py run that sends request 49 once per spec, e.g.
# 'LIST' or 'ADD ssh-ed25519 AAAA...'.  No account is entered; request 49 needs none.
function Invoke-ScramKey([string]$Label, [string]$Pw, [string[]]$Specs) {
    $a = '-3 "' + $Scram + '" --user ' + $Acct
    foreach ($s in $Specs) { $a += ' --sshkey ' + $s }
    Say ''
    Say ('  $ ' + $script:Py + ' ' + $a + '   [SD_SCRAM_PASSWORD: ' + $Label + ', not shown]')
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $script:Py
    $psi.Arguments = $a
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
Say ('account     : ' + $Acct + '   (ruling 29; the Windows user is ' + $WinUser + ')')
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

# AND IN MANAGED MODE THE GLOBAL PASSWORD, THE SAME WAY.  27 Sep 2026: the
# ACCOUNT password typed at the global prompt LANDS (it is valid) but does not
# unlock ADMIN, so leg 6's ADMIN asked for the administrator password, ate the
# OFF, and the session spun at end of input (SOLO 16).  The dummy line after
# ADMIN is what a surprise prompt eats instead; unlocked, it runs as a harmless
# unknown command.
if ($managed) {
    Say ''
    Say '== the global password, checked before any leg (managed mode)'
    $gOk = $false
    for ($try = 1; $try -le 3; $try++) {
        $t = Invoke-Sd ('global-check-' + $try) '' ($globalPw + "`nADMIN`nzz-not-a-password`nOFF`n") 'the global password, ADMIN, a dummy line, OFF'
        if ((CountOf (Get-Lines $t) '^Administrator commands are already unlocked') -eq 1) { $gOk = $true; Say '    accepted - ADMIN already unlocked'; break }
        $why = $(if ($globalPw -ceq $acctPw) { 'that is the ACCOUNT password' } elseif (Lands $t) { 'it logged in but did not unlock ADMIN - is it the account password?' } else { 'it was refused' })
        Say ('    ' + $why + ' (try ' + $try + ' of 3)')
        if ($try -eq 3) { break }
        try { $globalPw = Read-Password ('Global password - try ' + ($try + 1) + ' of 3') } catch { break }
        if (-not (Printable $globalPw)) { break }
        $script:secrets = @($script:secrets + $globalPw) | Where-Object { $_ }
    }
    if (-not $gOk) { Refuse 'the global password did not unlock the administrator commands (the sessions are shown above).  Nothing else was measured.' }
}

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

    # 28 Sep 26 - RULING 29: the account and the session's user name are sduser,
    # not the Windows user.  WHO prints "<userno> <account>"; the folder listing
    # is the second reading.  Meaningful only where the Windows user is not
    # itself called sduser, which is said rather than assumed.
    Say ('    Windows user: ' + $WinUser + $(if ($WinUser -eq $Acct) { '   (THE SAME AS THE ACCOUNT - these two checks cannot tell the rulings apart here)' } else { '' }))
    $t = Invoke-Sd 'oneshot-who' 'WHO' '' 'none'
    Check 'ruling 29: WHO names the account sduser' ((CountOf (Get-Lines $t) ('^\d+\s+' + [regex]::Escape($Acct) + '\b')) -ge 1) 'want a WHO line "<n> sduser"'
    $uaDirs = @(Get-ChildItem -LiteralPath (Join-Path $Root 'user_accounts') -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Say ('    user_accounts: ' + ($uaDirs -join ', '))
    Check 'ruling 29: user_accounts holds sduser and nothing else' (($uaDirs.Count -eq 1) -and ($uaDirs[0] -eq $Acct)) ('found: ' + ($uaDirs -join ', '))

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
        # APPEND.SD.PATH (its bare, report-only form) is here for !ps_script_out
        # run WITH ADMIN UNLOCKED - the path that used to go to the elevated
        # helper, retired 27 Sep 2026.
        $in = @($acctPw, 'WHERE', 'UPDATE.ACCOUNTS', $copy, 'ADMIN', $wrongPw, 'ADMIN', $adminPw,
                $copy, ('DELETE VOC ' + $Probe), 'UPDATE.ACCOUNTS', 'APPEND.SD.PATH', 'ADMIN OFF', 'OFF') -join "`n"
        $t = Invoke-Sd 'admin-gate' '' ($in + "`n") ('account password, WHERE, UPDATE.ACCOUNTS, ' + $copy + ', ADMIN + a wrong administrator password, ADMIN + the administrator password, ' + $copy + ', DELETE VOC ' + $Probe + ', UPDATE.ACCOUNTS, APPEND.SD.PATH, ADMIN OFF, OFF')
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
        $iShow = First $L '^mode\s*:\s*-Show$'
        Check 'with ADMIN, a PowerShell-backed verb runs in the session (APPEND.SD.PATH report)' ($iShow -gt $i5200 -and $iShow -lt $i12004 -and ($t -notmatch 'Could not \w+ (the system|your) PATH') -and ($t -match 'HKCU\\Environment')) ('want sd-path''s "mode : -Show" line between UPDATE.ACCOUNTS and ADMIN OFF, its HKCU\Environment registry line (SOLO 17), and no 10153; line ' + $iShow)
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
        $t = Invoke-Sd 'interactive-global' '' ($globalPw + "`nWHERE`nADMIN`nzz-not-a-password`nOFF`n") 'the global password, WHERE, ADMIN, a dummy line, OFF'
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
        $vocGate = '(?m)^The VOC can only be changed after ADMIN'
        # 28 Sep 26 - RULING 27: .S name and .D name need ADMIN.  Without it .S
        # is refused with 12008 and writes nothing (.L then says not found).
        $t = Invoke-Pe 'pe-e-s-noadmin' @(".S $sV 1", ".L $sV")
        Check "e: without ADMIN, .S is refused (12008) and saves nothing" (($t -match $vocGate) -and ($t -match "'$sV' not found in VOC") -and ($t -notmatch $sRx)) 'want 12008 and .L "not found"'
        $t = Invoke-Pe 'pe-e-make' @(".S $sV 1", ".L $sV") -Admin
        $sentOk = $t -match $sRx
        Check "e: setup - with ADMIN, .S wrote $sV as an S-type record" $sentOk 'no "001  S" line, so .D would never ask 5040'
        if ($sentOk) {
            $t = Invoke-Pe 'pe-e-d-noadmin' @(".D $sV", ".L $sV")
            Check "e: without ADMIN, .D $sV is refused (12008), no 5040, and the sentence stays" (($t -match $vocGate) -and ($t -notmatch "Delete VOC record '$sV'") -and ($t -match $sRx)) 'want 12008, no 5040 prompt, and .L still listing it'
            $t = Invoke-Pe 'pe-e-enter' @(".D $sV", '', ".L $sV") -Admin
            Check 'e: the transcript is a sane size' ($t.Length -lt 200000) ('' + $t.Length + ' bytes')
            Check 'e: prompt 5040 reached, showing (y/<n>)' ($t -match "Delete VOC record '$sV' \(y/<n>\)\?") 'no 5040 prompt'
            Check 'e: ENTER kept the sentence' (($t -match $sRx) -and ($t -notmatch "'$sV' not found in VOC")) 'gone after Enter - taken as YES'
            $t = Invoke-Pe 'pe-e-yes' @(".D $sV", 'Y', ".L $sV") -Admin
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
        foreach ($vocName in $names) { Check ("cleanup: no VOC record '" + $vocName + "' left") ($t -match "Record '$vocName' not found") ('CT VOC ' + $vocName + ' still finds it') }
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
    Say '== 11. SD-to-SD over the API from BASIC (!sdclient)'
    $scName = 'ZZSDCLIENT'
    $scDest = Join-Path $bpDir $scName
    if (-not $apiPort) {
        Skip 'the !sdclient leg' 'sd.conf has no APIPORT - the API was not ticked at install'
    }
    elseif (@(Get-ChildItem -LiteralPath $bpDir -File | Where-Object { $_.Name -ieq $scName }).Count) {
        Check 'the !sdclient leg could run' $false ($scName + ' is already in bp - left by an earlier run?  Delete it and its bp.out object by hand.')
    }
    else {
        # Replies can carry marks and line ends; flattened to | so each value is one line.
        $scSrc = @(
            '* ZZSDCLIENT - written by gplbld/verify-solo.ps1, leg 11.  Safe to delete.'
            "      PROMPT ''"
            '      INPUT PW HIDDEN'
            '      INPUT BAD HIDDEN'
            "      ACCT = '$Acct'"
            '      C = OBJECT(''!sdclient'')'
            "      OK = C->CONNECT('127.0.0.1', $apiPort, ACCT, PW, ACCT)"
            "      CRT 'CONNECT.RIGHT=':OK"
            "      IF NOT(OK) THEN CRT 'CONNECT.RIGHT.ERROR=':C->ERROR"
            '      IF OK THEN'
            "         S = C->EXECUTE('WHERE', ERR)"
            "         CRT 'EXEC.ERR=':ERR"
            "         CRT 'EXEC.OUT=':CONVERT(@FM:@VM:CHAR(13):CHAR(10), '||||', S)"
            "         F = C->OPEN('VOC')"
            "         CRT 'OPEN.FNO=':F"
            "         R = C->READ(F, 'WHERE', ERR)"
            "         CRT 'READ.ERR=':ERR"
            "         CRT 'READ.F1=':R<1>"
            "         R = C->READ(F, 'zz.no.such.record', ERR)"
            "         CRT 'READ.MISSING.ERR=':ERR"
            '         C->DISCONNECT'
            "         CRT 'CONNECTED.AFTER=':C->CONNECTED()"
            '      END'
            '      D = OBJECT(''!sdclient'')'
            "      OK2 = D->CONNECT('127.0.0.1', $apiPort, ACCT, BAD, ACCT)"
            "      CRT 'CONNECT.WRONG=':OK2"
            "      CRT 'SDCLIENT.DONE'"
            '   END'
        ) -join "`n"
        try {
            [IO.File]::WriteAllText($scDest, $scSrc + "`n", [Text.Encoding]::ASCII)
            $t = Invoke-Sd 'sdclient-compile' ('BASIC BP ' + $scName) '' 'none'
            $L = Get-Lines $t
            $compiled = ((CountOf $L '^0 error\(s\)') -ge 1) -and ((CountOf $L '^[1-9][0-9]* error') -eq 0) -and ($t -notmatch '(?i)Compilation error')
            Check 'the !sdclient probe compiles' $compiled 'want "0 error(s)" and no error count or "Compilation error"'
            if ($compiled) {
                $t = Invoke-Sd 'sdclient-run' ('RUN BP ' + $scName) ($acctPw + "`n" + $wrongPw + "`n") 'the account password, a wrong password'
                $L = Get-Lines $t
                $v = @{}
                foreach ($k in @('CONNECT.RIGHT', 'CONNECT.RIGHT.ERROR', 'EXEC.ERR', 'EXEC.OUT', 'OPEN.FNO', 'READ.ERR', 'READ.F1', 'READ.MISSING.ERR', 'CONNECTED.AFTER', 'CONNECT.WRONG')) {
                    $m = @($L | Where-Object { $_.StartsWith($k + '=') })
                    $v[$k] = $(if ($m.Count -eq 1) { $m[0].Substring($k.Length + 1) } elseif ($m.Count -eq 0) { '(none)' } else { '(' + $m.Count + ' lines)' })
                }
                Say ('    read: ' + (($v.GetEnumerator() | Sort-Object Name | ForEach-Object { $_.Name + '=' + $_.Value }) -join '  '))
                Check 'the probe ran to its end' ((CountOf $L '^SDCLIENT\.DONE$') -eq 1) 'want SDCLIENT.DONE'
                Check 'connect() with the account password succeeds' ($v['CONNECT.RIGHT'] -eq '1') ('CONNECT.RIGHT=' + $v['CONNECT.RIGHT'] + '  error: ' + $v['CONNECT.RIGHT.ERROR'])
                Check 'execute(WHERE) answers from the account' ($v['EXEC.ERR'] -eq '0' -and $v['EXEC.OUT'] -match ('(?i)user_accounts[\\/]' + [regex]::Escape($Acct) + '(\||$)')) ('EXEC.ERR=' + $v['EXEC.ERR'] + '  EXEC.OUT=' + $v['EXEC.OUT'])
                Check 'open(VOC) gives a file number' ($v['OPEN.FNO'] -match '^[1-9][0-9]*$') ('OPEN.FNO=' + $v['OPEN.FNO'])
                # WHERE is a SENTENCE, not a verb (27 Sep 2026: this row assumed V
                # and failed on a correct read).  So the expected field 1 is read
                # from the installed NEWVOC the account's VOC was built from.
                $shipped = Join-Path $Sdsys 'newvoc\where'
                $want = $(if (Test-Path -LiteralPath $shipped) { ([IO.File]::ReadAllText($shipped) -split "[\r\n\xFE]")[0] } else { '(no ' + $shipped + ')' })
                Check 'read(VOC, WHERE) returns the shipped record' ($v['READ.ERR'] -eq '0' -and $v['READ.F1'] -ceq $want) ('READ.ERR=' + $v['READ.ERR'] + '  field 1 read "' + $v['READ.F1'] + '", shipped "' + $want + '"')
                Check 'CONTROL: read of a missing id is not found' ($v['READ.MISSING.ERR'] -match '^[1-9][0-9]*$') ('READ.MISSING.ERR=' + $v['READ.MISSING.ERR'])
                Check 'disconnect() leaves it unconnected' ($v['CONNECTED.AFTER'] -eq '0') ('CONNECTED.AFTER=' + $v['CONNECTED.AFTER'])
                Check 'CONTROL: connect() with a wrong password fails' ($v['CONNECT.WRONG'] -eq '0') ('CONNECT.WRONG=' + $v['CONNECT.WRONG'])
            }
        }
        finally {
            $objs = @()
            if (Test-Path -LiteralPath $outDir) { $objs = @(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ieq $scName }) }
            foreach ($f in (@(Get-Item -LiteralPath $scDest -ErrorAction SilentlyContinue) + $objs)) {
                if ($f) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
            }
            # bp.out stays - see leg 7's cleanup for why.
            $leftS = @(Get-ChildItem -LiteralPath $bpDir -File | Where-Object { $_.Name -ieq $scName }).Count
            $leftO = $(if (Test-Path -LiteralPath $outDir) { @(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ieq $scName }).Count } else { 0 })
            Say ('    cleanup: source left ' + $leftS + ', object left ' + $leftO)
            Check 'the !sdclient probe is removed from the account' ($leftS -eq 0 -and $leftO -eq 0) ('delete ' + $scName + ' from bp and bp.out by hand')
        }
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 12. the installed client DLL finds its own home'
    # SOLO 2's owed leg (1), witnessed by hand 27 Sep 2026.  sdclilib.dll takes
    # the home from its own location, <home>\usr\bin (home_path()); its only
    # caller is sysdir(), reached only through SDConnectLocal, which Solo refuses
    # on the server (message 12021, apisrvr vb.local.login).  So the REFUSAL is
    # the success anchor: its text is not in the DLL and comes back only if the
    # DLL found <home>\sd.conf and sd.exe and the session started.  Loaded by
    # FULL PATH, and the loaded module is checked, so no other copy can answer.
    $cliDll = Join-Path $Root 'usr\bin\sdclilib.dll'
    Say ('    DLL: ' + $cliDll + '   exists: ' + (Test-Path -LiteralPath $cliDll) + '   SD_CONFIG: ''' + $env:SD_CONFIG + '''')
    if (-not (Test-Path -LiteralPath $cliDll)) { Check 'sdclilib.dll is installed beside sd.exe' $false ('no ' + $cliDll) }
    elseif ($env:SD_CONFIG) { Skip 'the client DLL finds its home' 'SD_CONFIG is set, so the DLL reads it instead of its home' }
    else {
        $dllEsc = $cliDll.Replace([string][char]92, [string][char]92 + [string][char]92)
        Add-Type -TypeDefinition (@'
using System;
using System.Runtime.InteropServices;
public static class SdSuiteCli {
  [DllImport("DLLPATH", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)]
  public static extern int SDConnectLocal(string account);
  [DllImport("DLLPATH", CallingConvention=CallingConvention.Cdecl)]
  public static extern IntPtr SDError();
  [DllImport("DLLPATH", CallingConvention=CallingConvention.Cdecl)]
  public static extern void SDDisconnectAll();
}
'@).Replace('DLLPATH', $dllEsc)
        $rx = '^.*API REFUSED request=25 SDConnectLocal'
        $a0 = Audit-Count $rx
        Say ('  $ [SdSuiteCli]::SDConnectLocal(''' + $Acct + ''')   (DllImport of the path above)')
        $rc  = [SdSuiteCli]::SDConnectLocal($Acct)
        $err = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([SdSuiteCli]::SDError())
        if ($rc -ne 0) { [SdSuiteCli]::SDDisconnectAll() }
        $a1 = Audit-Count $rx
        $mod = @((Get-Process -Id $PID).Modules | Where-Object { $_.ModuleName -eq 'sdclilib.dll' } | ForEach-Object { $_.FileName })
        Say ('    loaded: ' + $(if ($mod.Count) { $mod -join '; ' } else { 'NONE' }))
        Say ('    returned ' + $rc + '; SDError: ' + (Mask $err))
        Say ('    audit "API REFUSED request=25" lines: ' + $a0 + ' -> ' + $a1)
        Check 'the loaded sdclilib.dll is the installed one' ($mod.Count -eq 1 -and $mod[0] -eq $cliDll) ('loaded: ' + ($mod -join '; '))
        Check 'SDConnectLocal reaches the server and is refused as ruled (12021)' ($rc -eq 0 -and $err -match '^SDConnectLocal is not available in SD Core Solo for Windows - connect with SDConnect' -and $err -notmatch '(?i)cannot determine|not found') ('returned ' + $rc + ', SDError: ' + $err)
        Check 'and the audit records the refusal, once' ($a0 -ge 0 -and $a1 -eq $a0 + 1) ('audit count ' + $a0 + ' -> ' + $a1)
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 13. an sd started from Git Bash reaches the daemon'
    # SOLO 2's owed leg (2), witnessed by hand 27 Sep 2026.  An sd.exe inherits
    # its MSYS parent's POSIX root, and /dev/shm with it (measured 25 Sep: "SD
    # has not been started" with SD running); inipath.c SdShmOpen now opens the
    # segment by path under the home.  CONTROL: the parent's root must not be
    # the Solo tree and its /dev/shm must hold no SD segment, or this could pass
    # on the old behaviour.  Named paths only - System32's bash.exe is WSL's.
    $bash = @('C:\Program Files\Git\usr\bin\bash.exe', 'C:\msys64\usr\bin\bash.exe') | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $bash) { Skip 'an sd started from Git Bash reaches the daemon' 'neither Git for Windows nor MSYS2 bash.exe is installed' }
    else {
        $gbScript = Join-Path $Work 'gitbash-where.sh'
        $gbOut    = Join-Path $Work 'gitbash-bash.txt'
        $gbSdOut  = Join-Path $Work 'gitbash-sd.txt'
        # --noprofile leaves PATH as Windows' own, without /usr/bin, so cygpath
        # is not found (27 Sep 2026: root="" - which the control refused).
        $sh = @(
            'export PATH="/usr/bin:$PATH"'
            'echo "root=$(cygpath -w /)"'
            'echo "shm=$(cygpath -w /dev/shm)"'
            'for f in /dev/shm/*; do [ -e "$f" ] && echo "shmfile=$f"; done'
            '"$(cygpath -u "$SDV_EXE")" WHERE </dev/null >"$(cygpath -u "$SDV_OUT")" 2>&1'
            'echo "sdexit=$?"'
        ) -join "`n"
        [IO.File]::WriteAllText($gbScript, $sh + "`n", (New-Object Text.ASCIIEncoding))
        $rx = '^.*LOGIN PASSWORD account=' + [regex]::Escape($Acct) + ' via=stored\s*$'
        $a0 = Audit-Count $rx
        Say ''
        Say ('  $ ' + $bash + ' --noprofile --norc ' + $gbScript.Replace('\', '/') + '   [SDV_EXE=' + $SdExe + ', input: /dev/null]')
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $env:ComSpec
        $psi.Arguments = '/d /s /c ""' + $bash + '" --noprofile --norc "' + $gbScript.Replace('\', '/') + '" >"' + $gbOut + '" 2>&1"'
        $psi.UseShellExecute = $false
        $psi.WorkingDirectory = $Work
        $psi.EnvironmentVariables['SDV_EXE'] = $SdExe
        $psi.EnvironmentVariables['SDV_OUT'] = $gbSdOut
        $p = [Diagnostics.Process]::Start($psi)
        if (-not $p.WaitForExit(90000)) {
            $null = & taskkill.exe /PID $p.Id /T /F 2>$null
            $script:timeouts++
            Say '    TIMED OUT after 90 s - killed with its tree.'
        }
        else { Say ('    exit ' + $p.ExitCode) }
        $a1 = Audit-Count $rx
        $bt = $(if (Test-Path -LiteralPath $gbOut) { ([IO.File]::ReadAllText($gbOut)) -replace "`r", '' } else { '' })
        $st = $(if (Test-Path -LiteralPath $gbSdOut) { Mask (([IO.File]::ReadAllText($gbSdOut, [Text.Encoding]::GetEncoding(28591))) -replace "`r", '') } else { '' })
        foreach ($l in (Get-Lines $bt)) { Say ('    bash | ' + $l) }
        foreach ($l in (Get-Lines $st)) { Say ('    sd   | ' + ($l -replace [char]27, '^[')) }
        Say ('    audit "via=stored" lines: ' + $a0 + ' -> ' + $a1)
        $bl = Get-Lines $bt
        $rootLine = $(if ((First $bl '^root=') -ge 0) { $bl[(First $bl '^root=')] } else { '' })
        $gbRoot = $rootLine -replace '^root=', ''
        Check 'control: the bash root is not the Solo tree and its /dev/shm holds no SD segment' ($gbRoot -and ($gbRoot.TrimEnd('\') -ne $Root) -and ((CountOf $bl '^shmfile=.*sd_shm') -eq 0)) ('root "' + $gbRoot + '", SD segments there: ' + (CountOf $bl '^shmfile=.*sd_shm'))
        Check 'sd WHERE from Git Bash lands in the account' ((Lands $st) -and ($st -notmatch '(?i)has not been started|wrong password|needs the account password') -and ((CountOf $bl '^sdexit=0$') -eq 1)) ('want a line ending user_accounts\' + $Acct + ' and sdexit=0')
        Check 'and the audit says via=stored, once' ($a0 -ge 0 -and $a1 -eq $a0 + 1) ('audit count ' + $a0 + ' -> ' + $a1)
    }

    # -----------------------------------------------------------------------
    # 28 Sep 26 - RULING 28 (SOLO 16): a session whose input ends with no OFF
    # ends.  Before the fix each of these rang the bell (or, at PAUSE, spun
    # silently) until the 90 s kill.  Judged on the session ending by itself
    # (the timeout counter does not move), on it having reached the prompt
    # (Lands / the PAUSE prompt), and on the BEL count.
    Say ''
    Say '== 14. end of input ends a session, with no OFF'
    $to0 = $script:timeouts
    $t = Invoke-Sd 'eof-prompt' '' ($acctPw + "`nWHERE`n") 'the account password, WHERE - and NO OFF' -NoSpareOff
    $bel = ($t.Length - ($t -replace [char]7, '').Length)
    Check 'at the command prompt: it lands, then ends by itself' ((Lands $t) -and ($script:timeouts -eq $to0)) ('timeouts ' + $to0 + ' -> ' + $script:timeouts + ', landed ' + (Lands $t))
    Check 'and it rang the bell at most a few times' ($bel -lt 5) ('' + $bel + ' BEL')
    $to1 = $script:timeouts
    $t = Invoke-Sd 'eof-pause' '' ($acctPw + "`nPAUSE`n") 'the account password, PAUSE - and NO OFF' -NoSpareOff
    Check 'at PAUSE: the prompt shows, then the session ends by itself' (($t -match 'Press return to continue') -and ($script:timeouts -eq $to1)) ('timeouts ' + $to1 + ' -> ' + $script:timeouts + ', PAUSE prompt ' + ($t -match 'Press return to continue'))

    # -----------------------------------------------------------------------
    # 28 Sep 26 - RULING 26: no system BASIC source in the installed tree.  The
    # directory is gone, SDSYS's VOC record for it is gone (a one-shot CT, whose
    # "not found" is its answer about THAT id), and the compiled objects are
    # there - the control that the check is looking at a real install.
    Say ''
    Say '== 15. the installed tree carries no system BASIC source'
    $bpSrc = Join-Path $Sdsys 'gpl.bp'
    $bpOut = Join-Path $Sdsys 'gpl.bp.out'
    $nOut  = $(if (Test-Path -LiteralPath $bpOut) { @(Get-ChildItem -LiteralPath $bpOut -File).Count } else { -1 })
    Say ('    ' + $bpSrc + ' exists: ' + (Test-Path -LiteralPath $bpSrc))
    Say ('    ' + $bpOut + ' objects: ' + $nOut)
    Check 'control: gpl.bp.out holds the compiled system (over 150 objects)' ($nOut -gt 150) ('' + $nOut + ' objects')
    Check 'sdsys\gpl.bp is not installed' (-not (Test-Path -LiteralPath $bpSrc)) 'the directory is there'
    $t = Invoke-Sd 'no-gplbp-voc' 'CT VOC gpl.bp' '' 'none'
    Check 'and the VOC has no gpl.bp record' ((CountOf (Get-Lines $t) "^Record 'gpl\.bp' not found$") -eq 1) "want CT's \"Record 'gpl.bp' not found\""

    # -----------------------------------------------------------------------
    # 28 Sep 26 - RULING 33: the global catalogue is the SD Core server's.
    # a: sduser WITH ADMIN is refused every change - CATALOG ... GLOBAL and
    #    DELETE.CATALOG of a global entry (12029), SYNC.GLOBAL.CATALOG and a
    #    COPY into GLOBAL.BP.OUT (12028) - and GLOBAL.BP.OUT stays empty.
    # b: managed mode only - a session signed in with the GLOBAL password
    #    copies a compiled subroutine into GLOBAL.BP.OUT and syncs; sduser
    #    (account password, no ADMIN) then CALLs it as *name; the global
    #    session deletes it and syncs again, and the catalogue entry is gone.
    # The catalogue entry "*zzgsub" is stored on disk as "%Azzgsub" (a
    # directory file maps * to %A - the mapping HISTORY.md's entry 3 recorded).
    Say ''
    Say '== 16. the global catalogue belongs to the SD Core server'
    $gcatDir = Join-Path $Sdsys 'gcat'
    $gbpDir  = Join-Path $Sdsys 'global.bp.out'
    $gSub    = 'ZZGSUB'
    $gCall   = 'ZZGCALL'
    $gcatFile = Join-Path $gcatDir ('%A' + $gSub.ToLower())
    $gbpN = $(if (Test-Path -LiteralPath $gbpDir) { @(Get-ChildItem -LiteralPath $gbpDir -File).Count } else { -1 })
    Say ('    ' + $gbpDir + ' objects: ' + $gbpN + '   ' + $gcatFile + ' exists: ' + (Test-Path -LiteralPath $gcatFile))
    Check 'GLOBAL.BP.OUT is installed and empty, and no *zzgsub is catalogued' (($gbpN -eq 0) -and -not (Test-Path -LiteralPath $gcatFile)) ('objects ' + $gbpN + '; left by an earlier run?')

    $t = Invoke-Pe 'g-admin' @("CATALOG BP $gSub GLOBAL", ('DELETE.CATALOG *' + $gSub.ToLower()), 'SYNC.GLOBAL.CATALOG', 'COPY FROM VOC TO GLOBAL.BP.OUT WHERE') -Admin
    $L = Get-Lines $t
    Check 'a: with ADMIN, CATALOG ... GLOBAL and DELETE.CATALOG *name are refused (12029)' ((CountOf $L '^The global catalogue holds the SD Core server') -eq 2) ('12029 lines: ' + (CountOf $L '^The global catalogue holds the SD Core server'))
    Check 'a: with ADMIN, SYNC.GLOBAL.CATALOG and COPY into GLOBAL.BP.OUT are refused (12028)' (((CountOf $L '^The global catalogue can only be changed by the SD Core server') -eq 2) -and ($t -notmatch 'SYNC GLOBAL CATALOG DONE') -and ($t -notmatch 'record\(s\) copied')) ('12028 lines: ' + (CountOf $L '^The global catalogue can only be changed by the SD Core server'))
    $gbpN = @(Get-ChildItem -LiteralPath $gbpDir -File -ErrorAction SilentlyContinue).Count
    Check 'a: GLOBAL.BP.OUT is still empty' ($gbpN -eq 0) ('' + $gbpN + ' objects')

    if (-not $managed) {
        Skip 'b: the SD Core server adds, runs and removes a global program' 'standalone - no global password'
    }
    else {
        $gSubDest  = Join-Path $bpDir $gSub
        $gCallDest = Join-Path $bpDir $gCall
        try {
            [IO.File]::WriteAllText($gSubDest, (@(
                '* ZZGSUB - written by gplbld/verify-solo.ps1, leg 16.  Safe to delete.'
                '      SUBROUTINE ZZGSUB(X)'
                "      X = 'GLOBAL.OK'"
                '      RETURN'
                '   END') -join "`n") + "`n", [Text.Encoding]::ASCII)
            [IO.File]::WriteAllText($gCallDest, (@(
                '* ZZGCALL - written by gplbld/verify-solo.ps1, leg 16.  Safe to delete.'
                "      X = ''"
                '      CALL *ZZGSUB(X)'
                "      CRT 'GCALL=':X"
                '   END') -join "`n") + "`n", [Text.Encoding]::ASCII)
            $t = Invoke-Sd 'g-compile' ('BASIC BP ' + $gSub + ' ' + $gCall) '' 'none'
            $L = Get-Lines $t
            Check 'b: setup - both probe programs compile' (((CountOf $L '^0 error\(s\)') -ge 1) -and ($t -notmatch '(?i)Compilation error|[1-9][0-9]* error\(s\)')) 'want "0 error(s)"'

            $t = Invoke-Sd 'g-add' '' ($globalPw + "`nCOPY FROM BP.OUT TO GLOBAL.BP.OUT $gSub`nSYNC.GLOBAL.CATALOG`nOFF`n") 'the global password, COPY FROM BP.OUT TO GLOBAL.BP.OUT, SYNC.GLOBAL.CATALOG, OFF'
            Check 'b: the global session copies the object into GLOBAL.BP.OUT' ($t -match '1 record\(s\) copied') 'want "1 record(s) copied"'
            Check 'b: and SYNC.GLOBAL.CATALOG catalogues it' (($t -match '(?m)^SYNC GLOBAL CATALOG DONE 1 catalogued 0 removed 0 refused\s*$') -and (Test-Path -LiteralPath $gcatFile)) ('want the DONE 1/0/0 line and ' + $gcatFile)

            $t = Invoke-Sd 'g-run' ('RUN BP ' + $gCall) '' 'none'
            Check 'b: sduser, without ADMIN, CALLs the global program' ((CountOf (Get-Lines $t) '^GCALL=GLOBAL\.OK$') -eq 1) 'want "GCALL=GLOBAL.OK"'

            $t = Invoke-Sd 'g-remove' '' ($globalPw + "`nDELETE GLOBAL.BP.OUT $gSub`nSYNC.GLOBAL.CATALOG`nOFF`n") 'the global password, DELETE GLOBAL.BP.OUT, SYNC.GLOBAL.CATALOG, OFF'
            Check 'b: deleted from GLOBAL.BP.OUT and synced, the catalogue entry is gone' (($t -match '(?m)^SYNC GLOBAL CATALOG DONE 0 catalogued 1 removed 0 refused\s*$') -and -not (Test-Path -LiteralPath $gcatFile)) ('want the DONE 0/1/0 line and no ' + $gcatFile)
        }
        finally {
            foreach ($n in @($gSub, $gCall)) {
                foreach ($d in @($bpDir, $outDir)) {
                    $f = Join-Path $d $n
                    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
                }
            }
            # A failed run must not leave the server's file or the catalogue changed.
            foreach ($f in @((Join-Path $gbpDir $gSub), $gcatFile)) {
                if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue; Say ('    cleaned up ' + $f) }
            }
        }
    }

    # -----------------------------------------------------------------------
    # 28 Sep 26 - RULINGS 34, 35 AND 36.
    # a (35): without ADMIN the eight maintenance verbs that had no check are
    #    refused with 2001; with ADMIN the two harmless readers run.  SET.DATE,
    #    CLEAN.ACCOUNT, LOCK and CLEAR.LOCKS are only ever asked WITHOUT ADMIN.
    # b (36): DENY.VERBS is refused to sduser even with ADMIN (12030).
    # c (34, 36): managed only - a global session adds WHO to the deny list;
    #    sduser without ADMIN is refused WHO (2001), with ADMIN it runs; the
    #    global session removes WHO and sduser runs it again.  The list the
    #    install set is shown and left as it was; if WHO was already on it the
    #    leg says so and does not remove it.
    Say ''
    Say '== 17. the administrator-only verbs and the deny list'
    $gate2001 = '^Command requires administrator privileges$'
    $eight = @('CONFIG', 'LISTU', 'LIST.LOCKS', 'LIST.READU', 'LOCK 1', 'CLEAR.LOCKS', 'SET.DATE 01/01/2030', 'CLEAN.ACCOUNT')
    $t = Invoke-Pe 'v-noadmin' $eight
    $n2001 = CountOf (Get-Lines $t) $gate2001
    Check 'a: without ADMIN, all eight maintenance verbs are refused (2001)' ($n2001 -eq 8) ('' + $n2001 + ' of 8 refused')
    # SOLO 21: CONFIG GPL and CONFIG CONTRIB are the banner's own advice, so
    # they need no ADMIN.  Anchored on the first line of each record, which
    # only a successful display prints; a 2001 anywhere disqualifies.
    # show.doc clears the screen first, so each first line starts with ESC[H
    # ESC[J - measured 28 Sep 2026, when an anchor without $esc failed a run
    # whose displays had both worked.
    $esc = '^(?:\x1b\[[0-9;]*[A-Za-z])*'
    $t = Invoke-Pe 'v-config-docs' @('CONFIG GPL', 'CONFIG CONTRIB')
    $okDocs = ((CountOf (Get-Lines $t) ($esc + 'SD, including the API, is licensed under the GPL v3\.0\.$')) -eq 1) -and
              ((CountOf (Get-Lines $t) ($esc + 'Contributors to SD and predecessor applications$')) -eq 1) -and
              ((CountOf (Get-Lines $t) $gate2001) -eq 0)
    Check 'a: without ADMIN, CONFIG GPL and CONFIG CONTRIB run' $okDocs 'want the licence and contributors lines and no 2001'
    $t = Invoke-Pe 'v-admin' @('LISTU', 'LIST.LOCKS') -Admin
    Check 'a: with ADMIN, LISTU and LIST.LOCKS run' (((CountOf (Get-Lines $t) $gate2001) -eq 0) -and ($t -match '(?i)sduser')) 'want no 2001 and LISTU naming sduser'

    $t = Invoke-Pe 'v-deny-admin' @('DENY.VERBS', 'DENY.VERBS ADD WHO') -Admin
    Check 'b: with ADMIN, DENY.VERBS is refused (12030)' (((CountOf (Get-Lines $t) '^The denied verbs can only be listed or changed by the SD Core server') -eq 2) -and ($t -notmatch '(?m)^DENY\.VERBS \d+:')) 'want two 12030 and no DENY.VERBS answer'

    if (-not $managed) {
        Skip 'c: the SD Core server denies and allows a verb' 'standalone - no global password'
    }
    else {
        $t = Invoke-Sd 'v-deny-list' '' ($globalPw + "`nDENY.VERBS`nOFF`n") 'the global password, DENY.VERBS, OFF'
        $line = @((Get-Lines $t) | Where-Object { $_ -match '^DENY\.VERBS \d+:' })
        Say ('    the list the install set: ' + $(if ($line.Count) { $line[0] } else { '(no answer)' }))
        Check 'c: a global session lists the deny list' ($line.Count -eq 1) 'want one "DENY.VERBS n: ..." line'
        $hadWho = ($line.Count -eq 1) -and ((($line[0] -replace '^DENY\.VERBS \d+:\s*', '') -split ',') -contains 'WHO')
        if ($hadWho) {
            Skip 'c: deny and allow WHO' 'WHO is already on the install''s list - left alone'
        }
        else {
            try {
                $t = Invoke-Sd 'v-deny-add' '' ($globalPw + "`nDENY.VERBS ADD WHO`nOFF`n") 'the global password, DENY.VERBS ADD WHO, OFF'
                Check 'c: DENY.VERBS ADD WHO' ($t -match '(?m)^DENY\.VERBS \d+: .*\bWHO\b') 'want WHO in the DENY.VERBS answer'
                $t = Invoke-Pe 'v-who-denied' @('WHO')
                Check 'c: sduser without ADMIN is refused WHO (2001)' ((CountOf (Get-Lines $t) $gate2001) -eq 1) 'want one 2001'
                $t = Invoke-Pe 'v-who-admin' @('WHO') -Admin
                Check 'c: with ADMIN, WHO runs' (((CountOf (Get-Lines $t) $gate2001) -eq 0) -and ($t -match ('(?m)^\s*\d+\s+' + [regex]::Escape($Acct) + '\b'))) 'want a WHO answer and no 2001'
            }
            finally {
                $t = Invoke-Sd 'v-deny-remove' '' ($globalPw + "`nDENY.VERBS REMOVE WHO`nOFF`n") 'the global password, DENY.VERBS REMOVE WHO, OFF'
            }
            Check 'c: DENY.VERBS REMOVE WHO' (($t -match '(?m)^DENY\.VERBS \d+:') -and ($t -notmatch '(?m)^DENY\.VERBS \d+: .*\bWHO\b')) 'want a DENY.VERBS answer without WHO'
            $t = Invoke-Pe 'v-who-again' @('WHO')
            Check 'c: and sduser runs WHO again without ADMIN' (((CountOf (Get-Lines $t) $gate2001) -eq 0) -and ($t -match ('(?m)^\s*\d+\s+' + [regex]::Escape($Acct) + '\b'))) 'want a WHO answer and no 2001'

            # d (SOLO 22): a verb is denied by what it runs.  SH and ! are both
            # V/OS; denying SH must deny ! too, and DENY.VERBS must say so.  The
            # echo text is the success wording of the shell itself.
            $bangOk = 'zzbang-ran-' + $PID
            $t = Invoke-Sd 'v-deny-sh' '' ($globalPw + "`nDENY.VERBS ADD SH`nOFF`n") 'the global password, DENY.VERBS ADD SH, OFF'
            $shAdded = ($t -match '(?m)^DENY\.VERBS \d+: .*\bSH\b')
            try {
                Check 'd: DENY.VERBS ADD SH names ! as also denied' ($shAdded -and ($t -match '(?m)^DENY\.VERBS also denies, as the same command: .*!')) 'want SH on the list and an "also denies" line naming !'
                $t = Invoke-Pe 'v-bang-denied' @('! echo ' + $bangOk)
                Check 'd: with SH denied, sduser without ADMIN is refused ! (2001)' (((CountOf (Get-Lines $t) $gate2001) -eq 1) -and ((CountOf (Get-Lines $t) ('^' + [regex]::Escape($bangOk) + '$')) -eq 0)) 'want one 2001 and the echo text not printed'
            }
            finally {
                if ($shAdded) { $t = Invoke-Sd 'v-deny-sh-remove' '' ($globalPw + "`nDENY.VERBS REMOVE SH`nOFF`n") 'the global password, DENY.VERBS REMOVE SH, OFF' }
            }
            Check 'd: SH is off the list again' (($t -match '(?m)^DENY\.VERBS \d+:') -and ($t -notmatch '(?m)^DENY\.VERBS \d+: .*\bSH\b')) 'want a DENY.VERBS answer without SH'
            $t = Invoke-Pe 'v-bang-again' @('! echo ' + $bangOk)
            Check 'd: CONTROL - and ! runs again without ADMIN' (((CountOf (Get-Lines $t) ('^' + [regex]::Escape($bangOk) + '$')) -eq 1) -and ((CountOf (Get-Lines $t) $gate2001) -eq 0)) 'want the echo text and no 2001'
        }
    }

    # -----------------------------------------------------------------------
    # 18 (ruling 39): who changes which password.  The refusals first - they
    # change nothing.  Then each password is changed to a TEMPORARY one, proved,
    # and changed back.  The temporary one is the real one with $suffix after
    # it, so a failed put-back can be described without printing a password.
    # A put-back that does not print "Password changed" FAILS with the
    # recovery in its reason.  Last but one, so a failure here cannot void the
    # legs before it; leg 19 only reads a process token.
    Say ''
    Say '== 18. who changes which password (SET.PASSWORD [ADMIN|GLOBAL])'
    $suffix = 'Zz9!'
    $okRx = '^Password changed$'
    $gate2001 = '^Command requires administrator privileges$'
    $t = Invoke-Pe 'p-usage' @('SET.PASSWORD BOGUS')
    Check 'a: SET.PASSWORD BOGUS is refused with the usage line' (((CountOf (Get-Lines $t) '^SET\.PASSWORD \[ADMIN \| GLOBAL\]$') -eq 1) -and ((CountOf (Get-Lines $t) $okRx) -eq 0)) 'want the usage line and no "Password changed"'
    $t = Invoke-Sd 'p-wrong-current' '' ($acctPw + "`nTERM 200,9999`nSET.PASSWORD`n" + $wrongPw + "`nOFF`n") 'account password, TERM 200,9999, SET.PASSWORD, a WRONG current password, OFF'
    Check 'a: without ADMIN, SET.PASSWORD asks the current password and refuses a wrong one (12032)' (($t -match 'Current password:') -and ((CountOf (Get-Lines $t) '^Wrong password - the password is unchanged$') -eq 1) -and ((CountOf (Get-Lines $t) $okRx) -eq 0)) 'want "Current password:", 12032, and no "Password changed"'
    $t = Invoke-Pe 'p-admin-noadmin' @('SET.PASSWORD ADMIN')
    Check 'a: without ADMIN, SET.PASSWORD ADMIN is refused (2001)' ((CountOf (Get-Lines $t) $gate2001) -eq 1) 'want one 2001'
    $t = Invoke-Pe 'p-global-admin' @('SET.PASSWORD GLOBAL') -Admin
    if ($managed) {
        Check 'a: with ADMIN, SET.PASSWORD GLOBAL is refused (12033)' ((CountOf (Get-Lines $t) '^The global password can only be changed by the SD Core server$') -eq 1) 'want 12033'
    }
    else {
        Check 'a: standalone, SET.PASSWORD GLOBAL is refused (12034)' ((CountOf (Get-Lines $t) '^This computer is standalone - it has no global password$') -eq 1) 'want 12034'
    }

    # b: the account password, WITHOUT ADMIN, after the current one.
    $tAcct = $acctPw + $suffix
    $script:secrets = @($script:secrets + $tAcct) | Where-Object { $_ }
    $changed = $false
    try {
        $t = Invoke-Sd 'p-acct-set' '' ($acctPw + "`nSET.PASSWORD`n" + $acctPw + "`n" + $tAcct + "`n" + $tAcct + "`nOFF`n") 'account password, SET.PASSWORD, the current one, a temporary one twice, OFF'
        $changed = ((CountOf (Get-Lines $t) $okRx) -eq 1)
        Check 'b: without ADMIN, the account password changes after the current one' $changed 'want "Password changed"'
        if ($changed) {
            $t = Invoke-Sd 'p-acct-new' '' ($tAcct + "`nWHERE`nOFF`n") 'the temporary account password, WHERE, OFF'
            Check 'b: the new account password signs in' (Lands $t) ('want a WHERE line ending user_accounts/' + $Acct)
            $t = Invoke-Sd 'p-acct-oneshot' 'WHERE' '' 'none'
            Check 'b: a one-shot WHERE signs in with the kept copy, rewritten' (Lands $t) ('want a WHERE line ending user_accounts/' + $Acct)
        }
    }
    finally {
        if ($changed) {
            $t = Invoke-Sd 'p-acct-back' '' ($tAcct + "`nSET.PASSWORD`n" + $tAcct + "`n" + $acctPw + "`n" + $acctPw + "`nOFF`n") 'the temporary password, SET.PASSWORD, it, the real one twice, OFF'
            Check 'b: the account password is put back' ((CountOf (Get-Lines $t) $okRx) -eq 1) ('RECOVER BY HAND: the account password is now your usual one followed by ' + $suffix + ' - sign in with that and run SET.PASSWORD')
        }
    }

    # c: the administrator password, with ADMIN.
    $tAdm = $adminPw + $suffix
    $script:secrets = @($script:secrets + $tAdm) | Where-Object { $_ }
    $changed = $false
    try {
        $t = Invoke-Sd 'p-admin-set' '' ($acctPw + "`nADMIN`n" + $adminPw + "`nSET.PASSWORD ADMIN`n" + $tAdm + "`n" + $tAdm + "`nOFF`n") 'account password, ADMIN, administrator password, SET.PASSWORD ADMIN, a temporary one twice, OFF'
        $changed = ((CountOf (Get-Lines $t) $okRx) -eq 1)
        Check 'c: with ADMIN, the administrator password changes' $changed 'want "Password changed"'
        if ($changed) {
            $t = Invoke-Sd 'p-admin-new' '' ($acctPw + "`nADMIN`n" + $tAdm + "`nOFF`n") 'account password, ADMIN, the temporary administrator password, OFF'
            Check 'c: the new administrator password unlocks ADMIN' ((CountOf (Get-Lines $t) '^Administrator commands unlocked for this session$') -eq 1) 'want 12003'
            $t = Invoke-Sd 'p-admin-old' '' ($acctPw + "`nADMIN`n" + $adminPw + "`nOFF`n") 'account password, ADMIN, the OLD administrator password, OFF'
            Check 'c: CONTROL - the old one no longer does (12005)' ((CountOf (Get-Lines $t) '^Wrong password - administrator commands stay locked$') -eq 1) 'want 12005'
        }
    }
    finally {
        if ($changed) {
            $t = Invoke-Sd 'p-admin-back' '' ($acctPw + "`nADMIN`n" + $tAdm + "`nSET.PASSWORD ADMIN`n" + $adminPw + "`n" + $adminPw + "`nOFF`n") 'account password, ADMIN, the temporary one, SET.PASSWORD ADMIN, the real one twice, OFF'
            Check 'c: the administrator password is put back' ((CountOf (Get-Lines $t) $okRx) -eq 1) ('RECOVER BY HAND: the administrator password is now your usual one followed by ' + $suffix + ' - ADMIN with that, then SET.PASSWORD ADMIN')
        }
    }

    # d: the global password, from a global session - managed only.
    if (-not $managed) {
        Skip 'd: the SD Core server changes the global password' 'standalone - no global password'
    }
    else {
        $tGlb = $globalPw + $suffix
        $script:secrets = @($script:secrets + $tGlb) | Where-Object { $_ }
        $changed = $false
        try {
            $t = Invoke-Sd 'p-global-set' '' ($globalPw + "`nSET.PASSWORD GLOBAL`n" + $tGlb + "`n" + $tGlb + "`nOFF`n") 'the global password, SET.PASSWORD GLOBAL, a temporary one twice, OFF'
            $changed = ((CountOf (Get-Lines $t) $okRx) -eq 1)
            Check 'd: a global session changes the global password' $changed 'want "Password changed"'
            if ($changed) {
                $t = Invoke-Sd 'p-global-new' '' ($tGlb + "`nWHERE`nOFF`n") 'the temporary global password, WHERE, OFF'
                Check 'd: the new global password signs in' (Lands $t) ('want a WHERE line ending user_accounts/' + $Acct)
            }
        }
        finally {
            if ($changed) {
                $t = Invoke-Sd 'p-global-back' '' ($tGlb + "`nSET.PASSWORD GLOBAL`n" + $globalPw + "`n" + $globalPw + "`nOFF`n") 'the temporary global password, SET.PASSWORD GLOBAL, the real one twice, OFF'
                Check 'd: the global password is put back' ((CountOf (Get-Lines $t) $okRx) -eq 1) ('RECOVER BY HAND: the global password is now your usual one followed by ' + $suffix + ' - sign in with that and run SET.PASSWORD GLOBAL')
            }
        }
    }

    # e: after the changes, the API still verifies both passwords - the
    # account and $GLOBAL records must still share one salt (ruling 19).
    if (-not $apiPort -or -not $script:Py -or -not (Test-Path -LiteralPath $Scram)) {
        Skip 'e: the API after the changes' 'no API or no scram-probe - see leg 5'
    }
    else {
        $t = Invoke-Scram 'the account password, after' $acctPw @('WHO')
        Check 'e: an API login with the account password is still VERIFIED' (($t -match '(?i)SCRAM: server signature VERIFIED') -and ($t -notmatch '(?i)REFUSED')) 'want VERIFIED'
        if ($managed) {
            $t = Invoke-Scram 'the global password, after' $globalPw @('WHO')
            Check 'e: an API login with the global password is still VERIFIED' (($t -match '(?i)SCRAM: server signature VERIFIED') -and ($t -notmatch '(?i)REFUSED')) 'want VERIFIED'
        }
    }

    # -----------------------------------------------------------------------
    # 30 Sep 26 - SOLO 24: API request 49, the SD Core server installs its ssh key.
    # Managed mode only: a standalone computer has no global password.  A throwaway
    # key is made here, put through ADD/PRESENT/LIST/REMOVE/ABSENT with the global
    # password, refused with the account password (CONTROL), refused with a bad
    # argument, and used for a real ssh login to this machine - which must be
    # refused BEFORE the ADD (CONTROL) and reach SD after it.  Every anchor is the
    # tool's own success wording ("SSHKEY ADD: OK ...|ADDED"), never an echoed
    # argument.  The key is REMOVEd and the user's authorized_keys put back.
    Say ''
    Say '== 18b. the ssh key request (SOLO 24, request 49)'
    $kgen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    $sshc = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not $managed) { Skip '18b: request 49' 'standalone - no global password, the request cannot be made' }
    elseif (-not $apiPort -or -not $script:Py -or -not (Test-Path -LiteralPath $Scram)) { Skip '18b: request 49' 'no API or no scram-probe - see leg 5' }
    elseif (-not (Test-Path -LiteralPath $kgen) -or -not (Test-Path -LiteralPath $sshc)) { Skip '18b: request 49' 'no OpenSSH client in System32' }
    else {
        $akf = Join-Path $env:USERPROFILE '.ssh\authorized_keys'
        $akBefore = $(if (Test-Path -LiteralPath $akf) { (Get-FileHash -LiteralPath $akf -Algorithm SHA256).Hash } else { '(absent)' })
        $kdir = Join-Path $env:TEMP ('sdsshkey-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $kdir | Out-Null
        $kf = Join-Path $kdir 'k'
        $null = & $kgen -q -t ed25519 -N '""' -f $kf -C verify49
        $pub = (Get-Content -LiteralPath ($kf + '.pub') -Raw).Trim()
        $fpr = (((& $kgen -l -f ($kf + '.pub')) -join ' ') -split '\s+')[1]
        Say ('    throwaway key: ' + $kf + '   fingerprint (ssh-keygen): ' + $fpr)
        $sshArgs = @('-i', $kf, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '-o', ('UserKnownHostsFile=' + (Join-Path $kdir 'kh')),
                     '-o', 'ConnectTimeout=10', ($env:USERNAME.ToLower() + '@localhost'), 'echo SHELL-RAN')
        function Invoke-KeyLogin([string]$What) {
            $so = Join-Path $kdir ($What + '.out'); $se = Join-Path $kdir ($What + '.err'); $si = Join-Path $kdir 'stdin.txt'
            [IO.File]::WriteAllText($si, "`n")
            Say ('  $ ssh ' + ($sshArgs -join ' '))
            $p = Start-Process -FilePath $sshc -ArgumentList $sshArgs -PassThru -NoNewWindow -RedirectStandardInput $si -RedirectStandardOutput $so -RedirectStandardError $se
            if (-not $p.WaitForExit(40000)) { $null = & taskkill.exe /PID $p.Id /T /F 2>$null; Say '    ssh TIMED OUT after 40 s - killed.' }
            $txt = ((Get-Content -LiteralPath $so -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $se -Raw -ErrorAction SilentlyContinue))
            foreach ($l in (($txt -replace "`r", '') -split "`n")) { if ($l.Trim()) { Say ('    | ' + $l) } }
            return $txt
        }
        $added = $false
        try {
            # CONTROL first: before the ADD the key is unknown, so sshd must refuse it.
            $t = Invoke-KeyLogin 'before'
            Check 'CONTROL: before the ADD, ssh with the key is refused' (($t -match 'Permission denied') -and ($t -notmatch 'SD Core Solo for Windows')) 'want Permission denied and no SD banner'

            $t = Invoke-ScramKey 'the global password' $globalPw @('LIST', ('ADD ' + $pub), ('ADD ' + $pub), 'LIST', 'ADD ssh-ed25519 AAAA;x')
            $added = ($t -match 'SSHKEY ADD: OK')
            Check 'ADD answers five fields, the key was ADDED, and the fingerprint is ssh-keygen''s' ($t -match ('(?m)^SSHKEY ADD: OK [^|]+\|[^|]+\|' + [regex]::Escape($fpr) + '\|ADDED\|SHA256:[A-Za-z0-9+/]{43}\s*$')) 'want: SSHKEY ADD: OK <user>|<host>|<fingerprint>|ADDED|SHA256:<sshd host key> (field 5 is recorded by the installer)'
            Check 'the same key again is PRESENT' ($t -match ('(?m)^SSHKEY ADD: OK [^|]+\|[^|]+\|' + [regex]::Escape($fpr) + '\|PRESENT\|')) 'want |PRESENT|'
            Check 'LIST then shows the fingerprint' ($t -match ('(?m)^SSHKEY LIST: OK .*' + [regex]::Escape($fpr))) 'want LIST to carry the fingerprint'
            Check 'a key with a character that is not allowed is refused with the shared wording' ($t -match 'SSHKEY ADD: REFUSED server_error 3: The ssh key request was refused: the key or fingerprint is not valid') 'want "... is not valid"'
            Check 'the authorized_keys file holds our line with restrict and the tag' ((Test-Path -LiteralPath $akf) -and ((Get-Content -LiteralPath $akf -Raw) -match ('(?m)^restrict ssh-ed25519 \S+ sdcoresolo-managed\s*$'))) 'want a "restrict ... sdcoresolo-managed" line'

            $t = Invoke-KeyLogin 'after'
            Check 'after the ADD, ssh with the key reaches SD (the forced command, no shell)' (($t -match 'SD Core Solo for Windows') -and ($t -notmatch 'SHELL-RAN') -and ($t -notmatch 'Permission denied')) 'want the SD banner, no SHELL-RAN, no Permission denied'

            # CONTROL: an ordinary account-password session is refused, file untouched.
            $hashMid = (Get-FileHash -LiteralPath $akf -Algorithm SHA256).Hash
            $t = Invoke-ScramKey 'the account password' $acctPw @('LIST', ('ADD ' + $pub), ('REMOVE ' + $fpr))
            Check 'CONTROL: with the account password, ADD, LIST and REMOVE are all refused (12036)' ((CountOf (Get-Lines $t) 'SSHKEY (ADD|LIST|REMOVE): REFUSED server_error 3: Only the SD Core server may manage ssh keys') -eq 3) 'want three refusals'
            Check 'and the file is byte-identical afterwards' ((Get-FileHash -LiteralPath $akf -Algorithm SHA256).Hash -eq $hashMid) 'the file changed'
        }
        finally {
            $t = Invoke-ScramKey 'the global password' $globalPw @(('REMOVE ' + $fpr), ('REMOVE ' + $fpr))
            Check 'REMOVE deletes it (REMOVED), and again is ABSENT' (($t -match '(?m)^SSHKEY REMOVE: OK REMOVED\|\d+') -and ($t -match '(?m)^SSHKEY REMOVE: OK ABSENT\|\d+')) ('RECOVER BY HAND: delete the "sdcoresolo-managed" line from ' + $akf)
            if (-not $added -or $akBefore -eq '(absent)') {
                if ((Test-Path -LiteralPath $akf) -and ((Get-Item -LiteralPath $akf).Length -eq 0) -and $akBefore -eq '(absent)') { Remove-Item -LiteralPath $akf -Force }
            }
            $akAfter = $(if (Test-Path -LiteralPath $akf) { (Get-FileHash -LiteralPath $akf -Algorithm SHA256).Hash } else { '(absent)' })
            Check 'the user''s authorized_keys is as it was before the leg' ($akAfter -eq $akBefore) ('before ' + $akBefore + ', after ' + $akAfter)
            Remove-Item -LiteralPath $kdir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # -----------------------------------------------------------------------
    Say ''
    Say '== 19. the daemon runs on a standard token'
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
