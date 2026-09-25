# probe-solo-dropadmin.ps1 - SOLO 3, owner's ruling 16, run in an ELEVATED
# PowerShell: does SD drop an administrator token where it must, and only there?
#
# Uses the tree already staged and bootstrapped at <repo>\stage (the agent
# builds it unelevated; the account is the probe's own).  Installs nothing.
#
# SD IS DRIVEN NATIVELY - cmd.exe, output to a FILE - AND THAT IS THE POINT OF
# THIS VERSION.  The first version drove sd through MSYS2 python, and measured
# 25 Sep 2026: an sd.exe started from an MSYS2 process joins MSYS2's process
# table, so it could not see (or stop) a daemon that win32token.c had
# re-launched natively.  In production every start is native - the scheduled
# task, sshd, a console - so this is the faithful form.  Output goes to files,
# never to a pipe: "sd -start" hands its handles to sdwind, which lives on.
#
# Steps, each printing what it did and the raw output:
#   1. start    - sd -stop, sd -start from this elevated window.  -START must
#                 re-launch itself on a standard token.
#   2. daemon   - the running sdwind.exe of THIS tree: must be Medium integrity
#                 with BUILTIN\Administrators deny-only.
#   3. ssh      - SH whoami with SSH_CONNECTION set (as sshd would): Medium.
#   4. control  - the same WITHOUT it (a local elevated console, left alone by
#                 the ruling): must stay High - proves this window IS elevated.
#   5. stop     - sd -stop, always; then no sdwind of this tree may be left.

$ErrorActionPreference = 'Stop'
$Sd64  = Split-Path -Parent $PSScriptRoot
$Repo  = Split-Path -Parent (Split-Path -Parent $Sd64)
$Stage = Join-Path $Repo 'stage'
$Bin   = Join-Path $Stage 'SDCoreSolo\usr\bin'
$Sd    = Join-Path $Bin 'sd.exe'
$Wind  = Join-Path $Bin 'sdwind.exe'
$Work  = Join-Path $Stage 'probe-dropadmin'
$Who   = Join-Path $env:SystemRoot 'System32\whoami.exe'
$Cmd   = Join-Path $env:SystemRoot 'System32\cmd.exe'

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "probe-solo-dropadmin.ps1"
Write-Host "  sd.exe   $Sd   exists: $(Test-Path -LiteralPath $Sd)"
Write-Host "  work     $Work"
Write-Host "  elevated $elevated"
if (-not $elevated) { Write-Host 'REFUSED: run this from an ELEVATED PowerShell.'; exit 2 }
if (-not (Test-Path -LiteralPath $Sd)) { Write-Host 'REFUSED: no staged tree - the agent stages it first.'; exit 2 }
New-Item -ItemType Directory -Force -Path $Work | Out-Null

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SdTok {
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

# Runs sd.exe natively through cmd.exe: three empty lines on stdin (as the
# build's runner feeds one, so no prompt spins on end of file), output to a
# FILE.  Prints the command and the raw output; returns ONLY the text, never
# mixed with printed lines (the ps-function-output trap).
function Invoke-Sd([string] $label, [string] $sdArgs) {
    $out = Join-Path $Work ($label + '.txt')
    $in  = Join-Path $Work 'input.txt'
    [IO.File]::WriteAllText($in, "`r`n`r`n`r`n")
    $line = '/c ""' + $Sd + '" ' + $sdArgs + ' < "' + $in + '" > "' + $out + '" 2>&1"'
    Write-Host "  `$ $Cmd $line"
    $p = Start-Process -FilePath $Cmd -ArgumentList $line -NoNewWindow -PassThru
    if (-not $p.WaitForExit(120000)) {
        Write-Host "  TIMED OUT after 120 s - cmd.exe pid $($p.Id) left running"
        return 'TIMED OUT'
    }
    # Read SHARED: after "-start" the daemon still holds this file open (it
    # inherited it - which is why it is a file and not a pipe), and a plain
    # ReadAllText is refused "being used by another process".  Measured.
    $text = ''
    if (Test-Path -LiteralPath $out) {
        $fs = [IO.File]::Open($out, 'Open', 'Read', 'ReadWrite, Delete')
        try { $text = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() }
    }
    foreach ($l in ($text -split "`r?`n")) { if ($l.Trim()) { Write-Host "      | $l" } }
    return $text
}

function Token-Line([string] $text) {
    $lines = $text -split "`r?`n"
    $integ = ($lines | Where-Object { $_ -match 'Mandatory Label\\' } | Select-Object -First 1)
    $adm = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^SID:\s+S-1-5-32-544\s*$') {
            for ($j = $i + 1; $j -lt [Math]::Min($i + 3, $lines.Count); $j++) {
                if ($lines[$j] -match '^Attributes:\s*(.*)$') { $adm = $Matches[1].Trim() }
            }
        }
    }
    return @{ Integrity = "$integ".Trim(); Admins = $adm }
}

$pass = $true
function Verdict([bool] $ok, [string] $what) {
    Write-Host ("  {0}  {1}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $what)
    if (-not $ok) { $script:pass = $false }
}

$savedSsh = $env:SSH_CONNECTION
Remove-Item Env:SSH_CONNECTION, Env:SD_TOKEN_FILTERED, Env:SD_DROP_ADMIN_TEST, Env:SD_CONFIG -ErrorAction SilentlyContinue
try {
    Write-Host '=== 1. start'
    Invoke-Sd 'stop0' '-stop' | Out-Null
    $o = Invoke-Sd 'start' '-start'
    Verdict ($o -match 'has been started') 'sd -start from this elevated window started SD'

    Write-Host '=== 2. the daemon''s token'
    $procs = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Wind })
    Write-Host "  sdwind processes from this tree: $($procs.Count)"
    Verdict ($procs.Count -eq 1) 'exactly one daemon from this tree is running'
    foreach ($q in $procs) {
        $r = [SdTok]::Read($q.Id)
        Write-Host "  pid $($q.Id): $r"
        Verdict (($r -match 'integrity=S-1-16-8192') -and ($r -match 'administrators=deny-only')) 'the daemon holds a standard token (Medium, Administrators deny-only)'
    }

    Write-Host '=== 3. an ssh session (SSH_CONNECTION set, as sshd would)'
    $env:SSH_CONNECTION = '127.0.0.1 50000 127.0.0.1 22'
    $o = Invoke-Sd 'ssh' ('SH ' + $Who + ' /groups /fo list')
    Remove-Item Env:SSH_CONNECTION -ErrorAction SilentlyContinue
    $t = Token-Line $o
    Write-Host "    integrity: '$($t.Integrity)'   Administrators: '$($t.Admins)'"
    Verdict (($t.Integrity -match 'Medium Mandatory Level') -and ($t.Admins -match 'deny only')) 'an ssh session runs on a standard token'

    Write-Host '=== 4. CONTROL: a local elevated console (no SSH_CONNECTION)'
    $o = Invoke-Sd 'local' ('SH ' + $Who + ' /groups /fo list')
    $t = Token-Line $o
    Write-Host "    integrity: '$($t.Integrity)'   Administrators: '$($t.Admins)'"
    Verdict (($t.Integrity -match 'High Mandatory Level') -and ($t.Admins -match 'Enabled group')) 'a local elevated console is left alone (and this window really is elevated)'
}
finally {
    Write-Host '=== 5. stop'
    Invoke-Sd 'stop' '-stop' | Out-Null
    Start-Sleep -Seconds 2
    $left = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Wind })
    Verdict ($left.Count -eq 0) "sd -stop left no daemon of this tree running ($($left.Count) left)"
    if ($savedSsh) { $env:SSH_CONNECTION = $savedSsh }
}
Write-Host ''
Write-Host "probe-solo-dropadmin.ps1: $(if ($pass) {'PASS - every leg held'} else {'FAILED - see above'})"
Write-Host "  raw outputs: $Work"
if ($pass) { exit 0 } else { exit 1 }
