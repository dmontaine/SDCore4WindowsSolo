# probe-solo-dropadmin.ps1 - SOLO 3, owner's ruling 16, run in an ELEVATED
# PowerShell: does SD drop an administrator token where it must, and only there?
#
# Uses the tree already staged and bootstrapped at <repo>\stage (the agent
# builds it unelevated; the account and passwords are the probe's own).  Installs
# nothing.  Steps, each printing what it did:
#   1. start   - sd -stop, sd -start from this elevated window.  -START must
#                re-launch itself on a standard token (win32token.c).
#   2. daemon  - read the token of the running sdwind.exe from THIS tree:
#                integrity level, and how BUILTIN\Administrators is held.
#                Must be Medium and deny-only.
#   3. sessions- SH whoami with SSH_CONNECTION set (must be Medium), and
#                without it (a local elevated console: must stay High - the
#                control that this window really is elevated).
#   4. stop    - sd -stop, always.
# Output also goes to <repo>\stage\probe-solo-dropadmin.log.

$ErrorActionPreference = 'Stop'
$Sd64  = Split-Path -Parent $PSScriptRoot
$Repo  = Split-Path -Parent (Split-Path -Parent $Sd64)
$Stage = Join-Path $Repo 'stage'
$Log   = Join-Path $Stage 'probe-solo-dropadmin.log'
$Bash  = 'C:\msys64\usr\bin\bash.exe'
$Wind  = Join-Path $Stage 'SDCoreSolo\usr\bin\sdwind.exe'

function ToMsys([string] $p) {
    $p = $p -replace '\\', '/'
    if ($p -match '^([A-Za-z]):(.*)$') { return "/$($Matches[1].ToLower())$($Matches[2])" }
    return $p
}

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
"probe-solo-dropadmin.ps1"
"  stage    $Stage"
"  sdwind   $Wind   exists: $(Test-Path -LiteralPath $Wind)"
"  log      $Log"
"  elevated $elevated"
if (-not $elevated) { 'REFUSED: run this from an ELEVATED PowerShell.'; exit 2 }
if (-not (Test-Path -LiteralPath $Wind)) { 'REFUSED: no staged tree - the agent stages it first.'; exit 2 }

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

$pass = $true
# PRINTS TO THE HOST AND RETURNS ONLY THE EXIT CODE.  A function that emits
# lines AND returns a value hands its caller an array (the ps-function-output
# trap, recorded three times), and "(Step x) -ne 0" would then test an array.
# Piping bash's output to Out-Host is safe from the sdwind-holds-the-pipe hang:
# the Python legs give sd a temporary FILE for its output (bootstrap.sd()), so
# the daemon inherits that, not this pipe.
function Step([string] $what) {
    $cmd = "cd '$(ToMsys $Sd64)' && python3 gplbld/probe-solo-dropadmin.py --stage '$(ToMsys $Stage)' $what"
    Write-Host "  bash -lc $cmd"
    & $Bash -lc $cmd | Out-Host
    return [int]$LASTEXITCODE
}

Start-Transcript -LiteralPath $Log -Force | Out-Null
try {
    '=== 1. start'
    if ((Step 'start') -ne 0) { $pass = $false }

    '=== 2. the daemon''s token'
    $procs = @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Wind })
    "  sdwind processes from this tree: $($procs.Count)"
    if ($procs.Count -eq 0) { '  FAIL  no sdwind from this tree is running'; $pass = $false }
    foreach ($p in $procs) {
        $r = [SdTok]::Read($p.Id)
        "  pid $($p.Id): $r"
        $ok = ($r -match 'integrity=S-1-16-8192') -and ($r -match 'administrators=deny-only')
        "  $(if ($ok) {'PASS'} else {'FAIL'})  the daemon holds a standard token (Medium, Administrators deny-only)"
        if (-not $ok) { $pass = $false }
    }

    '=== 3. sessions'
    if ((Step 'sessions') -ne 0) { $pass = $false }
}
finally {
    '=== 4. stop'
    Step 'stop' | Out-Null
    Stop-Transcript | Out-Null
}
''
"probe-solo-dropadmin.ps1: $(if ($pass) {'PASS - every leg held'} else {'FAILED - see above'})"
"  log: $Log"
if ($pass) { exit 0 } else { exit 1 }
