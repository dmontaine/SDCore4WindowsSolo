# probe-solo-logonuser.ps1 - SOLO 1(b): can an UNELEVATED process check the
# current user's own Windows password with LogonUserW?  That is what ruling 3
# (API login with the Windows password, option A) rests on.
#
#   powershell -ExecutionPolicy Bypass -File probe-solo-logonuser.ps1
#
# Run it in an ORDINARY, UNELEVATED prompt - that is the daemon's case.
#
# THE PASSWORD IS TYPED BY THE PERSON AT THE KEYBOARD AND NEVER LEAVES MEMORY:
# it is read as a SecureString, handed to LogonUserW as an unmanaged buffer,
# and that buffer is zeroed and freed straight after.  Nothing prints it, logs
# it or writes it anywhere.
#
# Order, and each step prints its real inputs and Windows' own answer:
#   1. who is asking, and whether the account is local, Microsoft-linked or a
#      domain account (a Microsoft-linked one is the case ruling 3 worried about);
#   2. CONTROL: a random wrong password MUST be refused with 1326
#      (ERROR_LOGON_FAILURE) - otherwise the check below proves nothing.  It
#      counts one failed sign-in against the account's lockout counter;
#   3. the real password, as a NETWORK logon (type 3 - no profile load, the
#      cheapest kind), and the SID of the token it returns compared with the
#      caller's own.
# Exit 0 only when the control was refused AND the real password was accepted
# for the same SID.  1 otherwise.  2 when nothing was typed.

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SoloLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUserW(string user, string domain, IntPtr password,
                                         int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

$Meaning = @{
    0 = 'success'; 1326 = 'ERROR_LOGON_FAILURE (wrong name or password)';
    1327 = 'ERROR_ACCOUNT_RESTRICTION (e.g. blank password over the network)';
    1328 = 'ERROR_INVALID_LOGON_HOURS'; 1330 = 'ERROR_PASSWORD_EXPIRED';
    1331 = 'ERROR_ACCOUNT_DISABLED'; 1385 = 'ERROR_LOGON_TYPE_NOT_GRANTED';
    1909 = 'ERROR_ACCOUNT_LOCKED_OUT'; 1907 = 'ERROR_PASSWORD_MUST_CHANGE'
}

# Returns @{Ok; Code; Sid; Ms}.  PRINTS NOTHING (test-outputtrap-units.ps1).
function Test-Logon([string] $User, [string] $Domain, [Security.SecureString] $Secret) {
    $buf = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secret)
    $tok = [IntPtr]::Zero
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $ok = [SoloLogon]::LogonUserW($User, $Domain, $buf, 3, 0, [ref]$tok)
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($buf)
    }
    $ms = $sw.ElapsedMilliseconds
    $sid = ''
    if ($ok) {
        $code = 0
        $wid = New-Object Security.Principal.WindowsIdentity($tok)
        $sid = $wid.User.Value
        $wid.Dispose()
        [void][SoloLogon]::CloseHandle($tok)
    }
    return @{ Ok = $ok; Code = $code; Sid = $sid; Ms = $ms }
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$user   = $env:USERNAME
$domain = $env:USERDOMAIN
$source = 'unknown'
try { $source = [string](Get-LocalUser -Name $user -ErrorAction Stop).PrincipalSource } catch { $source = 'not a local account (domain?)' }

'=== probe-solo-logonuser ' + (Get-Date -Format s)
'caller          : ' + $me.Name + '   sid ' + $me.User.Value + '   elevated: ' + $elevated
'logon as        : user "' + $user + '"  domain "' + $domain + '"  type 3 (NETWORK)'
'account source  : ' + $source + '   (computer ' + $env:COMPUTERNAME + ')'
if ($elevated) { 'NOTE: run ELEVATED - the daemon will not be; rerun from an ordinary prompt' }

$pass = $true

# CONTROL: a password that cannot be right.
$wrong = New-Object Security.SecureString
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 24; $rng.GetBytes($bytes)
foreach ($b in $bytes) { $wrong.AppendChar([char](33 + ($b % 90))) }
$wrong.MakeReadOnly()
$c = Test-Logon $user $domain $wrong
'control (wrong) : ok=' + $c.Ok + '  code=' + $c.Code + ' ' + $Meaning[[int]$c.Code] + '  ' + $c.Ms + ' ms'
if ($c.Ok -or $c.Code -ne 1326) {
    'REFUSED: the control was not refused with 1326, so a success below would mean nothing'
    $pass = $false
}

$secret = Read-Host -AsSecureString ('Windows password for ' + $domain + '\' + $user + ' (not shown)')
if ($secret.Length -eq 0) { 'nothing typed - no real attempt made'; exit 2 }
$r = Test-Logon $user $domain $secret
$secret.Dispose()
'real password   : ok=' + $r.Ok + '  code=' + $r.Code + ' ' + $Meaning[[int]$r.Code] + '  ' + $r.Ms + ' ms'
if ($r.Ok) {
    'token sid       : ' + $r.Sid + '   same as caller: ' + ($r.Sid -eq $me.User.Value)
    if ($r.Sid -ne $me.User.Value) { $pass = $false }
} else {
    $pass = $false
}

if ($pass) { 'VERDICT         : PASS - an unelevated process can check this user''s own Windows password'; exit 0 }
'VERDICT         : FAIL - see the lines above'
exit 1
