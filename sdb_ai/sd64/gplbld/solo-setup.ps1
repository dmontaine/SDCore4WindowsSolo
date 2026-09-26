# solo-setup.ps1 - SD Core Solo's unelevated install steps.  SOLO 8.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-setup.ps1
#       -AppDir <install dir> -User <windows user name> -Report <file>
#       [-Passwords] [-Global]
#
# Run by sd-solo.iss at ssPostInstall, as the user, NOT elevated.  Exit 0 every
# step passed, 1 a step failed, 2 refused before doing anything.
#
# WHAT IT DOES, IN ORDER:
#   1. sd -start   SD sessions need a started SD (probe-solo-stage.py:108 - three
#                  sessions printed "SD has not been started" without it).
#   2. sd -internal RUN gpl.bp solo_account <user>       (SOLO 4, ruling 10)
#   3. -Passwords: solo_password ADMIN, and with -Global also GLOBAL  (SOLO 5)
#   4. sd -stop    the machine step (solo-machine.ps1) starts it again from the
#                  scheduled task, which is the process that should own it.
# Each -internal session gets the one-shot marker LOGIN demands (ruling 13,
# internal-marker.ps1), written immediately before it.
#
# THE PASSWORDS NEVER TOUCH A COMMAND LINE OR A FILE.  The installer puts them
# in its own environment as SD_SOLO_ADMIN_PW / SD_SOLO_GLOBAL_PW just before it
# starts this script and clears them after; this script reads them, clears them
# from its own environment before starting any child, and writes each to sd's
# standard input, which is where solo_password reads it ("input pw HIDDEN").
#
# sd's OUTPUT GOES TO A FILE, NOT A PIPE: a pipe would never reach end-of-file,
# because sdwind inherits it and keeps it open (probe-solo-stage.py sd_input).
# So sd runs under "cmd /c ... >file 2>&1" and only its INPUT is a pipe.
#
# EACH STEP IS JUDGED ON THE SUCCESS LINE THE BASIC PRINTS, anchored whole:
# "SOLO ACCOUNT READY <name> <path>" and "SOLO PASSWORD SET ADMIN|GLOBAL"
# (gpl.bp/solo_account:139, solo_password:88).  The account name is an argument
# and so appears in failure output too - the anchor is the whole line, and
# "only the installer may run this" / "Connection terminated" disqualify.
# Every session's raw output goes into the report, with any password masked; a
# password found in the output fails the step.

param(
    [string]$AppDir = '',
    [string]$User = '',
    [string]$Report = '',
    [switch]$Passwords,
    [switch]$Global
)

$ErrorActionPreference = 'Stop'
$lines = New-Object System.Collections.ArrayList
function Note([string]$s) { [void]$lines.Add($s) }
function Save-Report {
    if ($Report) {
        try { [IO.File]::WriteAllLines($Report, [string[]]$lines.ToArray(), (New-Object Text.UTF8Encoding($false))) }
        catch { }
    }
}

# Read and clear the passwords before anything else can inherit them.
$adminPw  = [Environment]::GetEnvironmentVariable('SD_SOLO_ADMIN_PW', 'Process')
$globalPw = [Environment]::GetEnvironmentVariable('SD_SOLO_GLOBAL_PW', 'Process')
# 25 Sep 26 - ruling 18: the user's own API password (solo_password API).
$apiPw    = [Environment]::GetEnvironmentVariable('SD_SOLO_API_PW', 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_ADMIN_PW', $null, 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_GLOBAL_PW', $null, 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_API_PW', $null, 'Process')
# SOLO 2: the tree finds itself from sd.exe's location; a stray SD_CONFIG would
# point it somewhere else.
[Environment]::SetEnvironmentVariable('SD_CONFIG', $null, 'Process')

$sdexe = Join-Path $AppDir 'usr\bin\sd.exe'
$sdsys = Join-Path $AppDir 'sdsys'
Note ('=== solo-setup ' + (Get-Date -Format s))
Note ('app dir      : ' + $AppDir)
Note ('sd.exe       : ' + $sdexe + '   exists: ' + (Test-Path -LiteralPath $sdexe))
Note ('user         : ' + $User)
Note ('passwords    : ' + $(if ($Passwords) { 'ADMIN' + $(if ($Global) { ' and GLOBAL' } else { '' }) } else { 'not set by this run' }))
Note ('admin pw     : ' + $(if ($adminPw) { 'given (' + $adminPw.Length + ' characters)' } else { 'NOT given' }))
Note ('global pw    : ' + $(if ($globalPw) { 'given (' + $globalPw.Length + ' characters)' } else { 'NOT given' }))
Note ('api pw       : ' + $(if ($apiPw) { 'given (' + $apiPw.Length + ' characters)' } else { 'NOT given' }))

# The null cases, refused out loud.
$refuse = @()
if (-not $AppDir -or -not (Test-Path -LiteralPath $sdexe)) { $refuse += 'no sd.exe under the app dir' }
if (-not (Test-Path -LiteralPath $sdsys)) { $refuse += 'no sdsys under the app dir' }
if (-not $User) { $refuse += 'no user name' }
if ($Passwords -and -not $adminPw) { $refuse += '-Passwords without an administrator password' }
if ($Global -and -not $Passwords) { $refuse += '-Global without -Passwords' }
if ($Global -and -not $globalPw) { $refuse += '-Global without a global password' }
$markerLib = Join-Path $AppDir 'internal-marker.ps1'
if (-not (Test-Path -LiteralPath $markerLib)) { $refuse += 'no internal-marker.ps1 under the app dir' }
if ($refuse.Count -gt 0) {
    foreach ($r in $refuse) { Note ('REFUSED      : ' + $r) }
    Note 'VERDICT      : REFUSED - nothing was run'
    Save-Report
    exit 2
}
. $markerLib

$work = Join-Path $env:TEMP ('sd-solo-setup-' + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
$script:n = 0
$secrets = @($adminPw, $globalPw, $apiPw) | Where-Object { $_ }

# Run sd.exe with $SdArgs; $InputText (may be empty) is written to its standard
# input, which is then closed so a read at end of input cannot wait forever.
# Returns the output with every password masked; sets $script:leaked when one
# was found.
function Invoke-Sd([string]$SdArgs, [string]$InputText) {
    $script:n++
    $out = Join-Path $work ('sd-' + $script:n + '.txt')
    $internal = $SdArgs -match '^-internal\b'
    Note ''
    Note ('$ sd ' + $SdArgs + $(if ($InputText) { '   [input: 1 line, not shown]' } else { '' }) + $(if ($internal) { '   [marker written]' } else { '' }))
    if ($internal -and -not (Set-SdInternalMarker -SdsysDir $sdsys -Writer 'solo-setup')) {
        Note '  could not write the internal marker'
        return ''
    }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c ""' + $sdexe + '" ' + $SdArgs + ' >"' + $out + '" 2>&1"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $work
    # NO BYTE-ORDER MARK ON sd's INPUT.  Measured 25 Sep 2026: INPUT received
    # EF BB BF + the password and solo_password stored THAT, so a SCRAM login
    # with the right password was refused as "wrong password" (the stored key
    # matched BOM + password exactly) - every password this script had stored
    # carried it.  Process builds its stdin writer from [Console]::InputEncoding
    # and writes that encoding's PREAMBLE AT START, before any byte of ours -
    # so writing raw bytes alone did not stop it (measured the same day:
    # solo_password refused code 239 at position 1).  Set a preamble-free
    # encoding first, and refuse to send anything if the writer still has one.
    try { [Console]::InputEncoding = New-Object Text.ASCIIEncoding } catch { }
    $p = [Diagnostics.Process]::Start($psi)
    $pre = $p.StandardInput.Encoding.GetPreamble().Length
    if ($pre -ne 0) {
        Note ('  REFUSED: the stdin writer (' + $p.StandardInput.Encoding.WebName + ') writes a ' + $pre + '-byte preamble; nothing sent')
        $InputText = ''
    }
    # Raw ASCII bytes to the base stream: the installer allows printable ASCII
    # only, so ASCII is exact.
    if ($InputText) {
        $bytes = [Text.Encoding]::ASCII.GetBytes($InputText + "`n")
        $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $p.StandardInput.BaseStream.Flush()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(120000)) {
        try { $p.Kill() } catch { }
        Note '  TIMED OUT after 120 s'
    }
    else { Note ('  exit ' + $p.ExitCode) }
    if ($internal) { [void](Remove-SdInternalMarker -SdsysDir $sdsys) }
    $text = ''
    if (Test-Path -LiteralPath $out) {
        # The daemon started by "sd -start" may still hold this file open.
        $fs = [IO.File]::Open($out, 'Open', 'Read', 'ReadWrite')
        try { $text = (New-Object IO.StreamReader($fs, [Text.Encoding]::GetEncoding(28591))).ReadToEnd() }
        finally { $fs.Close() }
    }
    $text = $text -replace "`r", ''
    foreach ($s in $secrets) {
        if ($text.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $script:leaked = $true
            $text = $text -replace [regex]::Escape($s), '********'
        }
    }
    foreach ($l in ($text -split "`n")) { if ($l.Trim()) { Note ('  | ' + $l) } }
    return $text
}

$disqualify = @('only the installer may run this', 'Connection terminated', 'has not been started')
$fails = @()
function Judge([string]$Label, [string]$Text, [string]$Pattern) {
    $hit = [bool]([regex]::IsMatch($Text, $Pattern, 'IgnoreCase, Multiline'))
    $bad = @($disqualify | Where-Object { $Text.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    if ($hit -and $bad.Count -eq 0 -and -not $script:leaked) { Note ('  PASS  ' + $Label) }
    else {
        $why = @()
        if (-not $hit) { $why += 'no line matching ' + $Pattern }
        if ($bad.Count) { $why += 'output says: ' + ($bad -join '; ') }
        if ($script:leaked) { $why += 'a password appeared in the output' }
        Note ('  FAIL  ' + $Label + ' (' + ($why -join '; ') + ')')
        $script:fails += $Label
    }
}

try {
    $script:leaked = $false
    [void](Invoke-Sd '-stop' '')          # a leftover daemon from an earlier run
    # No verdict of its own: "has not been started" in the NEXT session's
    # output is the disqualifier that says whether this worked.
    [void](Invoke-Sd '-start' '')

    # Unquoted, as probe-solo-stage.py passes it: solo_account takes the fourth
    # word of the sentence, so quotes would become part of the name.
    $acct = $User.ToLower()
    $t = Invoke-Sd ('-internal RUN gpl.bp solo_account ' + $User) ''
    Judge 'account created' $t ('^SOLO ACCOUNT READY ' + [regex]::Escape($acct) + ' \S')

    if ($Passwords) {
        $t = Invoke-Sd '-internal RUN gpl.bp solo_password ADMIN' $adminPw
        Judge 'administrator password set' $t '^SOLO PASSWORD SET ADMIN\s*$'
        if ($Global) {
            $t = Invoke-Sd '-internal RUN gpl.bp solo_password GLOBAL' $globalPw
            Judge 'global password set' $t '^SOLO PASSWORD SET GLOBAL\s*$'
        }
        if ($apiPw) {
            $t = Invoke-Sd ('-internal RUN gpl.bp solo_password API ' + $acct) $apiPw
            Judge 'API password set' $t '^SOLO PASSWORD SET API\s*$'
        }
    }
}
catch {
    Note ('ERROR        : ' + $_.Exception.Message)
    $fails += 'exception'
}
finally {
    $adminPw = $null; $globalPw = $null; $apiPw = $null; $secrets = $null
    [void](Invoke-Sd '-stop' '')
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Note ''
if ($fails.Count -eq 0) { Note 'VERDICT      : PASS - every step printed its success line'; $code = 0 }
else { Note ('VERDICT      : FAIL - ' + ($fails -join ', ')); $code = 1 }
Save-Report
exit $code
