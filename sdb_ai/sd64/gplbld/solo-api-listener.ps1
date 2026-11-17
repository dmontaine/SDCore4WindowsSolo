# solo-api-listener.ps1 - turn SD Core Solo's API listener on or off in sd.conf.  SOLO 33.
#
#   powershell -ExecutionPolicy Bypass -File solo-api-listener.ps1 -Show     report, change nothing
#   powershell -ExecutionPolicy Bypass -File solo-api-listener.ps1 -On       set APIPORT
#   powershell -ExecutionPolicy Bypass -File solo-api-listener.ps1 -Off      comment APIPORT out
#                                          [-ConfPath <file>]   (default: sd.conf beside this script)
#
# Exit 0 the file now says what was asked, 1 it could not be written or did not read back, 2 the
# question could not be answered (no file, unreadable, nothing asked).
#
# WHY IT EXISTS (SOLO 33, owner's choice of option 1, 6 Oct 2026).  Windows shows its own "allow
# this app through the firewall?" alert the first time a program LISTENS and no rule covers it.  The
# installer's unelevated step starts SD (sd -start) to make the account, in the user's interactive
# session; with APIPORT in sd.conf that start opened the API port, raised the alert behind the
# consent prompt, and an Allow left two sdwind.exe rules open to ANY address on Public - wider than
# the "reach" box the user left unticked.  Measured twice (6 Oct 2026, fresh guests).  So the
# installer now ships sd.conf with APIPORT commented out, that unelevated start listens on nothing,
# and solo-machine.ps1 - elevated, AFTER it has made the firewall rule - runs this with -On, then
# registers the startup task, whose sdwind starts in session 0 (which cannot show an alert) with the
# listener on and the rule already there.  -Off is the same switch the other way, and is what the
# reload step uses on a kept sd.conf so a saved APIPORT cannot reopen the problem.
#
# THE PORT ONLY OPENS AT START-UP: sdwind reads APIPORT once as SD starts (gplsrc/sdwind.c,
# open_api_listener()).  A change here takes effect when SD next starts, and the caller says so.
#
# IT IS THE LISTENER, NOT THE FIREWALL: APIPORT decides whether SD opens a socket at all;
# api-firewall.ps1 decides who may reach it.  The number is not the port: SD listens on 4249
# whatever the number is (any value above zero means ON), so an old file's APIPORT=4243 is read as
# ON and -On rewrites it to the 4249 form.
#
# ASCII AND THE FILE'S OWN LINE ENDINGS, BOTH KEPT: bytes are read and written with [System.IO.File],
# never Get-Content/Set-Content (which re-encode), and the file's CRLF or LF is detected and kept.
# THE MATCH IS WHOLE-LINE AND CASE-SENSITIVE, as stage.py's own check is (l.strip() == 'APIPORT=4249'):
# a substring test cannot tell "APIPORT=4249" from the commented "# APIPORT=4249" that contains it.
# A file with NEITHER form (the user took the line out): -Off is already true; -On appends one.

#
# 17 Nov 26 - -Local, from Core 8bd42f1a (RELEASE_1.1 317; four-version audit round 1).  ONE LINE SAYS WHICH ADDRESS: APILOCAL=1
# active binds 127.0.0.1 only (-Local, remote.api local, as Linux Solo's LOCAL); commented or absent, every interface (-On).  -Off
# leaves it alone (no listener either way).  A move between ON and LOCAL changes the bind, which SD reads only as it starts.
#   powershell -ExecutionPolicy Bypass -File solo-api-listener.ps1 -Local    set APIPORT and APILOCAL=1 (127.0.0.1 only)

param(
    [switch]$On,
    [switch]$Local,
    [switch]$Off,
    [switch]$Show,
    [string]$ConfPath = ''
)

$ErrorActionPreference = 'Stop'

$ACTIVE    = 'APIPORT=4249'
$COMMENTED = '# APIPORT=4249'
$LEGACY_ACTIVE    = 'APIPORT=4243'     # an earlier Solo build's sd.conf: ON, and SD listens on 4249
$LEGACY_COMMENTED = '# APIPORT=4243'
$LOCAL_ACTIVE    = 'APILOCAL=1'
$LOCAL_COMMENTED = '# APILOCAL=1'

if ($ConfPath -eq '') { $ConfPath = Join-Path $PSScriptRoot 'sd.conf' }

function Say([string]$t) { Write-Output ('solo-api-listener: ' + $t) }

# EVERY RUN ECHOES ITS REAL INPUTS (CLAUDE.md's instrument rule).
Say ('file   : ' + $ConfPath)
Say ('action : ' + $(if ($On) { 'On' } elseif ($Local) { 'Local' } elseif ($Off) { 'Off' } elseif ($Show) { 'Show' } else { '(none given)' }))

if (-not $On -and -not $Local -and -not $Off -and -not $Show) { Say 'one of -On, -Local, -Off or -Show is required'; exit 2 }
if (@($On, $Local, $Off, $Show | Where-Object { $_ }).Count -gt 1) { Say 'give only one of -On, -Local, -Off, -Show'; exit 2 }
if (-not (Test-Path -LiteralPath $ConfPath)) { Say 'the file does not exist, so there is nothing to read or change'; exit 2 }

try { $text = [System.IO.File]::ReadAllText($ConfPath, [System.Text.Encoding]::ASCII) }
catch { Say ('the file could not be read: ' + $_.Exception.Message); exit 2 }

# The file's own line ending: CRLF if it has any, else LF.
$nl = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = $text -split $nl, 0, 'SimpleMatch'

$activeIdx = @(); $commentedIdx = @(); $legacyActive = 0; $localIdx = @(); $localOffIdx = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
    $t = $lines[$i].Trim()
    if ($t -ceq $ACTIVE)           { $activeIdx += $i }
    if ($t -ceq $LEGACY_ACTIVE)    { $activeIdx += $i; $legacyActive++ }
    if ($t -ceq $COMMENTED)        { $commentedIdx += $i }
    if ($t -ceq $LEGACY_COMMENTED) { $commentedIdx += $i }
    if ($t -ceq $LOCAL_ACTIVE)     { $localIdx += $i }
    if ($t -ceq $LOCAL_COMMENTED)  { $localOffIdx += $i }
}
$isLocal = ($localIdx.Count -gt 0)
Say ($(if ($Show) { 'lines  : active=' } else { 'before : active=' }) + $activeIdx.Count + ' commented=' + $commentedIdx.Count + ' local=' + $localIdx.Count + ' (line ending ' + $(if ($nl -eq "`r`n") { 'CRLF' } else { 'LF' }) + ')')

if ($Show) {
    if ($activeIdx.Count -gt 0 -and $isLocal) { Say 'state  : ON - SD opens the API listener on 127.0.0.1 only (APILOCAL)' }
    elseif ($activeIdx.Count -gt 0) { Say 'state  : ON - SD opens the API listener when it next starts' }
    else                        { Say 'state  : OFF - SD opens no API socket at all' }
    if ($legacyActive -gt 0) { Say 'port   : the line says 4243; SD ignores the number and listens on port 4249' }
    elseif ($activeIdx.Count -gt 0) { Say 'port   : 4249' }
    exit 0
}

$wantOn = [bool]$On -or [bool]$Local
$wantLocal = [bool]$Local
Say ('bind   : ' + $(if ($isLocal) { '127.0.0.1 only (APILOCAL=1)' } else { 'every interface' }))
$newActive = $activeIdx.Count - $legacyActive
# "already" only when the bind is already the one asked for, too.
if ($wantOn -and $activeIdx.Count -gt 0 -and ($newActive -gt 0 -or $legacyActive -eq 0) -and ($isLocal -eq $wantLocal)) {
    Say ('already ' + $(if ($wantLocal) { 'LOCAL' } else { 'ON' }) + ' - nothing to change'); exit 0
}
if ((-not $wantOn) -and $activeIdx.Count -eq 0) { Say 'already OFF - nothing to change'; exit 0 }

# ONE LINE MOVES: the first.  Several lines are reported above so the caller can see them.
if ($wantOn) {
    if ($activeIdx.Count -gt 0)        { $i = $activeIdx[0]; $lines[$i] = $ACTIVE }      # already on (the bind moves below), or a legacy 4243 line, rewritten
    elseif ($commentedIdx.Count -gt 0) { $i = $commentedIdx[0]; $lines[$i] = $ACTIVE }
    else {
        # neither form: append one (a trailing empty element is the file's final line ending)
        $keep = @($lines)
        if ($keep.Count -gt 0 -and $keep[$keep.Count - 1] -eq '') { $keep = $keep[0..($keep.Count - 2)] }
        $lines = @($keep) + @('# APIPORT switched on by the installer (SOLO 33), after the firewall rule', $ACTIVE, '')
        $i = $lines.Count - 2
    }
} else {
    $i = $activeIdx[0]; $lines[$i] = $COMMENTED
}
Say ('editing line ' + ($i + 1))

# The bind.  -Local makes one APILOCAL=1 line active (a commented one turned on, or a new line after APIPORT's); -On comments every
# active one out; -Off leaves them.
if ($wantLocal -and -not $isLocal) {
    if ($localOffIdx.Count -gt 0) {
        $lines[$localOffIdx[0]] = $LOCAL_ACTIVE
        Say ('APILOCAL on, line ' + ($localOffIdx[0] + 1))
    } else {
        $before = @(); $after2 = @()
        if ($i -ge 0) { $before = $lines[0..$i] }
        if ($i + 1 -le $lines.Count - 1) { $after2 = $lines[($i + 1)..($lines.Count - 1)] }
        $lines = @($before) + @($LOCAL_ACTIVE) + @($after2)
        Say ('APILOCAL added after line ' + ($i + 1))
    }
} elseif ($wantOn -and -not $wantLocal -and $isLocal) {
    foreach ($li in $localIdx) { $lines[$li] = $LOCAL_COMMENTED }
    Say ('APILOCAL commented out (' + $localIdx.Count + ' line(s))')
}

try { [System.IO.File]::WriteAllText($ConfPath, ($lines -join $nl), [System.Text.Encoding]::ASCII) }
catch { Say ('the file could not be written: ' + $_.Exception.Message); exit 1 }

# READ BACK BEFORE REPORTING SUCCESS.
try { $after = [System.IO.File]::ReadAllText($ConfPath, [System.Text.Encoding]::ASCII) }
catch { Say ('written, but it could not be read back: ' + $_.Exception.Message); exit 1 }
$afterActive = @($after -split $nl, 0, 'SimpleMatch' | Where-Object { ($_.Trim() -ceq $ACTIVE) -or ($_.Trim() -ceq $LEGACY_ACTIVE) })
$afterLocal = @($after -split $nl, 0, 'SimpleMatch' | Where-Object { $_.Trim() -ceq $LOCAL_ACTIVE })
Say ('after  : active=' + $afterActive.Count + ' local=' + $afterLocal.Count)
if ($wantOn -and $afterActive.Count -ne 1) { Say 'the file does not read back as ON'; exit 1 }
if ((-not $wantOn) -and $afterActive.Count -ne 0) { Say 'the file does not read back as OFF'; exit 1 }
if ($wantOn -and (($afterLocal.Count -gt 0) -ne $wantLocal)) {
    Say ('the file does not read back as ' + $(if ($wantLocal) { 'LOCAL (no active APILOCAL=1)' } else { 'ON (an APILOCAL=1 is still active)' })); exit 1
}

if ($wantLocal)  { Say 'the API listener is ON, on 127.0.0.1 only, when SD is next started' }
elseif ($wantOn) { Say 'the API listener is ON when SD is next started' }
else             { Say 'the API listener is OFF when SD is next started' }
exit 0
