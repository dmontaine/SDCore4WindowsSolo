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
# WHY IT EXISTS (SOLO 33, owner's choice of option 1, 7 Oct 2026).  Windows shows its own "allow
# this app through the firewall?" alert the first time a program LISTENS and no rule covers it.  The
# installer's unelevated step starts SD (sd -start) to make the account, in the user's interactive
# session; with APIPORT in sd.conf that start opened the API port, raised the alert behind the
# consent prompt, and an Allow left two sdwind.exe rules open to ANY address on Public - wider than
# the "reach" box the user left unticked.  Measured twice (6 and 7 Oct 2026, fresh guests).  So the
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

param(
    [switch]$On,
    [switch]$Off,
    [switch]$Show,
    [string]$ConfPath = ''
)

$ErrorActionPreference = 'Stop'

$ACTIVE    = 'APIPORT=4249'
$COMMENTED = '# APIPORT=4249'
$LEGACY_ACTIVE    = 'APIPORT=4243'     # an earlier Solo build's sd.conf: ON, and SD listens on 4249
$LEGACY_COMMENTED = '# APIPORT=4243'

if ($ConfPath -eq '') { $ConfPath = Join-Path $PSScriptRoot 'sd.conf' }

function Say([string]$t) { Write-Output ('solo-api-listener: ' + $t) }

# EVERY RUN ECHOES ITS REAL INPUTS (CLAUDE.md's instrument rule).
Say ('file   : ' + $ConfPath)
Say ('action : ' + $(if ($On) { 'On' } elseif ($Off) { 'Off' } elseif ($Show) { 'Show' } else { '(none given)' }))

if (-not $On -and -not $Off -and -not $Show) { Say 'one of -On, -Off or -Show is required'; exit 2 }
if (($On -and $Off) -or ($On -and $Show) -or ($Off -and $Show)) { Say 'give only one of -On, -Off, -Show'; exit 2 }
if (-not (Test-Path -LiteralPath $ConfPath)) { Say 'the file does not exist, so there is nothing to read or change'; exit 2 }

try { $text = [System.IO.File]::ReadAllText($ConfPath, [System.Text.Encoding]::ASCII) }
catch { Say ('the file could not be read: ' + $_.Exception.Message); exit 2 }

# The file's own line ending: CRLF if it has any, else LF.
$nl = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = $text -split $nl, 0, 'SimpleMatch'

$activeIdx = @(); $commentedIdx = @(); $legacyActive = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $t = $lines[$i].Trim()
    if ($t -ceq $ACTIVE)           { $activeIdx += $i }
    if ($t -ceq $LEGACY_ACTIVE)    { $activeIdx += $i; $legacyActive++ }
    if ($t -ceq $COMMENTED)        { $commentedIdx += $i }
    if ($t -ceq $LEGACY_COMMENTED) { $commentedIdx += $i }
}
Say ($(if ($Show) { 'lines  : active=' } else { 'before : active=' }) + $activeIdx.Count + ' commented=' + $commentedIdx.Count + ' (line ending ' + $(if ($nl -eq "`r`n") { 'CRLF' } else { 'LF' }) + ')')

if ($Show) {
    if ($activeIdx.Count -gt 0) { Say 'state  : ON - SD opens the API listener when it next starts' }
    else                        { Say 'state  : OFF - SD opens no API socket at all' }
    if ($legacyActive -gt 0) { Say 'port   : the line says 4243; SD ignores the number and listens on port 4249' }
    elseif ($activeIdx.Count -gt 0) { Say 'port   : 4249' }
    exit 0
}

$wantOn = [bool]$On
$newActive = $activeIdx.Count - $legacyActive
if ($wantOn -and $activeIdx.Count -gt 0 -and ($newActive -gt 0 -or $legacyActive -eq 0)) { Say 'already ON - nothing to change'; exit 0 }
if ((-not $wantOn) -and $activeIdx.Count -eq 0) { Say 'already OFF - nothing to change'; exit 0 }

# ONE LINE MOVES: the first.  Several lines are reported above so the caller can see them.
if ($wantOn) {
    if ($activeIdx.Count -gt 0)        { $i = $activeIdx[0]; $lines[$i] = $ACTIVE }      # a legacy 4243 line, rewritten
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

try { [System.IO.File]::WriteAllText($ConfPath, ($lines -join $nl), [System.Text.Encoding]::ASCII) }
catch { Say ('the file could not be written: ' + $_.Exception.Message); exit 1 }

# READ BACK BEFORE REPORTING SUCCESS.
try { $after = [System.IO.File]::ReadAllText($ConfPath, [System.Text.Encoding]::ASCII) }
catch { Say ('written, but it could not be read back: ' + $_.Exception.Message); exit 1 }
$afterActive = @($after -split $nl, 0, 'SimpleMatch' | Where-Object { ($_.Trim() -ceq $ACTIVE) -or ($_.Trim() -ceq $LEGACY_ACTIVE) })
Say ('after  : active=' + $afterActive.Count)
if ($wantOn -and $afterActive.Count -ne 1) { Say 'the file does not read back as ON'; exit 1 }
if ((-not $wantOn) -and $afterActive.Count -ne 0) { Say 'the file does not read back as OFF'; exit 1 }

if ($wantOn) { Say 'the API listener is ON when SD is next started' }
else         { Say 'the API listener is OFF when SD is next started' }
exit 0
