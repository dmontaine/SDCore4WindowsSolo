# solo-setup.ps1 - SD Core Solo's unelevated install steps.  SOLO 8.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-setup.ps1
#       -AppDir <install dir> -User <windows user name> -Report <file>
#       [-Passwords] [-Global] [-Upgrade] [-ReloadFrom <dir>]   (-ReloadFrom alone: a reload that keeps the passwords)
#
# Run by sd-solo.iss at ssPostInstall, as the user, NOT elevated.  Exit 0 every
# step passed, 1 a step failed, 2 refused before doing anything.
#
# WHAT IT DOES, IN ORDER:
#   1. sd -start   SD sessions need a started SD (probe-solo-stage.py:108 - three
#                  sessions printed "SD has not been started" without it).
#   2. sd -internal RUN gpl.bp solo_account    the account sduser (ruling 29)
#   3. -Passwords: solo_password ADMIN, and with -Global also GLOBAL  (SOLO 5)
#      -ReloadFrom <dir> (SOLO 37, the user chose to reload kept data): the kept account's files are copied
#      into the new account, the kept sd.conf is tried (the default is put back if SD refuses it), and the
#      account's VOC is refreshed.  16 Nov 26 - SOLO 72 (Linux Solo 6d53db4, S.234 N9, the owner: "N9 same as core"): what
#      the uninstaller's Keep now keeps is put back too - sd-tls and ssh beside the account; in sdsys $cred, ai, netlogins,
#      newvoc.mods, voc_removed.saved and start.default, each replacing what this install made, and the audit trail JOINED
#      (the kept lines, then this install's) with its rotated copies.  $cred only without -Passwords: -ReloadFrom alone is
#      the installer's "kept passwords" case, and passwords given replace the kept ones (Linux's rule)
#   3a. (17 Nov 26, four-version audit round 4, Linux Solo's control file) SD_SOLO_SSH_KEY_FILE, a new tree only: the public key's
#      one line is added to <app>\ssh\authorized_keys (P-7371); a reloaded sd.conf with no SCREENTHEME line gets SCREENTHEME=paper
#      (P-4944, as sd-solo.iss does for a kept one).
#   4. -Upgrade: the dictionaries (SOLO 9, replacing upgrade-dicts.ps1) -
#      {app}\gplbld\FILES_DICTS placed at sdsys\gplbld, sd -internal RUN gpl.bp
#      WRITE_INSTALL_DICTS NO.PAGE (merges; every shipped record must be
#      written), sd -internal THIRD.COMPILE, the placed copy removed.  Then
#      sd -internal UPDATE.ACCOUNTS ALL   (SOLO 9, the
#      upgrade-completeness gap left by retiring upgrade-voc.ps1).  An upgrade
#      replaces NEWVOC but rebuilds no account's own live VOC, so a release
#      that adds a verb would otherwise ship it to nobody.  "-internal" names
#      SDSYS for itself (sd.c) and is seeded with the administrator flag
#      (kernel.c), which is exactly what LOGIN's mode-4 walk gates on
#      ("@who = 'SDSYS' and kernel(K$ADMINISTRATOR,-1)", gpl.bp/login:364) -
#      the same mechanism the retired script drove, called the same way.
#   4a. (16 Nov 26, RELEASE_1.1 335, Linux Solo S.261 fb685f0) sd -internal RUN gpl.bp solo_examples: the account's examples.bp, from
#      sdsys\examples, compiled.  EVERY install path - a new tree, a reload of kept data and an upgrade - so an existing account gains
#      the file on its first upgrade and has the shipped programs refreshed on every later one.  A failure is a WARNING line in the
#      report and does not fail the install (Linux Solo's EXAMPLES block; SD Core for Windows' LoadExamples never stops one either).
#   4b. (18 Nov 26, P-5661) -Upgrade: sd -internal RUN gpl.bp upgrade_nocase NO.PAGE, the older tree's files to case-insensitive
#      record ids; its output to <Solo folder>\nocase-upgrade.log; a file it left, or no COMPLETE, is a WARNING (18 Nov 26, as Linux Solo).
#   5. sd -internal DELETE VOC gpl.bp   (ruling 26 - no system BASIC source
#      in the installed tree; every install and upgrade), then
#      sd -internal SYNC.GLOBAL.CATALOG  (ruling 33 - the server's programs in
#      GLOBAL.BP.OUT back into the global catalogue after gcat is replaced)
#   5a. (20 Oct 26, RELEASE_1.1 165, the OS switch) SD_SOLO_OS_ACCESS none|sh|os|both, new tree and upgrade:
#      sd -internal SET.OS.ACCESS SH ON / OS ON for what it names, then SET.OS.ACCESS alone to read both switches back.
#   5b. (12 Nov 26, SOLO 56 group 6, the start question; Linux Solo S.221 START-SET) SD_SOLO_START menu|terminal, a new tree only
#      (sd-solo.iss passes nothing on an upgrade, which keeps the site's start): terminal runs sd -internal SET.START.DEFAULT TERMINAL
#      and is judged on the verb's words AND on sdsys\start.default, which must then say terminal; menu writes nothing (no
#      start.default is the home screen, as delivered).
#   5c. (17 Nov 26, four-version audit P-3791, Linux Solo's self-check) sd -internal WHO WITH NO MARKER, every install path: it
#      must be refused ("Connection terminated") and leave no marker; admitted fails the install.
#   6. sd -stop    the machine step (solo-machine.ps1) starts it again from the
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
    [switch]$Global,
    [switch]$Upgrade,
    # 06 Oct 26 - SOLO 37: the folder the installer moved the user's kept data to ("<tree>.kept-<time>").
    # On a NEW tree (-Passwords) it makes this run copy the kept account's files into the new account,
    # try the kept sd.conf, and refresh the account's VOC.  Never combined with -Upgrade.
    [string]$ReloadFrom = '',
    # 13 Nov 26 - RELEASE_1.1 252 (P-25, Linux Solo S.216): the installer's own folder, where a release package keeps the changes
    # document and the pdf folder of the documentation.  Empty: nothing is looked for.
    [string]$SourceDir = ''
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
# 25 Sep 26 - rulings 18, 21: the account password, asked by every session
# (solo_password ACCOUNT).  Was SD_SOLO_API_PW until the owner made it global.
$accountPw = [Environment]::GetEnvironmentVariable('SD_SOLO_ACCOUNT_PW', 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_ADMIN_PW', $null, 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_GLOBAL_PW', $null, 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_ACCOUNT_PW', $null, 'Process')
# 28 Sep 26 - ruling 34: the control file's deny-verbs line (not a secret).
$denyVerbs = "" + [Environment]::GetEnvironmentVariable('SD_SOLO_DENY_VERBS', 'Process')
[Environment]::SetEnvironmentVariable('SD_SOLO_DENY_VERBS', $null, 'Process')
# 20 Oct 26 - RELEASE_1.1 165, THE OS SWITCH (Linux Solo acd94b9 "ask during install"; the owner: "carry the switch").  The answer to
# "turn on the shell and OS access?": none, sh, os or both (not a secret).  Passed on a new tree AND on an upgrade.  none, or nothing
# at all, turns nothing on: both switches stay as they are, which is OFF on a new account.
$osAccess = ("" + [Environment]::GetEnvironmentVariable('SD_SOLO_OS_ACCESS', 'Process')).Trim().ToLowerInvariant()
[Environment]::SetEnvironmentVariable('SD_SOLO_OS_ACCESS', $null, 'Process')
# 12 Nov 26 - SOLO 56 group 6, THE START QUESTION (Linux Solo S.221; SD Core for Windows RELEASE_1.1 210): where new sessions start,
# menu (the home screen, as delivered) or terminal (the command prompt).  A new tree only; '' on an upgrade.  Not a secret.
$startAt = ("" + [Environment]::GetEnvironmentVariable('SD_SOLO_START', 'Process')).Trim().ToLowerInvariant()
[Environment]::SetEnvironmentVariable('SD_SOLO_START', $null, 'Process')
# 16 Nov 26 - SOLO 54, THE PDF READER QUESTION (Linux Solo's --viewer, Solo carry 14): a reader's name to allow for the pdf verb
# (SET.VIEWER ADD PDF name, which looks it up in App Paths and tests it), or '' for none.  New tree and upgrade.  Not a secret.
$viewer = ("" + [Environment]::GetEnvironmentVariable('SD_SOLO_VIEWER', 'Process')).Trim().ToLowerInvariant()
[Environment]::SetEnvironmentVariable('SD_SOLO_VIEWER', $null, 'Process')
# 17 Nov 26 - four-version audit round 4 (P-7371), Linux Solo's ssh-public-key-file= (solo-ssh.sh key-add): a public key FILE whose
# owner may ssh straight into sd-solo on Solo's own port.  Its one line goes into Solo's own key file, <app>\ssh\authorized_keys, where
# Solo's sshd forces sd-solo for every sign-in (solo-sshd.ps1's ForceCommand).  A new tree with ssh on only; sd-solo.iss passes none
# otherwise.  Not a secret (a public key).
$sshKeyFile = ("" + [Environment]::GetEnvironmentVariable('SD_SOLO_SSH_KEY_FILE', 'Process')).Trim()
[Environment]::SetEnvironmentVariable('SD_SOLO_SSH_KEY_FILE', $null, 'Process')
# SOLO 2: the tree finds itself from sd.exe's location; a stray SD_CONFIG would
# point it somewhere else.
[Environment]::SetEnvironmentVariable('SD_CONFIG', $null, 'Process')

$sdexe = Join-Path $AppDir 'usr\bin\sd-solo.exe'
$sdsys = Join-Path $AppDir 'sdsys'
Note ('=== solo-setup ' + (Get-Date -Format s))
Note ('app dir      : ' + $AppDir)
Note ('sd-solo.exe  : ' + $sdexe + '   exists: ' + (Test-Path -LiteralPath $sdexe))
Note ('user         : ' + $User + '   (the Windows user; the SD account is sduser, ruling 29)')
Note ('passwords    : ' + $(if ($Passwords) { 'ADMIN' + $(if ($Global) { ' and GLOBAL' } else { '' }) } else { 'not set by this run' }))
Note ('upgrade      : ' + $(if ($Upgrade) { 'UPDATE.ACCOUNTS ALL will run' } else { 'not requested' }))
Note ('reload from  : ' + $(if ($ReloadFrom) { $ReloadFrom + '   exists: ' + (Test-Path -LiteralPath $ReloadFrom) } else { 'not requested' }))
Note ('admin pw     : ' + $(if ($adminPw) { 'given (' + $adminPw.Length + ' characters)' } else { 'NOT given' }))
Note ('global pw    : ' + $(if ($globalPw) { 'given (' + $globalPw.Length + ' characters)' } else { 'NOT given' }))
Note ('account pw   : ' + $(if ($accountPw) { 'given (' + $accountPw.Length + ' characters)' } else { 'NOT given' }))
Note ('deny verbs   : ' + $(if ($denyVerbs) { '"' + $denyVerbs + '"' } else { 'none given' }))
Note ('os access    : ' + $(if ($osAccess) { '"' + $osAccess + '"' } else { 'not given (nothing is turned on)' }))
Note ('start        : ' + $(if ($startAt) { '"' + $startAt + '"' } else { 'not given (nothing is written: an upgrade, or the home screen)' }))
Note ('pdf reader   : ' + $(if ($viewer) { '"' + $viewer + '"' } else { 'not given (nothing is allowed)' }))
Note ('ssh key file : ' + $(if ($sshKeyFile) { '"' + $sshKeyFile + '"' } else { 'not given (no key is added)' }))

# The null cases, refused out loud.
$refuse = @()
# 20 Oct 26 - RELEASE_1.1 165: only the four words are an answer; it reaches sd's command line through cmd.exe.
if ($osAccess -and ($osAccess -notmatch '^(none|sh|os|both)$')) { $refuse += 'os-access is not none, sh, os or both' }
# 12 Nov 26 - SOLO 56 group 6: only the two words are an answer, and only on a new tree.
if ($startAt -and ($startAt -notmatch '^(menu|terminal)$')) { $refuse += 'start is not menu or terminal' }
if ($startAt -and $Upgrade) { $refuse += 'start is given on an upgrade, which keeps the site''s start' }
# 16 Nov 26 - SOLO 54: a reader's name reaches sd's command line through cmd.exe, so only a-z 0-9 . _ + -, not starting with a dot.
if ($viewer -and (($viewer -notmatch '^[a-z0-9._+-]{1,60}$') -or $viewer.StartsWith('.'))) { $refuse += 'the pdf reader is not a name of letters, digits and . _ + -' }
if (-not $AppDir -or -not (Test-Path -LiteralPath $sdexe)) { $refuse += 'no sd-solo.exe under the app dir' }
if (-not (Test-Path -LiteralPath $sdsys)) { $refuse += 'no sdsys under the app dir' }
if (-not $User) { $refuse += 'no user name' }
if ($Passwords -and -not $adminPw) { $refuse += '-Passwords without an administrator password' }
if ($Global -and -not $Passwords) { $refuse += '-Global without -Passwords' }
if ($Global -and -not $globalPw) { $refuse += '-Global without a global password' }
# SOLO 37: a reload goes into a NEW tree, from a folder that holds the kept account.
# 16 Nov 26 - SOLO 72: -ReloadFrom without -Passwords keeps the kept passwords, so the kept $cred must hold all three records a
# password-asking install writes (the installer's KeptPwFound); otherwise the new tree would have no password at all.
$keptCredWhole = $false
if ($ReloadFrom) {
    $kc = Join-Path $ReloadFrom 'sdsys\$cred'
    $keptCredWhole = (Test-Path -LiteralPath (Join-Path $kc 'sduser') -PathType Leaf) -and
                     (Test-Path -LiteralPath (Join-Path $kc '$admin') -PathType Leaf) -and
                     (Test-Path -LiteralPath (Join-Path $kc '$stored') -PathType Leaf)
    Note ('kept passwords: ' + $(if ($keptCredWhole) { 'sduser, $admin and $stored are in ' + $kc } else { 'not all three records are in ' + $kc }))
}
if ($ReloadFrom -and -not $Passwords -and -not $keptCredWhole) { $refuse += '-ReloadFrom without -Passwords, and the kept $cred lacks sduser, $admin or $stored' }
if ($ReloadFrom -and $Upgrade) { $refuse += '-ReloadFrom with -Upgrade (an upgrade already keeps its data)' }
if ($ReloadFrom -and -not (Test-Path -LiteralPath (Join-Path $ReloadFrom 'user_accounts\sduser'))) { $refuse += ('-ReloadFrom ' + $ReloadFrom + ' holds no user_accounts\sduser') }
# It reaches sd's command line through cmd.exe, so only verb-name characters,
# commas and spaces - nothing cmd could read as & | < > ^ or a quote.
if ($denyVerbs -and ($denyVerbs -notmatch '^[A-Za-z0-9.$_, -]+$')) { $refuse += 'deny-verbs holds a character that cannot be in a verb name' }
# 17 Nov 26 - P-7371: the key is checked as Linux Solo's solo-ssh.sh key-add checks it, before anything is done: one line, a key type
# sshd knows the shape of, no quote or backslash, and a key body that is base64.
$sshKeyLine = ''
if ($sshKeyFile) {
    if ($Upgrade) { $refuse += 'an ssh public key is given on an upgrade (a new tree only)' }
    elseif (-not (Test-Path -LiteralPath $sshKeyFile -PathType Leaf)) { $refuse += ('cannot read the ssh public key ' + $sshKeyFile) }
    else {
        $kl = @([IO.File]::ReadAllLines($sshKeyFile) | Where-Object { $_.Trim() -ne '' })
        $kf = @()
        if ($kl.Count -eq 1) { $kf = @($kl[0].Trim() -split '\s+') }
        $kb = $false
        if ($kf.Count -ge 2) { try { $kb = ([Convert]::FromBase64String($kf[1]).Length -ge 8) } catch { $kb = $false } }
        if ($kl.Count -ne 1) { $refuse += ($sshKeyFile + ' does not hold exactly one line; give one public key') }
        elseif ($kf[0] -notmatch '^(ssh-|ecdsa-|sk-)') { $refuse += ($sshKeyFile + ' does not look like an ssh public key') }
        elseif ($kl[0].Contains('"') -or $kl[0].Contains([string][char]92)) { $refuse += 'the key line contains a quote or backslash' }
        elseif (-not $kb) { $refuse += ($sshKeyFile + ': the key is not base64') }
        else { $sshKeyLine = $kl[0].Trim() }
    }
}
$markerLib = Join-Path $AppDir 'internal-marker.ps1'
if (-not (Test-Path -LiteralPath $markerLib)) { $refuse += 'no internal-marker.ps1 under the app dir' }
# The dictionary source: shipped to {app}\gplbld (stage.py), read by
# WRITE_INSTALL_DICTS from @sdsys/gplbld while it runs (bootstrap.py does the
# same placement).  Counted here so the transfer can be measured against it.
$dictSrc = Join-Path $AppDir 'gplbld\FILES_DICTS'
$dictDir = Join-Path $sdsys 'gplbld'
$dictDst = Join-Path $dictDir 'FILES_DICTS'
$dictWanted = 0
if ($Upgrade) {
    if (Test-Path -LiteralPath $dictSrc) { $dictWanted = @(Get-ChildItem -LiteralPath $dictSrc -File).Count }
    Note ('dictionaries : ' + $dictSrc + '   ' + $dictWanted + ' record(s)')
    if ($dictWanted -eq 0) { $refuse += '-Upgrade with no FILES_DICTS records under the app dir' }
}
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
$secrets = @($adminPw, $globalPw, $accountPw) | Where-Object { $_ }

# Run sd.exe with $SdArgs; $InputText (may be empty) is written to its standard
# input, which is then closed so a read at end of input cannot wait forever.
# Returns the output with every password masked; sets $script:leaked when one
# was found.
# 16 Nov 26 - RELEASE_1.1 335: $WaitMs, for solo_examples, which compiles 28 programs on a first run; every other call keeps 120 s.
# 17 Nov 26 - P-3791: -NoMarker runs an -internal command WITHOUT the marker, for the closing check that the door is shut.
function Invoke-Sd([string]$SdArgs, [string]$InputText, [int]$WaitMs = 120000, [switch]$NoMarker) {
    $script:n++
    $out = Join-Path $work ('sd-' + $script:n + '.txt')
    $internal = ($SdArgs -match '^-internal\b') -and -not $NoMarker
    Note ''
    Note ('$ sd ' + $SdArgs + $(if ($InputText) { '   [input: 1 line, not shown]' } else { '' }) + $(if ($internal) { '   [marker written]' } elseif ($NoMarker) { '   [NO marker: must be refused]' } else { '' }))
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
    if (-not $p.WaitForExit($WaitMs)) {
        try { $p.Kill() } catch { }
        Note ('  TIMED OUT after ' + [int]($WaitMs / 1000) + ' s')
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

$disqualify = @('only the installer may run this', 'Connection terminated', 'has not been started',
                'Cannot update every registered account from here', 'Command requires administrator privileges',
                # SYNC.GLOBAL.CATALOG's refusals (15915, its own open failures, 3022)
                'can only be changed by the SD Core server', 'cannot open global.bp.out',
                'Cannot open global catalog directory',
                # DENY.VERBS's refusals (ruling 34)
                'is not a verb name', 'deny.verbs: cannot open',
                # SET.OS.ACCESS's refusals (RELEASE_1.1 165): 10114 (register unchanged) and 12931 (syntax)
                'Unable to change the state of', 'Syntax: set.os.access',
                'Cannot open accounts register', 'does not take',
                # SET.START.DEFAULT's refusals (12877 could not be written, 12875 its syntax) - SOLO 56 group 6
                'The system default start could not be written', 'set.start.default {menu | terminal}',
                # SET.VIEWER's refusals (12854 the test, 12904 not found, 12903 not written, 12895 its syntax) - SOLO 54
                'cannot be used:', 'was not found: give the full path', 'The list of allowed programs could not be written', 'set.viewer {add | remove}',
                # WRITE_INSTALL_DICTS' refusals (and bootstrap.py's Invalid runfile)
                'ERROR OPENING FILE', 'ERROR CANNOT OPEN', 'PROCESS ABORTED', 'READLIST EMPTY',
                'NO DIRECTORY RECORDS FOUND', 'CANNOT READ TRANSFER_FILE', 'Invalid runfile',
                # CD's (sysmsg 2975, 2976) and the ERRGEN trap's warning
                'Compilation error in', 'has no expression', 'is not assigned a value')
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

$script:dictPlaced = $false
$script:dictMadeDir = $false
try {
    $script:leaked = $false
    [void](Invoke-Sd '-stop' '')          # a leftover daemon from an earlier run
    # No verdict of its own: "has not been started" in the NEXT session's
    # output is the disqualifier that says whether this worked.
    [void](Invoke-Sd '-start' '')

    # 28 Sep 26 - RULING 29: the account is always sduser, whatever $User (the
    # Windows user, still used for the report) is.  solo_account takes no name
    # now; the MOVED outcome (SOLO 15 piece 5, a tree copied from another
    # Windows user) is gone with it, so only READY sduser passes.
    $acct = 'sduser'
    $t = Invoke-Sd '-internal RUN gpl.bp solo_account' ''
    Judge 'account created' $t ('^SOLO ACCOUNT READY ' + [regex]::Escape($acct) + ' \S')

    if ($Passwords) {
        $t = Invoke-Sd '-internal RUN gpl.bp solo_password ADMIN' $adminPw
        Judge 'administrator password set' $t '^SOLO PASSWORD SET ADMIN\s*$'
        if ($Global) {
            $t = Invoke-Sd '-internal RUN gpl.bp solo_password GLOBAL' $globalPw
            Judge 'global password set' $t '^SOLO PASSWORD SET GLOBAL\s*$'
        }
        if ($accountPw) {
            $t = Invoke-Sd ('-internal RUN gpl.bp solo_password ACCOUNT ' + $acct) $accountPw
            Judge 'account password set' $t '^SOLO PASSWORD SET ACCOUNT\s*$'
        }
    }

    # 06 Oct 26 - SOLO 37 (owner: removal and reinstall work the same on both ports).  THE RELOAD: the new tree
    # was just made, with a new account, its passwords and the default sd.conf; the user's kept data is in
    # $ReloadFrom, moved aside by the installer.  Three steps, each printing what it did - counts before and after,
    # never just a verdict - and a failure of any is a failed install, not a quiet skip:
    #   1. SD is stopped and the new account's files are REPLACED, whole, by the kept account's (the new account
    #      was made a moment ago, so nothing in it is the user's).
    #   2. The kept sd.conf is tried: put in place, SD started, one session run.  If SD does not accept it (a line the
    #      new release no longer knows, STARTUP= for one) the default is put back and the report says so; the kept
    #      copy in $ReloadFrom is never touched, so it can be corrected and loaded by hand.
    #   3. UPDATE.ACCOUNTS ALL below refreshes the account's VOC, because the kept account may be from an older release.
    if ($ReloadFrom) {
        Note ''
        Note ('--- reload: ' + $ReloadFrom)
        [void](Invoke-Sd '-stop' '')
        $keptAcct = Join-Path $ReloadFrom 'user_accounts\sduser'
        $newAcct = Join-Path $AppDir 'user_accounts\sduser'
        $keptFiles = @(Get-ChildItem -LiteralPath $keptAcct -Recurse -Force -File -ErrorAction SilentlyContinue)
        $keptBytes = ($keptFiles | Measure-Object -Property Length -Sum).Sum
        Note ('  kept account : ' + $keptAcct + '   ' + $keptFiles.Count + ' file(s), ' + [int64]$keptBytes + ' bytes')
        if (-not (Test-Path -LiteralPath $newAcct)) {
            Note ('  FAIL  the new account folder is missing: ' + $newAcct)
            $script:fails += 'reload: account folder'
        }
        else {
            $before = @(Get-ChildItem -LiteralPath $newAcct -Recurse -Force -File -ErrorAction SilentlyContinue).Count
            Note ('  new account  : ' + $newAcct + '   ' + $before + ' file(s) before')
            try {
                Get-ChildItem -LiteralPath $newAcct -Force | Remove-Item -Recurse -Force
                Get-ChildItem -LiteralPath $keptAcct -Force | Copy-Item -Destination $newAcct -Recurse -Force
                $afterFiles = @(Get-ChildItem -LiteralPath $newAcct -Recurse -Force -File -ErrorAction SilentlyContinue)
                $afterBytes = ($afterFiles | Measure-Object -Property Length -Sum).Sum
                Note ('  after        : ' + $afterFiles.Count + ' file(s), ' + [int64]$afterBytes + ' bytes')
                if ($afterFiles.Count -eq $keptFiles.Count -and [int64]$afterBytes -eq [int64]$keptBytes -and $keptFiles.Count -gt 0) {
                    Note '  PASS  reloaded: your saved data (the account''s files copied from the kept folder)'
                }
                else {
                    Note '  FAIL  the new account does not hold what the kept account held'
                    $script:fails += 'reload: account files'
                }
            }
            catch {
                Note ('  FAIL  copying the kept account failed: ' + $_.Exception.Message)
                $script:fails += 'reload: account files'
            }
        }

        # 16 Nov 26 - SOLO 72 (Linux Solo solo-stage.sh RELOAD-KEPT): WHAT SD CORE'S KEEP CYCLE KEEPS IS PUT BACK, each replacing what
        # this install made; SD is stopped.  Only a real folder or file is taken (a reparse point is skipped and named), and each line
        # says what it did.  $cred only when no password was given to this run.
        # RELOAD-KEPT-BEGIN
        $reparse = [IO.FileAttributes]::ReparsePoint
        $keptItems = @(
            @{ Rel = 'sd-tls';                  Dir = $true },
            @{ Rel = 'ssh';                     Dir = $true },
            @{ Rel = 'sdsys\$cred';             Dir = $true },
            @{ Rel = 'sdsys\ai';                Dir = $true },
            @{ Rel = 'sdsys\netlogins';         Dir = $true },
            @{ Rel = 'sdsys\newvoc.mods';       Dir = $true },
            @{ Rel = 'sdsys\voc_removed.saved'; Dir = $true },
            @{ Rel = 'sdsys\$jobs';             Dir = $true },      # 16 Nov 26 - S.247: the jobs' definitions; solo-machine.ps1 gives them their tasks
            @{ Rel = 'sdsys\start.default';     Dir = $false },
            # 21 Nov 26 - SOLO 87 (Linux Solo S.287): the PDF reader allow-list and the deny list.  The deny list only when this install
            # is given none (DENY.VERBS SET below replaces it); the kept PDFs are merged after the documentation step, not copied here.
            @{ Rel = 'sdsys\viewers';           Dir = $false },
            @{ Rel = 'sdsys\solo.policy';       Dir = $true })
        foreach ($k in $keptItems) {
            $src = Join-Path $ReloadFrom $k.Rel
            $dst = Join-Path $AppDir $k.Rel
            if ($k.Rel -eq 'sdsys\$cred' -and $Passwords) { Note '  passwords: set by this install, the kept ones not used'; continue }
            if ($k.Rel -eq 'sdsys\solo.policy' -and $denyVerbs) { Note '  deny list: given to this install, the kept one not used'; continue }
            if (-not (Test-Path -LiteralPath $src)) { Note ('  ' + $k.Rel + ': none was kept'); continue }
            $item = Get-Item -LiteralPath $src -Force
            if (($item.Attributes -band $reparse) -or ($item.PSIsContainer -ne $k.Dir)) {
                Note ('  FAIL  ' + $k.Rel + ': the kept one is a link or not a ' + $(if ($k.Dir) { 'folder' } else { 'file' }) + '; not taken')
                $script:fails += ('reload: ' + $k.Rel)
                continue
            }
            try {
                if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force }
                Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force
                $n1 = @(Get-ChildItem -LiteralPath $src -Recurse -Force -File -ErrorAction SilentlyContinue).Count
                $n2 = @(Get-ChildItem -LiteralPath $dst -Recurse -Force -File -ErrorAction SilentlyContinue).Count
                if (-not $k.Dir) { $n1 = 1; $n2 = [int](Test-Path -LiteralPath $dst -PathType Leaf) }
                if ($n1 -eq $n2) { Note ('  PASS  ' + $(if ($k.Rel -eq 'sdsys\$cred') { 'passwords' } else { $k.Rel }) + ': reloaded (' + $n2 + ' file(s))') }
                else { Note ('  FAIL  ' + $k.Rel + ': ' + $n1 + ' file(s) kept, ' + $n2 + ' copied'); $script:fails += ('reload: ' + $k.Rel) }
            }
            catch { Note ('  FAIL  ' + $k.Rel + ': ' + $_.Exception.Message); $script:fails += ('reload: ' + $k.Rel) }
        }
        # The audit trail is JOINED: the kept lines, then the lines this install wrote.  Rotated copies go back as they were.
        $keptAudit = Join-Path $ReloadFrom 'sdsys\audit'
        $newAudit = Join-Path $sdsys 'audit'
        if ((Test-Path -LiteralPath $keptAudit -PathType Leaf) -and -not ((Get-Item -LiteralPath $keptAudit -Force).Attributes -band $reparse)) {
            try {
                $joined = [IO.File]::ReadAllBytes($keptAudit)
                $mine = New-Object byte[] 0
                if (Test-Path -LiteralPath $newAudit) { $mine = [IO.File]::ReadAllBytes($newAudit) }
                $ms = New-Object IO.MemoryStream
                $ms.Write($joined, 0, $joined.Length)
                $ms.Write($mine, 0, $mine.Length)
                [IO.File]::WriteAllBytes($newAudit, $ms.ToArray())
                Note ('  PASS  audit trail: reloaded (' + $joined.Length + ' kept bytes, then ' + $mine.Length + ' of this install''s)')
            }
            catch { Note ('  FAIL  audit trail: ' + $_.Exception.Message); $script:fails += 'reload: audit' }
        }
        else { Note '  audit trail: none was kept' }
        foreach ($r in @(Get-ChildItem -LiteralPath (Join-Path $ReloadFrom 'sdsys') -Filter 'audit.*' -Force -File -ErrorAction SilentlyContinue)) {
            if ($r.Attributes -band $reparse) { continue }
            Copy-Item -LiteralPath $r.FullName -Destination (Join-Path $sdsys $r.Name) -Force
            Note ('  rotated audit copy reloaded: ' + $r.Name)
        }
        # RELOAD-KEPT-END

        # 20 Nov 26 - RELEASE_1.1 367 (Linux Solo b5219e1 solo-stage.sh REGISTER-CARRY, S.278; the owner, chat 20 Nov, asked whether Keep
        # should restore what the administrator had turned on: "yes"; his rule of 13 Nov: an upgrade does not shut what the administrator
        # opened, delivered-closed governs a FRESH install).  The kept register record sdsys\accounts\sduser carries the administrator's
        # switches; this install made its own record (its path, group and what it asked this time), so only the SWITCHES are read back,
        # and only ever TO yes: fields 7-12 (SH, OS.EXECUTE, and four that are blank in Solo), 15 NET, 18 PINS, 19 RECOVERY, 20-21 MCP,
        # 22 XFER, 23 JOBS, 24 STORED.ANY become yes where the kept record had yes; field 17 (the tiles that are off) is taken when this
        # install's is blank.  Nothing is turned off.  Not carried: the path, description, group, suspension, the start word
        # (start.default is reloaded above) and the shared account's 13 and 14.  SD is stopped, so the record is a file: CR LF between
        # fields as SD writes it on Windows (read: CR LF or LF), written back the same, its last line end as it was.  A record that cannot
        # be read or written leaves the install as delivered (closed) and says so.  The line "ACCOUNT SWITCHES : ..." goes to the finish
        # page (sd-solo.iss SwitchesNote).
        # REGISTER-CARRY-BEGIN
        function Invoke-RegisterCarry([string]$keptRec, [string]$newRec) {
            $rp = [IO.FileAttributes]::ReparsePoint
            if (-not (Test-Path -LiteralPath $keptRec -PathType Leaf) -or ((Get-Item -LiteralPath $keptRec -Force).Attributes -band $rp)) { return 'none was saved' }
            if (-not (Test-Path -LiteralPath $newRec -PathType Leaf) -or ((Get-Item -LiteralPath $newRec -Force).Attributes -band $rp)) {
                return 'NOT carried (the new install has no register record), the switches are as delivered'
            }
            try {
                $latin = [Text.Encoding]::GetEncoding(28591)                  # bytes as they are: no BOM, no re-encoding
                $k = @([IO.File]::ReadAllText($keptRec, $latin) -split "`r?`n")
                $text = [IO.File]::ReadAllText($newRec, $latin)
                $endNl = $text.EndsWith("`n")
                $f = New-Object Collections.Generic.List[string]
                foreach ($x in ($text -split "`r?`n")) { $f.Add($x) }
                if ($endNl -and $f.Count -gt 0) { $f.RemoveAt($f.Count - 1) }  # the empty piece after the last line end
                $changed = 0
                foreach ($j in @(7, 8, 9, 10, 11, 12, 15, 18, 19, 20, 21, 22, 23, 24)) {
                    $kv = if ($j -le $k.Count) { $k[$j - 1] } else { '' }
                    if ($kv -ieq 'yes') {
                        while ($f.Count -lt $j) { $f.Add('') }
                        if ($f[$j - 1] -ine 'yes') { $f[$j - 1] = 'yes'; $changed++ }
                    }
                }
                $k17 = if ($k.Count -ge 17) { $k[16] } else { '' }
                if ($k17 -ne '') {
                    while ($f.Count -lt 17) { $f.Add('') }
                    if ($f[16] -eq '') { $f[16] = $k17; $changed++ }
                }
                if ($changed -gt 0) {
                    $out = [string]::Join("`r`n", $f.ToArray())
                    if ($endNl) { $out += "`r`n" }
                    [IO.File]::WriteAllText($newRec, $out, $latin)
                }
                return ([string]$changed + ' switch(es) carried from the kept record')
            }
            catch { return ('NOT carried (the record could not be read or written: ' + $_.Exception.Message + '), the switches are as delivered') }
        }
        $carried = Invoke-RegisterCarry (Join-Path $ReloadFrom 'sdsys\accounts\sduser') (Join-Path $sdsys 'accounts\sduser')
        Note ('  register: ' + $carried)
        Note ('ACCOUNT SWITCHES : ' + $carried)
        # REGISTER-CARRY-END

        $keptConf = Join-Path $ReloadFrom 'sd.conf'
        $conf = Join-Path $AppDir 'sd.conf'
        $defaultConf = Join-Path $work 'sd.conf.default'
        if (-not (Test-Path -LiteralPath $keptConf)) {
            Note '  configuration: none was saved (no sd.conf in the kept folder), the default was kept'
            [void](Invoke-Sd '-start' '')
        }
        elseif (-not (Test-Path -LiteralPath $conf)) {
            Note ('  FAIL  there is no default sd.conf to put back at ' + $conf)
            $script:fails += 'reload: sd.conf'
            [void](Invoke-Sd '-start' '')
        }
        else {
            Copy-Item -LiteralPath $conf -Destination $defaultConf -Force
            Copy-Item -LiteralPath $keptConf -Destination $conf -Force
            # 9 Nov 26 - RELEASE_1.1 197: a kept sd.conf can name a parameter SD no longer has, and SD refuses to start on
            # one.  Only the copy being tried is changed.  The same list as RetiredConfNames in sd-solo.iss.
            $retiredConf = 'INVCASE CODEPAGE EXCLREM RINGWAIT TXCHAR APILOGIN CREATUSR JNLDIR JNLMODE GDI FIXUSERS PORTMAP FILERULE'
            $retiredRx = '^(' + (($retiredConf -split ' ') -join '|') + ')='
            $confLines = @(Get-Content -LiteralPath $conf)
            $confKept = @($confLines | Where-Object { $_ -cnotmatch $retiredRx })
            if ($confKept.Count -ne $confLines.Count) {
                [System.IO.File]::WriteAllLines($conf, [string[]]$confKept)
                Note ('  configuration: ' + ($confLines.Count - $confKept.Count) + ' retired parameter line(s) taken out of the copy being tried')
            }
            # 17 Nov 26 - four-version audit round 4 (P-4944), Linux Solo's default_screentheme, as sd-solo.iss UpgradeScreenTheme: a
            # kept sd.conf with no SCREENTHEME line gets SCREENTHEME=paper after its [sd] line; one that has the line is left as it is.
            $confLines = @(Get-Content -LiteralPath $conf)
            if (-not @($confLines | Where-Object { $_ -cmatch '^SCREENTHEME=' }).Count) {
                $at = -1
                for ($i = 0; $i -lt $confLines.Count; $i++) { if ($confLines[$i] -cmatch '^\[sd\]') { $at = $i; break } }
                if ($at -lt 0) { Note '  configuration: the kept sd.conf has no [sd] section, SCREENTHEME was not added' }
                else {
                    $themed = @($confLines[0..$at]) + 'SCREENTHEME=paper'
                    if ($at + 1 -lt $confLines.Count) { $themed += @($confLines[($at + 1)..($confLines.Count - 1)]) }
                    [System.IO.File]::WriteAllLines($conf, [string[]]$themed)
                    Note '  configuration: SCREENTHEME=paper added to the copy being tried (the kept file had no SCREENTHEME line)'
                }
            }
            # SOLO 33: THE KEPT sd.conf MAY CARRY AN ACTIVE APIPORT, and this unelevated step starts SD before the
            # firewall rule exists - the alert the installer was changed to avoid.  So the API line is switched OFF in
            # the copy being tried; the elevated step switches it ON afterwards only if the API box was ticked.
            $lp = Join-Path $AppDir 'solo-api-listener.ps1'
            $lo = & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $lp -Off -ConfPath $conf 2>&1
            $lcode = $LASTEXITCODE
            foreach ($x in @($lo)) { Note ('  | ' + $x) }
            Note ('  solo-api-listener.ps1 -Off exit ' + $lcode)
            if ($lcode -ne 0) { Note '  FAIL  the kept sd.conf could not be made listener-free'; $script:fails += 'reload: sd.conf API line' }
            [void](Invoke-Sd '-start' '')
            $t = Invoke-Sd '-internal RUN gpl.bp solo_account' ''
            $accepted = $t -match ('(?m)^SOLO ACCOUNT READY ' + [regex]::Escape($acct) + ' \S')
            if ($accepted) {
                Note '  PASS  configuration: reloaded (SD started on the kept sd.conf and ran a session)'
            }
            else {
                $reason = (($t -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
                [void](Invoke-Sd '-stop' '')
                Copy-Item -LiteralPath $defaultConf -Destination $conf -Force
                [void](Invoke-Sd '-start' '')
                Note ('  configuration: NOT accepted by SD, the default was kept (' + $reason + ')')
                Note ('  the kept copy is untouched: ' + $keptConf)
            }
        }
    }

    # 28 Sep 26 - RULING 34: the verbs denied to the local user, from the
    # control file, on a new tree only (sd-solo.iss passes none otherwise).
    # DENY.VERBS SET normalises each name and drops ADMIN/OFF/QUIT/LO; a name
    # it refuses fails the step, so a typo in the control file is seen.
    if ($denyVerbs) {
        $t = Invoke-Sd ('-internal DENY.VERBS SET ' + ($denyVerbs -replace ' ', '')) ''
        Judge 'denied verbs set' $t '(?m)^DENY\.VERBS \d+: '
    }

    # 17 Nov 26 - P-7371, Linux Solo's solo-ssh.sh key-add: the control file's public key, one line in Solo's own key file.  A line
    # already there is not added twice.  Judged on the line being in the file afterwards, read back.
    if ($sshKeyLine) {
        $akDir = Join-Path $AppDir 'ssh'
        $ak = Join-Path $akDir 'authorized_keys'
        if (-not (Test-Path -LiteralPath $akDir)) { New-Item -ItemType Directory -Path $akDir | Out-Null }
        $akLines = @()
        if (Test-Path -LiteralPath $ak) { $akLines = @([IO.File]::ReadAllLines($ak)) }
        Note ('  ssh key: ' + $ak + ' held ' + $akLines.Count + ' line(s) before')
        if ($akLines -ccontains $sshKeyLine) { Note '  ssh key: already present, nothing added' }
        else { [IO.File]::WriteAllLines($ak, [string[]]($akLines + $sshKeyLine), (New-Object Text.UTF8Encoding($false))) }
        $akAfter = @([IO.File]::ReadAllLines($ak))
        Note ('  ssh key: ' + $akAfter.Count + ' line(s) after; key type ' + ($sshKeyLine -split '\s+')[0])
        if ($akAfter -ccontains $sshKeyLine) { Note '  PASS  the ssh public key is in Solo''s key file' }
        else { Note '  FAIL  the ssh public key is in Solo''s key file'; $script:fails += 'ssh public key added' }
    }

    # 12 Nov 26 - SOLO 56 group 6, THE START QUESTION.  terminal is written with the verb (the audit line is SET.START.DEFAULT's own)
    # and judged twice: the verb's success words (12876, or 12878 when it already said so), and the file it writes read back.
    if ($startAt -eq 'terminal') {
        $t = Invoke-Sd '-internal SET.START.DEFAULT TERMINAL' ''
        Judge 'new sessions start at the command prompt (the verb)' $t '(?m)^(Accounts with no start setting of their own start at: terminal|The system default start is already terminal; nothing changed)\s*$'
        $sdFile = Join-Path $sdsys 'start.default'
        $first = ''
        if (Test-Path -LiteralPath $sdFile) { $first = ("" + (@(Get-Content -LiteralPath $sdFile -TotalCount 1) | Select-Object -First 1)).Trim().ToLowerInvariant() }
        Note ('  start.default: "' + $first + '"   (' + $sdFile + ')')
        if ($first -eq 'terminal') { Note '  PASS  start.default says terminal' }
        else { Note '  FAIL  start.default says terminal'; $script:fails += 'start.default says terminal' }
    }

    # 16 Nov 26 - SOLO 54, THE PDF READER.  SET.VIEWER ADD PDF <name>: it finds the program in App Paths and tests it; judged on its
    # success words (12896, or 12898 when it was already allowed), and the list it writes read back.
    if ($viewer) {
        $t = Invoke-Sd ('-internal SET.VIEWER ADD PDF ' + $viewer) ''
        Judge ('pdf reader ' + $viewer + ' allowed (the verb)') $t '(?m)^The program \S.* (is now|was already) allowed for pdf'
        $vf = Join-Path $sdsys 'viewers'
        $vl = @()
        if (Test-Path -LiteralPath $vf) { $vl = @(Get-Content -LiteralPath $vf | Where-Object { $_ -match '^pdf \S' }) }
        Note ('  viewers: ' + $vl.Count + ' pdf line(s) in ' + $vf + $(if ($vl.Count) { ': ' + ($vl -join ' | ') } else { '' }))
        if ($vl.Count -gt 0) { Note '  PASS  the list holds a pdf reader' }
        else { Note '  FAIL  the list holds a pdf reader'; $script:fails += 'pdf reader in the list' }
    }

    # 20 Oct 26 - RELEASE_1.1 165, THE OS SWITCH.  The shell and OS access are two switches of the one account, fields 7 and 8 of the
    # register record accounts/sduser, OFF as delivered.  What the installer was told to turn on is turned on here with the verb (an
    # internal session is an administrator, and SET.OS.ACCESS is the one place the fields are written), and the state is READ BACK
    # every time, on every install and upgrade: that line is what the summary shows, and it proves the verb works on this tree.
    # SET.OS.ACCESS ... ON of a switch that is already on answers "already had that access", which is a pass.  The sd-solo session
    # that signs in later loads the switches at ITS sign-on, so nothing running is affected.
    if (($osAccess -eq 'sh') -or ($osAccess -eq 'both')) {
        $t = Invoke-Sd '-internal SET.OS.ACCESS SH ON' ''
        Judge 'shell switched on' $t '(?m)^(Account sduser has SH yes, OS\.EXECUTE (yes|no)|sduser already had that access; nothing changed)\s*$'
    }
    if (($osAccess -eq 'os') -or ($osAccess -eq 'both')) {
        $t = Invoke-Sd '-internal SET.OS.ACCESS OS ON' ''
        Judge 'OS access switched on' $t '(?m)^(Account sduser has SH (yes|no), OS\.EXECUTE yes|sduser already had that access; nothing changed)\s*$'
    }
    $t = Invoke-Sd '-internal SET.OS.ACCESS' ''
    Judge 'OS access switches read back' $t '(?m)^Account sduser has SH (yes|no), OS\.EXECUTE (yes|no)\s*$'
    $osLine = @(($t -split "`n") | Where-Object { $_ -match '^Account sduser has SH (yes|no), OS\.EXECUTE (yes|no)\s*$' }) | Select-Object -Last 1
    Note ('  os access now: ' + $osLine)

    if ($Upgrade) {
        # SDSYS's dictionaries are made by the bootstrap and named in no
        # stage.py list, so upgrade.iss never reaches them.  Merge the shipped
        # records (WRITE_INSTALL_DICTS writes per record, deletes nothing),
        # then THIRD.COMPILE, as bootstrap.py does.  The placed copy is removed
        # in the finally below whatever happens: the data tree keeps no build
        # input.
        $script:dictMadeDir = -not (Test-Path -LiteralPath $dictDir)
        if (Test-Path -LiteralPath $dictDst) {
            Note ('  ' + $dictDst + ' was left by an earlier run; replacing it')
            Remove-Item -LiteralPath $dictDst -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $dictDir | Out-Null
        Copy-Item -LiteralPath $dictSrc -Destination $dictDst -Recurse -Force
        $script:dictPlaced = $true
        $placedN = @(Get-ChildItem -LiteralPath $dictDst -File).Count
        Note ('  placed ' + $dictDst + ': ' + $placedN + ' of ' + $dictWanted + ' record(s)')

        # NO.PAGE: without it the program pages and waits for a key.
        $t = Invoke-Sd '-internal RUN gpl.bp WRITE_INSTALL_DICTS NO.PAGE' ''
        $moved = @(($t -split "`n") | Where-Object { $_ -match '^\s*DICTIONARY:\s' }).Count
        Note ('  ' + $moved + ' DICTIONARY line(s), ' + $dictWanted + ' record(s) shipped')
        Judge 'dictionaries written' $t '^\s*COMPLETE\s*$'
        if ($placedN -ne $dictWanted -or $moved -ne $dictWanted) {
            Note ('  FAIL  dictionary count (placed ' + $placedN + ', written ' + $moved + ', shipped ' + $dictWanted + ')')
            $script:fails += 'dictionary count'
        }

        # THIRD.COMPILE is SDSYS's paragraph of CD (COMPILE.DICT) commands.  CD
        # prints "Compiling <item>" per I-type and has no summary line, so the
        # anchor is at least one of those, and its failure wordings disqualify.
        $t = Invoke-Sd '-internal THIRD.COMPILE' ''
        $compiled = @(($t -split "`n") | Where-Object { $_ -match '^\s*Compiling\s+\S' }).Count
        Note ('  ' + $compiled + ' Compiling line(s)')
        Judge 'dictionaries compiled' $t '^\s*Compiling\s+\S'
        $badErr = @(($t -split "`n") | Where-Object { $_.Trim() -match 'error\(s\)$' -and $_.Trim() -notmatch '^0 ' })
        if ($badErr.Count) {
            Note ('  FAIL  THIRD.COMPILE reported: ' + ($badErr -join '; '))
            $script:fails += 'dictionary compile errors'
        }

        # message 10171, "N account(s) had their VOC updated" - the same
        # anchor the retired upgrade-voc.ps1 used.  "0 account(s)" is refused
        # too: a walk that opened the register and visited nothing is not a
        # pass on a tree that this script just confirmed has an account in it.
        $t = Invoke-Sd '-internal UPDATE.ACCOUNTS ALL' ''
        Judge 'accounts VOC refreshed' $t '(?m)^[1-9]\d* account\(s\) had their VOC updated'
    }
    elseif ($ReloadFrom) {
        # SOLO 37: the reloaded account's VOC predates this release's templates, as after an upgrade.  The walk
        # counts every account it WRITES, so the one account gives 1 and the anchor is the same as above.
        $t = Invoke-Sd '-internal UPDATE.ACCOUNTS ALL' ''
        Judge 'reloaded account VOC refreshed' $t '(?m)^[1-9]\d* account\(s\) had their VOC updated'
    }

    # 16 Nov 26 - RELEASE_1.1 335 (Linux Solo S.261 fb685f0; the owner: "just include examples.bp in the single account, no need to load
    # or remove").  THE EXAMPLE PROGRAMS: solo_examples gives sduser its examples.bp from sdsys\examples, compiled; a shipped program is
    # replaced and one the user added is kept.  OUTSIDE every if: a new tree, a reload of kept data and an upgrade all reach it, so an
    # existing account gains the file on upgrade (Linux Solo's stage runs it after a new account and a reload only).  After the reload
    # and UPDATE.ACCOUNTS, before DELETE VOC gpl.bp (the last RUN gpl.bp step stays the last).  Judged on its own last line with
    # 0 failed; anything else is a WARNING in the report and the install goes on, as on Linux Solo.
    # EXAMPLES-BEGIN
    $t = Invoke-Sd '-internal RUN gpl.bp solo_examples' '' 600000
    $exOk = [regex]::IsMatch($t, '(?m)^solo_examples: examples\.bp ready: \d+ new, \d+ changed, \d+ the same, compiled \d+ of \d+, 0 failed\s*$')
    $exBad = @($disqualify | Where-Object { $t.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    if ($exOk -and $exBad.Count -eq 0) { Note '  PASS  example programs in examples.bp' }
    else { Note '  WARNING  the example programs were not put into the account (solo_examples did not report 0 failed); run the installer again over this installation (an upgrade) to try again' }
    # EXAMPLES-END

    # 18 Nov 26 - four-version audit P-5661 (Linux Solo's upgrade, SD Core for Windows' upgrade-nocase.ps1): AN UPGRADE OVER A KEPT TREE
    # CONVERTS THE OLDER TREE'S FILES TO CASE-INSENSITIVE RECORD IDS.  gpl.bp/upgrade_nocase scans each file read only for two ids that
    # differ only by case, converts only a file proven clean, and leaves and NAMES a file that holds such a pair, an indexed file and a
    # file outside its account.  Its whole output goes to <Solo folder>\nocase-upgrade.log.  After the compile and before DELETE VOC
    # gpl.bp below (RUN gpl.bp needs that pointer); the marker is written by Invoke-Sd, as for every internal step.  Judged as Core's
    # script judges it: COMPLETE is the success line; "could not be read or rebuilt" (10183), no COMPLETE, or a file left
    # (10178, 12041, 15993, 10186) is a WARNING naming the log, not a failure - the files are safe as they are (round 6: Linux Solo
    # warns and goes on).  Up to 30 minutes.
    if ($Upgrade) {
        $t = Invoke-Sd '-internal RUN gpl.bp upgrade_nocase NO.PAGE' '' 1800000
        $nocaseLog = Join-Path $AppDir 'nocase-upgrade.log'
        try { [IO.File]::WriteAllText($nocaseLog, ('=== upgrade_nocase ' + (Get-Date -Format 's') + "`r`n" + $t + "`r`n"), (New-Object Text.UTF8Encoding($false))) }
        catch { Note ('  could not write ' + $nocaseLog + ': ' + $_.Exception.Message) }
        $ncComplete = [regex]::IsMatch($t, '(?m)^\s*COMPLETE\s*$')
        $ncTrouble = $t -match 'could not be read or rebuilt'
        $ncLeft = ($t -match 'WARNING:\s+\d+\s+file\(s\)\s+hold\s+\d+\s+record id') -or ($t -match '\d+\s+file\(s\)\s+named by an account''s VOC lie') -or
                  ($t -match '\d+\s+indexed file\(s\)\s+were left')
        $ncBad = @($disqualify | Where-Object { $t.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
        Note ('  nocase: complete=' + $ncComplete + ' trouble=' + $ncTrouble + ' left=' + $ncLeft + '   (the report: ' + $nocaseLog + ')')
        # 18 Nov 26 - four-version audit round 6 (Linux T0754): an unfinished conversion is a WARNING and the install goes on, as Linux
        # Solo's solo-stage.sh:333 ("the case-insensitive conversion of the kept account did not finish"); the files are safe as they are.
        if (-not $ncComplete -or $ncTrouble -or $ncBad.Count -gt 0) {
            Note ('  WARNING  the case-insensitive conversion did not finish; the files are as they were (' + $nocaseLog + ' has its output)')
        }
        elseif ($ncLeft) { Note ('  WARNING  some files were left with case-sensitive record ids, each named in ' + $nocaseLog + '; convert each with configure.file no.case') }
        else { Note '  PASS  case-insensitive record ids (every file converted)' }
    }

    # 28 Sep 26 - RULING 26: NO SYSTEM BASIC SOURCE IN THE INSTALLED TREE.  The
    # gpl.bp directory no longer ships (stage.py SDSYS_BUILD_SEED; an upgrade
    # removes an older copy, SDSYS_RETIRED), and this removes SDSYS's VOC record
    # for it, which the bootstrap made from voc_template and no upgrade reaches
    # (SDSYS's VOC is on no stage.py list).  Every install and upgrade, so the
    # anchor accepts both outcomes that leave the record gone: DELETE's 3221
    # after a delete, or its 2108 when an earlier run already did it.  RUN
    # gpl.bp <prog> above never used this record - it opens gpl.bp.out by its
    # own VOC name (cproc:2305-2313).  Last, after every RUN gpl.bp step.
    $t = Invoke-Sd '-internal DELETE VOC gpl.bp' ''
    Judge 'gpl.bp source pointer removed from the VOC' $t "(?m)^(1 record\(s\) deleted|Record 'gpl\.bp' not found)\s*$"
    # 9 Nov 26 - FIRST.COMPILE and SECOND.COMPILE go too (Linux e3490a7f, S.198): both
    # compile gpl.bp, so with no source they can only fail.  THIRD.COMPILE stays (it
    # compiles dictionary I-types).  Every install and upgrade, both outcomes accepted.
    $t = Invoke-Sd '-internal DELETE VOC first.compile' ''
    Judge 'first.compile removed from the VOC' $t "(?mi)^(1 record\(s\) deleted|Record 'first\.compile' not found)\s*$"
    $t = Invoke-Sd '-internal DELETE VOC second.compile' ''
    Judge 'second.compile removed from the VOC' $t "(?mi)^(1 record\(s\) deleted|Record 'second\.compile' not found)\s*$"

    # 28 Sep 26 - RULING 33: the global catalogue's server programs come from
    # GLOBAL.BP.OUT.  An upgrade replaces gcat and drops them, and the owner
    # ruled they are "cataloged at installation", so every install and upgrade
    # re-runs the sync.  With no global password it says so and succeeds.  The anchor is the
    # verb's own last line with 0 refused; a refused object fails the step.
    $t = Invoke-Sd '-internal SYNC.GLOBAL.CATALOG' ''
    Judge 'global catalog matches GLOBAL.BP.OUT' $t '(?m)^SYNC GLOBAL CATALOG DONE \d+ cataloged \d+ removed 0 refused\s*$'

    # 26 Oct 26 - the context help (Core RELEASE_1.1 184).  The text under sdsys\helptext becomes the records of the file context.help in the
    # system directory; every install and upgrade, because an upgrade replaces the text.  The anchor is the verb's own result line (message 12844).
    $t = Invoke-Sd '-internal LOAD.HELP' ''
    Judge 'context help loaded into context.help' $t '(?m)^Context help: \d+ new, \d+ changed, \d+ already current, \d+ added by the administrator and kept\s*$'

    # 13 Nov 26 - THE DOCUMENTATION BESIDE THE INSTALLER (RELEASE_1.1 252, P-25; Linux Solo S.216's CHANGES-DOC and MANUALS-PDF, from SD
    # Core's).  Solo has no shared account, so the destination is sdsys\pdf, which sd-solo.iss's [Dirs] makes.  The changes document
    # (sd-core-solo-for-windows-<version>-changes.pdf / .html / .md) is copied as it is; the pdf folder is handed to DOCS.INSTALL, which
    # judges every file.  NOTHING BESIDE THE INSTALLER IS NOT A FAILURE (a build folder has neither): it is noted.  A copy that fails, or
    # DOCS.INSTALL without its success line with nothing skipped (message 12727), is.
    $pdfDir = Join-Path $sdsys 'pdf'
    if (-not $SourceDir -or -not (Test-Path -LiteralPath $SourceDir)) {
        Note '  NOTE  no installer folder was given, so no documentation was looked for'
    } elseif (-not (Test-Path -LiteralPath $pdfDir)) {
        Note ('  FAIL  documentation: there is no ' + $pdfDir)
        $fails += 'documentation directory'
    } else {
        $seen = 0; $copied = 0
        foreach ($pat in @('sd-core-solo-for-windows-*-changes.pdf', 'sd-core-solo-for-windows-*-changes.html', 'sd-core-solo-for-windows-*-changes.md')) {
            foreach ($f in @(Get-ChildItem -LiteralPath $SourceDir -Filter $pat -File -ErrorAction SilentlyContinue)) {
                if ($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { Note ('  NOTE  ' + $f.Name + ' is a link and was not copied'); continue }
                $seen++
                if ($f.Name -cnotmatch '^[a-z0-9][a-z0-9._-]{0,79}$') { Note ('  NOTE  ' + $f.Name + ' was not copied: the name must be lower case letters, digits and . _ -'); continue }
                $to = Join-Path $pdfDir $f.Name
                try { Copy-Item -LiteralPath $f.FullName -Destination $to -Force -ErrorAction Stop } catch { }
                if (Test-Path -LiteralPath $to) { $copied++ } else { Note ('  FAIL  ' + $f.Name + ' was not copied into ' + $pdfDir); $fails += 'changes document' }
            }
        }
        if ($seen -eq 0) { Note ('  NOTE  no changes document beside the installer (' + $SourceDir + ')') }
        else { Note ('  PASS  changes document: ' + $copied + ' of ' + $seen + ' file(s) copied into ' + $pdfDir) }

        $srcPdf = Join-Path $SourceDir 'pdf'
        $nPdf = @(Get-ChildItem -LiteralPath $srcPdf -Filter '*.pdf' -File -ErrorAction SilentlyContinue).Count
        if ($nPdf -eq 0) {
            Note ('  NOTE  no documentation PDFs beside the installer (' + $srcPdf + '); the administrator can add them later:  docs.install <folder of PDFs>')
        } else {
            $t = Invoke-Sd ('-internal DOCS.INSTALL "' + $srcPdf + '"') ''
            Judge ('documentation PDFs (' + $nPdf + ') installed into ' + $pdfDir) $t '(?m)^Copied \d+ document\(s\) into the pdf directory; skipped 0\s*$'
        }
    }

    # 21 Nov 26 - SOLO 87 (Linux Solo S.287, solo-stage.sh): THE KEPT DOCUMENTATION PDFs ARE ADDED BESIDE THE RELEASE'S, NEVER OVER THEM.
    # A reload of kept data (Keep keeps sdsys\pdf) puts back each plain file of the kept folder that this install did not make; a file the
    # release shipped under the same name stays the release's.  After the documentation step above, so the release's are already here.
    # Only a plain, lower case named file (docs.install's own rule) is taken; a link or any other name is named and left.
    if ($ReloadFrom) {
        $keptPdf = Join-Path $ReloadFrom 'sdsys\pdf'
        if (-not (Test-Path -LiteralPath $keptPdf -PathType Container)) { Note '  kept documentation: none was kept' }
        elseif (-not (Test-Path -LiteralPath $pdfDir -PathType Container)) { Note ('  FAIL  kept documentation: there is no ' + $pdfDir); $fails += 'kept documentation' }
        else {
            $added = 0; $already = 0; $refused = 0
            foreach ($f in @(Get-ChildItem -LiteralPath $keptPdf -Force -File -ErrorAction SilentlyContinue)) {
                $to = Join-Path $pdfDir $f.Name
                if (($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or ($f.Name -cnotmatch '^[a-z0-9][a-z0-9._-]{0,79}$')) {
                    $refused++; Note ('  NOTE  kept documentation ' + $f.Name + ' was not taken: a link, or a name outside lower case letters, digits and . _ -'); continue
                }
                if (Test-Path -LiteralPath $to) { $already++; continue }
                try { Copy-Item -LiteralPath $f.FullName -Destination $to -ErrorAction Stop } catch { }
                if (Test-Path -LiteralPath $to) { $added++ } else { Note ('  FAIL  kept documentation ' + $f.Name + ' was not copied into ' + $pdfDir); $fails += 'kept documentation' }
            }
            Note ('  PASS  kept documentation: ' + $added + ' file(s) added beside the release''s, ' + $already + ' already there (the release''s are kept), ' + $refused + ' not taken')
        }
    }

    # 17 Nov 26 - four-version audit P-2914/P-3613 (Linux Solo DOCS-CORPUS): the pages the AI line draws on came with the tree
    # (stage.py DOCS_CORPUS, sdsys\docs\user and docs\admin).  Counted for the report only: none is not a failure, as on Linux.
    $nUser = @(Get-ChildItem -LiteralPath (Join-Path $sdsys 'docs\user') -Filter '*.md' -File -ErrorAction SilentlyContinue).Count
    $nAdmin = @(Get-ChildItem -LiteralPath (Join-Path $sdsys 'docs\admin') -Filter '*.md' -File -ErrorAction SilentlyContinue).Count
    if ($nUser -gt 0) { Note ('  PASS  documentation for the AI line: ' + $nUser + ' user and ' + $nAdmin + ' administrator page(s) in ' + (Join-Path $sdsys 'docs')) }
    else { Note ('  NOTE  no documentation for the AI line in ' + (Join-Path $sdsys 'docs\user') + '; it will answer without passages of it') }

    # 17 Nov 26 - four-version audit P-3791 (Linux Solo installsdsolo.sh, the self-check's last step): THE INTERNAL DOOR IS SHUT
    # WHEN THE INSTALL ENDS.  Every -internal step above wrote a marker that LOGIN consumed; with none left, "sd -internal" must be
    # refused ("Connection terminated", login's terminate.connection) and leave no marker behind.  Admitted is a failed install.
    # The anchor for the failure is WHO's own line for the SDSYS account; the success anchor is the refusal's whole line.
    $markerPath = Join-Path $sdsys '$internal'
    if (-not (Remove-SdInternalMarker -SdsysDir $sdsys)) {
        Note ('  FAIL  internal door: a marker at ' + $markerPath + ' could not be removed before the check')
        $fails += 'internal door check'
    } else {
        $t = Invoke-Sd '-internal WHO' '' -NoMarker
        if ($t -match '(?mi)^\d+\s+sdsys\s*$') { Note '  FAIL  sd -internal was admitted with no marker: the internal door is OPEN'; $fails += 'internal door OPEN' }
        elseif ($t -notmatch '(?m)^Connection terminated\s*$') { Note "  FAIL  sd -internal did not end with 'Connection terminated'"; $fails += 'internal door check' }
        elseif (Test-Path -LiteralPath $markerPath) { Note ('  FAIL  a marker was left at ' + $markerPath); $fails += 'internal marker left' }
        else { Note '  PASS  sd -internal is closed' }
    }
}
catch {
    Note ('ERROR        : ' + $_.Exception.Message)
    $fails += 'exception'
}
finally {
    $adminPw = $null; $globalPw = $null; $accountPw = $null; $secrets = $null
    if ($script:dictPlaced) {
        try {
            Remove-Item -LiteralPath $dictDst -Recurse -Force -ErrorAction Stop
            if ($script:dictMadeDir) { Remove-Item -LiteralPath $dictDir -Recurse -Force -ErrorAction Stop }
            Note ('removed      : ' + $(if ($script:dictMadeDir) { $dictDir } else { $dictDst }))
        }
        catch {
            Note ('COULD NOT REMOVE ' + $dictDst + ' - delete it by hand')
            $fails += 'dictionary cleanup'
        }
    }
    [void](Invoke-Sd '-stop' '')
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Note ''
if ($fails.Count -eq 0) { Note 'VERDICT      : PASS - every step printed its success line'; $code = 0 }
else { Note ('VERDICT      : FAIL - ' + ($fails -join ', ')); $code = 1 }
Save-Report
exit $code
