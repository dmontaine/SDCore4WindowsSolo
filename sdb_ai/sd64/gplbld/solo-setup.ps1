# solo-setup.ps1 - SD Core Solo's unelevated install steps.  SOLO 8.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File solo-setup.ps1
#       -AppDir <install dir> -User <windows user name> -Report <file>
#       [-Passwords] [-Global] [-Upgrade] [-ReloadFrom <dir>]
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
#      account's VOC is refreshed
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
#   5. sd -internal DELETE VOC gpl.bp   (ruling 26 - no system BASIC source
#      in the installed tree; every install and upgrade), then
#      sd -internal SYNC.GLOBAL.CATALOG  (ruling 33 - the server's programs in
#      GLOBAL.BP.OUT back into the global catalogue after gcat is replaced)
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
    [string]$ReloadFrom = ''
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

# The null cases, refused out loud.
$refuse = @()
if (-not $AppDir -or -not (Test-Path -LiteralPath $sdexe)) { $refuse += 'no sd-solo.exe under the app dir' }
if (-not (Test-Path -LiteralPath $sdsys)) { $refuse += 'no sdsys under the app dir' }
if (-not $User) { $refuse += 'no user name' }
if ($Passwords -and -not $adminPw) { $refuse += '-Passwords without an administrator password' }
if ($Global -and -not $Passwords) { $refuse += '-Global without -Passwords' }
if ($Global -and -not $globalPw) { $refuse += '-Global without a global password' }
# SOLO 37: a reload goes into a NEW tree, from a folder that holds the kept account.
if ($ReloadFrom -and -not $Passwords) { $refuse += '-ReloadFrom without -Passwords (it is for a new tree)' }
if ($ReloadFrom -and $Upgrade) { $refuse += '-ReloadFrom with -Upgrade (an upgrade already keeps its data)' }
if ($ReloadFrom -and -not (Test-Path -LiteralPath (Join-Path $ReloadFrom 'user_accounts\sduser'))) { $refuse += ('-ReloadFrom ' + $ReloadFrom + ' holds no user_accounts\sduser') }
# It reaches sd's command line through cmd.exe, so only verb-name characters,
# commas and spaces - nothing cmd could read as & | < > ^ or a quote.
if ($denyVerbs -and ($denyVerbs -notmatch '^[A-Za-z0-9.$_, -]+$')) { $refuse += 'deny-verbs holds a character that cannot be in a verb name' }
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

$disqualify = @('only the installer may run this', 'Connection terminated', 'has not been started',
                'Cannot update every registered account from here', 'Command requires administrator privileges',
                # SYNC.GLOBAL.CATALOG's refusals (12028, its own open failures, 3022)
                'can only be changed by the SD Core server', 'cannot open GLOBAL.BP.OUT',
                'Cannot open global catalogue directory',
                # DENY.VERBS's refusals (ruling 34)
                'is not a verb name', 'DENY.VERBS: cannot open',
                'Cannot open accounts register', 'does not take',
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

    # 28 Sep 26 - RULING 33: the global catalogue's server programs come from
    # GLOBAL.BP.OUT.  An upgrade replaces gcat and drops them, and the owner
    # ruled they are "cataloged at installation", so every install and upgrade
    # re-runs the sync.  With no global password it says so and succeeds.  The anchor is the
    # verb's own last line with 0 refused; a refused object fails the step.
    $t = Invoke-Sd '-internal SYNC.GLOBAL.CATALOG' ''
    Judge 'global catalogue matches GLOBAL.BP.OUT' $t '(?m)^SYNC GLOBAL CATALOG DONE \d+ catalogued \d+ removed 0 refused\s*$'
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
