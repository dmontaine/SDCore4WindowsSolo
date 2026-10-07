# test-verifysolo-units.ps1 - free-tier guard for verify-solo.ps1's early refusal when the account has no password.
# It loads AccountPasswordRefusal out of the file by parsing it (nothing is re-typed) and runs it against SCRATCH
# credential registers, so no install, no SD, no password and no elevation are involved.
#
#   powershell -ExecutionPolicy Bypass -File <this file>
# Exit 0 = all rows pass, 1 = a row failed, 2 = could not run.
#
# WHAT IT PROTECTS (6 Oct 2026, and 2 Oct 18:05 and 19:27 before it): an install from a control file has NO account
# password - the register holds $ADMIN and $GLOBAL and nothing named for the account - until someone runs sd-solo once
# at the keyboard.  verify-solo.ps1 then asked for passwords, sent the account password, was refused, and said "the
# account password was refused ... mistyped, or login is broken": neither was true, the owner was told the password
# rule was the trouble, twice.  It must say what is missing and what to do, BEFORE it asks for any password, and it
# must NEVER refuse an install that has the record (a false refusal would block every good install).

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'verify-solo.ps1'
if (-not (Test-Path $src)) { Write-Host "NO TREE: $src missing"; exit 2 }

$fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label"; $script:fail++ }
}

$text = [IO.File]::ReadAllText($src)

function Load-Fn([string]$t) {
    $tk = $null; $er = $null
    $a = [System.Management.Automation.Language.Parser]::ParseInput($t, [ref]$tk, [ref]$er)
    $f = @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'AccountPasswordRefusal' }, $true))
    return [pscustomobject]@{ Errors = $er.Count; Fn = $(if ($f.Count -eq 1) { $f[0].Extent.Text } else { '' }) }
}

# ---- 1. the file parses and carries the function -----------------------------------------------------------------
$real = Load-Fn $text
Check 'verify-solo.ps1 parses with 0 errors' ($real.Errors -eq 0)
Check 'it defines AccountPasswordRefusal exactly once' ($real.Fn -ne '')
if ($real.Fn -eq '') { Write-Host 'NO FUNCTION: nothing to run'; exit 2 }
$b = [IO.File]::ReadAllBytes($src); $bom = 0
for ($i = 1; $i -lt $b.Length - 2; $i++) { if ($b[$i] -eq 0xEF -and $b[$i + 1] -eq 0xBB -and $b[$i + 2] -eq 0xBF) { $bom++ } }
Check 'no embedded BOM past offset 0' ($bom -eq 0)

# ---- 2. run it against scratch registers ----------------------------------------------------------------------------
$scratch = Join-Path $env:TEMP ('sdverifysolo-units-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $scratch | Out-Null
function New-Register([string]$name, [string[]]$records) {
    $d = Join-Path $scratch $name
    New-Item -ItemType Directory -Path $d | Out-Null
    foreach ($r in $records) { [IO.File]::WriteAllText((Join-Path $d $r), 'x') }
    return $d
}
. ([scriptblock]::Create($real.Fn))

$wizard  = New-Register 'wizard'  @('$ADMIN', '$GLOBAL', '$STORED', 'SDUSER')   # what a wizard install made (6 Oct 21:33)
$ctlfile = New-Register 'ctlfile' @('$ADMIN', '$GLOBAL')                          # what a control-file install made (6 Oct 21:25)
$plain   = New-Register 'plain'   @('$ADMIN', '$STORED', 'SDUSER')                # unmanaged, with its record
$bare    = New-Register 'bare'    @('$ADMIN')                                     # unmanaged, no record
$lower   = New-Register 'lower'   @('$ADMIN', '$GLOBAL', 'sduser')                # the record's file name in lower case (NTFS ignores case)
$gone    = Join-Path $scratch 'no-such-register'

$r1 = AccountPasswordRefusal $wizard 'sduser' $true
Write-Host ('--- wizard install, managed: [' + $r1 + ']')
Check 'a wizard install (the account record is there) is NOT refused' ($r1 -eq '')
$r2 = AccountPasswordRefusal $ctlfile 'sduser' $true
Write-Host ('--- control-file install, managed: ' + $r2)
Check 'a control-file install (no account record, managed) IS refused' ($r2 -ne '')
Check 'the message says the password has not been set, names the SDUSER record, and says what to do: run sd-solo once at the keyboard, choose it' (
    $r2 -match 'has not been set' -and $r2 -match 'SDUSER' -and $r2 -match 'Run sd-solo once' -and $r2 -match 'keyboard' -and $r2 -match 'choose the account password')
Check 'the message says it is the control file that does not set it, and NOT that the password was mistyped or login is broken' ($r2 -match 'control file' -and $r2 -notmatch 'mistyped' -and $r2 -notmatch 'login is broken')
$r3 = AccountPasswordRefusal $bare 'sduser' $false
Write-Host ('--- unmanaged, no record: ' + $r3)
Check 'an unmanaged tree with no account record is refused, and told to install again - nothing will ask for a password there' ($r3 -match 'not managed' -and $r3 -match 'Install again' -and $r3 -notmatch 'Run sd-solo once')
Check 'an unmanaged tree WITH its record is not refused' ((AccountPasswordRefusal $plain 'sduser' $false) -eq '')
Check 'the record is found whatever the case of its file name (NTFS)' ((AccountPasswordRefusal $lower 'sduser' $true) -eq '')
Check 'a register that cannot be read is not a reason to refuse here (the other checks report a broken install)' ((AccountPasswordRefusal $gone 'sduser' $true) -eq '')

# ---- 3. it runs before any password is asked for ------------------------------------------------------------------------
$call = [regex]::Match($text, '(?m)^\$acctWhy = AccountPasswordRefusal \$CredDir \$Acct \$managed\s*\r?\n\s*if \(\$acctWhy\) \{ Refuse \$acctWhy \}')
$ask = [regex]::Match($text, '(?m)^\s*\$acctPw\s*=\s*Read-Password')
Check 'the script calls it and refuses on its answer' $call.Success
Check 'and that is BEFORE the first password prompt (Read-Password), so nobody types passwords into a run that cannot work' ($call.Success -and $ask.Success -and $call.Index -lt $ask.Index)
Check 'the old "mistyped, or login is broken" message is still there, for a record that exists and a password that is refused' ($text -match 'the account password was refused \(the session is shown above\) - mistyped, or login is broken')

# ---- 4. mutants: each must be caught, or this is not looking at anything ---------------------------------------------------
Write-Host '--- mutants'
$m1 = $text.Replace("if (Test-Path -LiteralPath (Join-Path `$CredDir `$Acct.ToUpper())) { return '' }", "return ''")
$m2 = $text.Replace("`$acctWhy = AccountPasswordRefusal `$CredDir `$Acct `$managed`r`nif (`$acctWhy) { Refuse `$acctWhy }", '').Replace("`$acctWhy = AccountPasswordRefusal `$CredDir `$Acct `$managed`nif (`$acctWhy) { Refuse `$acctWhy }", '')
$m3 = $text.Replace("if (Test-Path -LiteralPath (Join-Path `$CredDir `$Acct.ToUpper())) { return '' }", "if (`$false) { return '' }")
foreach ($mut in @(@('the check always says "set" (never refuses)', $m1), @('the call is removed', $m2), @('the check always refuses (a false refusal)', $m3))) {
    $label = $mut[0]; $mt = $mut[1]
    Check ('CONTROL: the mutant "' + $label + '" differs from the real file') ($mt -ne $text)
    $lf = Load-Fn $mt
    $caught = $false
    if ($label -like '*always says*') {
        . ([scriptblock]::Create($lf.Fn)); $caught = ((AccountPasswordRefusal $ctlfile 'sduser' $true) -eq '')
        . ([scriptblock]::Create($real.Fn))
    }
    elseif ($label -like '*removed*') { $caught = -not ([regex]::Match($mt, '(?m)^\$acctWhy = AccountPasswordRefusal').Success) }
    else {
        . ([scriptblock]::Create($lf.Fn)); $caught = ((AccountPasswordRefusal $wizard 'sduser' $true) -ne '')
        . ([scriptblock]::Create($real.Fn))
    }
    Check ('MUTANT "' + $label + '" is caught by the rows above') $caught
}

Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail -eq 0) { Write-Host 'verify-solo units: ALL PASS'; exit 0 }
Write-Host "verify-solo units: $fail FAILED"; exit 1
