# test-apifirewall-units.ps1 - free-tier guard for what api-firewall.ps1 -Retarget does
# about a firewall rule an older build left under the OLD name.
#
#   powershell -ExecutionPolicy Bypass -File C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\test-apifirewall-units.ps1
#
# ORDINARY UNELEVATED PROMPT.  No firewall, no install, no SD.  Exit 0 all passed,
# 1 something failed, 2 could not set up.
#
# WHY IT EXISTS.  01 Oct 26, owner's ruling: SD Core Solo's rule is SD-Solo-API-In-TCP,
# and the full product keeps SD-API-In-TCP, so the two no longer act on each other's rule.
# A rule an older Solo left under the old name cannot be told from the full product's.
# -Retarget therefore ADOPTS it (new name, new port, same scope) only when it is on the
# old port 4243 AND the full product is not installed - and a wrong answer here either
# takes the full product's rule away from it or strands a site that had opened the API.
# The decision is a pure function (Get-LegacyPlan) so every case can be driven here
# with no firewall; the function is lifted from the file by AST (test-sdpath-units.ps1's
# technique), so this tests the shipped text.  What cannot be tested here is the firewall
# itself: the create, the scope copy and the removal need elevation and are witnessed on
# a cycle.
#
# NOT SHIPPED - assert-current exempts test-* scripts by name.

$ErrorActionPreference = 'Stop'

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$subject = Join-Path $here 'api-firewall.ps1'
Write-Host "test-apifirewall-units: subject $subject"
if (-not (Test-Path -LiteralPath $subject)) { Write-Host 'test-apifirewall-units: subject not found.'; exit 2 }

$tok = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($subject, [ref]$tok, [ref]$errs)
if ($errs.Count -gt 0) { Write-Host "test-apifirewall-units: subject has $($errs.Count) parse error(s)."; exit 2 }
$text = [System.IO.File]::ReadAllText($subject)

$fns = @($ast.FindAll({
    param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-LegacyPlan'
}, $true))
if ($fns.Count -ne 1) { Write-Host "test-apifirewall-units: expected exactly one Get-LegacyPlan, found $($fns.Count)."; exit 2 }
$fnText = $fns[0].Extent.Text
. ([scriptblock]::Create($fnText))

$fail = 0
$ran  = 0
function Check([string]$label, [bool]$ok) {
    $script:ran++
    if ($ok) { Write-Host "  [PASS] $label" } else { Write-Host "  [FAIL] $label"; $script:fail++ }
}

# The table the owner's ruling and the design give.  (exists, port, fullInstalled) -> plan.
$table = @(
    @{ e = $false; p = '';     f = $false; want = 'none';       why = 'no rule under the old name' }
    @{ e = $false; p = '';     f = $true;  want = 'none';       why = 'no rule, full product installed' }
    @{ e = $true;  p = '4243'; f = $false; want = 'adopt';      why = 'old port, no full product: certainly Solo''s' }
    @{ e = $true;  p = '4243'; f = $true;  want = 'leave-full'; why = 'old port but the full product is installed: may be its rule' }
    @{ e = $true;  p = '4247'; f = $false; want = 'leave-port'; why = 'already on the full product''s new port: not ours' }
    @{ e = $true;  p = '5000'; f = $false; want = 'leave-port'; why = 'an administrator''s own port' }
    @{ e = $true;  p = '4249'; f = $false; want = 'leave-port'; why = 'under the OLD name on Solo''s new port: not made by an older build' }
    @{ e = $true;  p = '4247'; f = $true;  want = 'leave-port'; why = 'full product installed and its rule on 4247' }
)
Write-Host 'the decision table, against the lifted function:'
foreach ($r in $table) {
    $got = Get-LegacyPlan $r.e $r.p $r.f
    Write-Host ("    exists={0} port='{1}' full={2} -> {3}" -f $r.e, $r.p, $r.f, $got)
    Check ("{0}: {1}" -f $r.want, $r.why) ($got -eq $r.want)
}
$adopts = @($table | Where-Object { (Get-LegacyPlan $_.e $_.p $_.f) -eq 'adopt' }).Count
Check 'CONTROL: exactly one input in the table adopts, so the table is not vacuous' ($adopts -eq 1)

# MUTANTS, on synthetic text of the function: each is a plausible edit, and the table must go red.
function Table-Matches([string]$fnSource) {
    $sb = [scriptblock]::Create($fnSource)
    . $sb
    foreach ($r in $table) { if ((Get-LegacyPlan $r.e $r.p $r.f) -ne $r.want) { return $false } }
    return $true
}
$m1 = $fnText.Replace("if (`$fullInstalled)         { return 'leave-full' }", '')
$m2 = $fnText.Replace("if (`$legacyPort -ne '4243') { return 'leave-port' }", '')
$m3 = $fnText.Replace("return 'adopt'", "return 'leave-full'")
Check 'MUTANT: the full-product check removed is caught'  ($m1 -ne $fnText -and -not (Table-Matches $m1))
Check 'MUTANT: the old-port check removed is caught'      ($m2 -ne $fnText -and -not (Table-Matches $m2))
Check 'MUTANT: never adopting is caught'                  ($m3 -ne $fnText -and -not (Table-Matches $m3))
Check 'CONTROL: the unmodified function still passes the table after the mutants ran' (Table-Matches $fnText)

# The text around the function: the names, the call, and the order create-before-remove.
Check 'Solo''s own rule name is SD-Solo-API-In-TCP' ($text -match "(?m)^\`$ruleName\s*=\s*'SD-Solo-API-In-TCP'")
Check 'the old name is kept only as the legacy name' ($text -match "(?m)^\`$legacyRuleName\s*=\s*'SD-API-In-TCP'" -and $text -notmatch "(?m)^\`$ruleName\s*=\s*'SD-API-In-TCP'")
$calls = ([regex]::Matches($text, 'Get-LegacyPlan \(')).Count
Check 'the decision is actually used (a call site besides the definition)' ($calls -ge 1)
$iNew = $text.IndexOf('New-NetFirewallRule -Name $ruleName -DisplayName $displayName', $text.IndexOf('$plan -eq ''leave-full'''))
$iDel = $text.IndexOf('Remove-NetFirewallRule -Name $legacyRuleName')
Write-Host ("    adoption: New-NetFirewallRule at {0}, Remove-NetFirewallRule of the old rule at {1}" -f $iNew, $iDel)
Check 'the new rule is created BEFORE the old one is removed' ($iNew -gt 0 -and $iDel -gt $iNew)
Check 'the old rule is not removed anywhere before the new one is read back' ($text.IndexOf('Remove-NetFirewallRule -Name $legacyRuleName') -eq $text.LastIndexOf('Remove-NetFirewallRule -Name $legacyRuleName'))

# The count of Check calls above, so a check DELETED in a refactor fails loudly.
$minimum = 18
Write-Host ''
Write-Host ("  ran {0}, failed {1}" -f $ran, $fail)
if ($ran -lt $minimum) { Write-Host ("  REFUSED: only {0} checks ran, expected at least {1}" -f $ran, $minimum); exit 1 }
if ($fail -gt 0) { Write-Host 'test-apifirewall-units: FAILED'; exit 1 }
Write-Host 'test-apifirewall-units: all passed'
exit 0
