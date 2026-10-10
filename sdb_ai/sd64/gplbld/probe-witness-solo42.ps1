# probe-witness-solo42.ps1 - SOLO 42's witness: with Core's daemon up, the sign-in task script still clears a sign-out leftover.
# Ordinary UNELEVATED prompt, on a machine with BOTH products installed, Core running and Solo running.
#   powershell -ExecutionPolicy Bypass -File <this file> [-Root <Solo folder>]
#
# WHAT IT DOES (and nothing else).  1. Refuses unless Core's sdwind AND Solo's sdwind are both running, because the case
# the row is about is "a process named sdwind exists that is not Solo's".  2. Kills SOLO'S sdwind (a hard kill, the way a
# sign-out does: the shared segment stays behind).  3. Runs solo-start.ps1 from the Solo folder, exactly as the sign-in
# task does.  4. Reads the lines solo-start.log gained, and checks Solo's sdwind is running again.
# PASS needs ALL of: the log gained a line 'the start failed and no sdwind is running' (the clear-and-retry branch ran),
# a line 'sd-solo -stop', and Solo's sdwind running from the Solo folder afterwards.  The OLD script (the name test)
# would have skipped the clear because Core's sdwind exists, and the log would say success while Solo stayed down.
# It prints the inputs, before and after states, and the raw log lines.

# -Script names the solo-start.ps1 to run instead of the installed one (a CONTROL: the source file against the installed
# binaries, before a cycle).  It is run with -AppDir <Solo folder>, which is where the real task script finds sd-solo.exe.
param([string]$Root = '', [string]$Script = '')
$ErrorActionPreference = 'Stop'
if ($Root -eq '') { $Root = Join-Path $env:USERPROFILE 'SDCoreSolo' }
$rootFull = ([IO.Path]::GetFullPath($Root)).TrimEnd('\')
$script = if ($Script -ne '') { $Script } else { Join-Path $rootFull 'solo-start.ps1' }
$logf = Join-Path $rootFull 'solo-start.log'

function Mine { @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([IO.Path]::GetFullPath($_.Path)).StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase) }) }
function Others { @(Get-Process -Name sdwind -ErrorAction SilentlyContinue | Where-Object { -not ($_.Path -and ([IO.Path]::GetFullPath($_.Path)).StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) }) }

Write-Output ('witness-solo42  ' + (Get-Date -Format 's'))
Write-Output ('  user     : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Output ('  root     : ' + $rootFull)
Write-Output ('  script   : ' + $script + '  exists=' + (Test-Path -LiteralPath $script))
Write-Output ('  log      : ' + $logf)
if (-not (Test-Path -LiteralPath $script)) { Write-Output 'REFUSED: solo-start.ps1 is not in the Solo folder.'; exit 2 }
$m0 = Mine; $o0 = Others
Write-Output ('  BEFORE   : Solo sdwind=' + $m0.Count + ' (pids ' + (($m0 | ForEach-Object { $_.Id }) -join ',') + ')   other sdwind (Core)=' + $o0.Count + ' (pids ' + (($o0 | ForEach-Object { $_.Id }) -join ',') + ')')
if ($m0.Count -eq 0) { Write-Output 'REFUSED: Solo is not running, so there is no daemon to kill.  Start it, then run this again.'; exit 2 }
if ($o0.Count -eq 0) { Write-Output 'REFUSED: no other sdwind is running (Core is down), so the case SOLO 42 is about is not set up.  Start Core, then run this again.'; exit 2 }

$before = if (Test-Path -LiteralPath $logf) { @(Get-Content -LiteralPath $logf).Count } else { 0 }
Write-Output ('  killing Solo sdwind pid(s) ' + (($m0 | ForEach-Object { $_.Id }) -join ',') + '  (log had ' + $before + ' lines)')
$m0 | Stop-Process -Force
Start-Sleep -Seconds 2
Write-Output ('  after the kill: Solo sdwind=' + (Mine).Count + '   other sdwind=' + (Others).Count)
if ((Mine).Count -ne 0) { Write-Output 'REFUSED: Solo sdwind is still running after the kill.'; exit 2 }

Write-Output ('  running: powershell -NoProfile -ExecutionPolicy Bypass -File ' + $script + ' -AppDir ' + $rootFull)
& powershell -NoProfile -ExecutionPolicy Bypass -File $script -AppDir $rootFull
$code = $LASTEXITCODE
Start-Sleep -Seconds 3
$m1 = Mine
$new = if (Test-Path -LiteralPath $logf) { @(Get-Content -LiteralPath $logf | Select-Object -Skip $before) } else { @() }
Write-Output ''
Write-Output ('  solo-start.ps1 exit code: ' + $code)
Write-Output '  lines the log gained:'
foreach ($l in $new) { Write-Output ('    ' + $l) }
Write-Output ('  AFTER    : Solo sdwind=' + $m1.Count + ' (pids ' + (($m1 | ForEach-Object { $_.Id }) -join ',') + ')   other sdwind=' + (Others).Count)

$text = $new -join "`n"
$cleared = $text -match 'the start failed and no sdwind is running'
$stopped = $text -match 'sd-solo -stop: exit'
Write-Output ''
Write-Output ('  clear-and-retry branch ran : ' + $cleared)
Write-Output ('  sd-solo -stop was run      : ' + $stopped)
Write-Output ('  Solo sdwind running again  : ' + ($m1.Count -gt 0))
if ($cleared -and $stopped -and $m1.Count -gt 0) {
    Write-Output 'SOLO 42 WITNESS: PASS - Solo restarted itself with Core running.'
    exit 0
}
Write-Output 'SOLO 42 WITNESS: FAIL - read the log lines above; the old behaviour is a log that says the start failed and then reports success.'
exit 1
