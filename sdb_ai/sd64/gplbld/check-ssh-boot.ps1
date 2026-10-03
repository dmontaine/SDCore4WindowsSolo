# check-ssh-boot.ps1 - did SD Core Solo's sshd start at boot, BEFORE anyone signed in?  SOLO 28.
#
#   powershell -ExecutionPolicy Bypass -File <repo>\sdb_ai\sd64\gplbld\check-ssh-boot.ps1
#
# Read-only.  Run it from an ORDINARY UNELEVATED PowerShell, after the computer was RESTARTED (the
# Start menu's Restart - not Shut down: Fast Startup can leave the boot time unchanged across a
# shut down) and you have signed in.  A task registered by the installer and started by the
# installer proves the task works; only a restart proves the "at startup" trigger does.
#
# WHAT IT MEASURES, AND HOW IT KNOWS: the process that holds port 4251 is found by the PORT (an
# ordinary shell cannot read a task-started process's command line or path - measured 2 Oct 2026),
# its start time is read from WMI (that IS readable), and it is compared with the boot time and with
# the start of the first explorer.exe, which is the sign-in.  A session-0 sshd that began BEFORE the
# first explorer was started by the boot trigger and nobody was signed in when it came up.
#
# VERDICT: PASS (exit 0) only when the holder started after boot and before the first explorer;
# FAIL (exit 1) when it did not, with the numbers; exit 2 when it could not measure (nothing on
# 4251, no explorer found, no start time) - the null case is said out loud, never a pass.

$ErrorActionPreference = 'Continue'
$Port = 4251

function Out-Line([string]$s) { Write-Host $s }

# The task is registered as SYSTEM, which an ORDINARY user cannot see at all - Get-ScheduledTask finds nothing and
# schtasks says "Access is denied" (measured 2 Oct 2026) - so "not found" here would be a false "NOT REGISTERED".
# What an ordinary user CAN read is the Task Scheduler's operational log, which records each launch and for whom.
function Show-Task {
    $ti = Get-ScheduledTaskInfo -TaskName 'SD Core Solo SSH' -ErrorAction SilentlyContinue
    if ($ti) { Out-Line ('task "SD Core Solo SSH"  : last run ' + $ti.LastRunTime + ', result 0x' + ('{0:X}' -f $ti.LastTaskResult) + '  (0x41301 = still running)'); return }
    Out-Line 'task "SD Core Solo SSH"  : not visible from an ordinary shell (a task registered as SYSTEM is readable only elevated) - the log says:'
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 100; StartTime = $boot } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'SD Core Solo SSH' } | Sort-Object TimeCreated | Select-Object -First 2)
    if ($ev.Count -eq 0) { Out-Line '                         no launch of it since boot is recorded in the Task Scheduler operational log' }
    foreach ($e in $ev) { Out-Line ('                         launched {0:yyyy-MM-dd HH:mm:ss.fff}: {1}' -f $e.TimeCreated, (($e.Message -split "`r?`n")[0])) }
}

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Out-Line ('boot (LastBootUpTime) : ' + $boot)
if (-not $boot) { Out-Line 'VERDICT: COULD NOT MEASURE - no boot time'; exit 2 }

$explorers = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate })
if ($explorers.Count -eq 0) { Out-Line 'VERDICT: COULD NOT MEASURE - no explorer.exe start time could be read (is anyone signed in?)'; exit 2 }
$firstExplorer = ($explorers | Sort-Object CreationDate | Select-Object -First 1).CreationDate
Out-Line ('first explorer.exe     : ' + $firstExplorer + '   (' + $explorers.Count + ' explorer process(es) seen)')

$listen = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
if ($listen.Count -eq 0) {
    Out-Line ('VERDICT: FAIL - nothing is listening on port ' + $Port + '.  Solo''s sshd is not running.')
    Show-Task
    exit 1
}
$holderId = $listen[0].OwningProcess
$holder = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $holderId) -ErrorAction SilentlyContinue
if (-not $holder -or -not $holder.CreationDate) { Out-Line ('VERDICT: COULD NOT MEASURE - pid ' + $holderId + ' holds port ' + $Port + ' but its start time cannot be read'); exit 2 }
Out-Line ('port ' + $Port + ' holder        : ' + $holder.Name + ' pid ' + $holderId + '  session ' + $holder.SessionId + '  started ' + $holder.CreationDate)

Show-Task

$afterBoot = [int]($holder.CreationDate - $boot).TotalSeconds
$beforeExplorer = [int]($firstExplorer - $holder.CreationDate).TotalSeconds
Out-Line ('sshd started          : ' + $afterBoot + ' s after boot, ' + $beforeExplorer + ' s before the first explorer.exe')

if ($holder.Name -ne 'sshd.exe') { Out-Line ('VERDICT: FAIL - port ' + $Port + ' is held by ' + $holder.Name + ', not sshd.exe'); exit 1 }
if ($afterBoot -lt 0) { Out-Line 'VERDICT: FAIL - this sshd started BEFORE the last boot, so the computer has not been restarted since it was started (Restart, not Shut down).'; exit 1 }
if ($beforeExplorer -le 0) {
    Out-Line 'VERDICT: FAIL - the sshd started AFTER the sign-in began.  Either it was not started by the boot trigger, or it was restarted since (or automatic sign-in beat it - see the seconds above).'
    exit 1
}
Out-Line ('VERDICT: PASS - Solo''s sshd (pid ' + $holderId + ') came up ' + $afterBoot + ' s after boot and ' + $beforeExplorer + ' s before anyone signed in: the startup trigger started it.')
exit 0
