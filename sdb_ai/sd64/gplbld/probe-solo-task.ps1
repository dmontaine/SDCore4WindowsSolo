# probe-solo-task.ps1 - why does the "SD Core Solo" startup task not run?
#
# 30 Sep 2026.  Two cycles in a row (18:52 and 18:56) registered the task, started it,
# and it never ran: state Ready, last run 11/30/1999, last result 0x41303.  The same task
# ran fine at 18:36.  Task Scheduler's own log would say why, but that log is OFF by
# default and unreadable unelevated, so this turns it on, starts the task once, and
# prints what Task Scheduler recorded.  RUN ELEVATED.  It changes nothing else; it
# leaves the Operational log enabled (wevtutil sl ... /e:false turns it off again).
#
# Everything is also written to %TEMP%\probe-solo-task.txt so the result can be read
# without copying it out of the console.

$out = Join-Path $env:TEMP 'probe-solo-task.txt'
$lines = New-Object System.Collections.ArrayList
function Say([string]$t) { Write-Host $t; [void]$lines.Add($t) }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$adm = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ("probe-solo-task " + (Get-Date -Format s) + "   as " + $id.Name + "   elevated: " + $adm)
if (-not $adm) { Say 'REFUSED: run this from an ELEVATED PowerShell.'; exit 2 }

$name = 'SD Core Solo'
$log = 'Microsoft-Windows-TaskScheduler/Operational'
$task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if (-not $task) { Say "REFUSED: no task named '$name' is registered."; exit 2 }
Say ("task: " + $name + "   state " + $task.State + "   principal " + $task.Principal.UserId + " " + $task.Principal.LogonType)
Say ("Schedule service: " + (Get-Service Schedule).Status)
Say ("sd.exe: " + $task.Actions[0].Execute + "   exists: " + (Test-Path -LiteralPath $task.Actions[0].Execute))

& wevtutil.exe sl $log /e:true
Say ("Operational log enabled: " + ((& wevtutil.exe gl $log) -match 'enabled: true' -as [bool]))
$t0 = Get-Date
Say "starting the task now ($t0)"
Start-ScheduledTask -TaskName $name
Start-Sleep -Seconds 8
$info = Get-ScheduledTaskInfo -TaskName $name
Say ("after 8 s: state " + (Get-ScheduledTask -TaskName $name).State + "   last run " + $info.LastRunTime + "   last result 0x" + ('{0:X}' -f $info.LastTaskResult))
$sd = @(Get-Process sdwind -ErrorAction SilentlyContinue)
Say ("sdwind processes: " + $sd.Count)

Say ''
Say 'Task Scheduler events since the start (oldest first):'
$ev = @(Get-WinEvent -LogName $log -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $t0.AddSeconds(-2) } | Sort-Object TimeCreated)
if ($ev.Count -eq 0) { Say '  (none - the service recorded nothing for this start)' }
foreach ($e in $ev) {
    Say ("  " + $e.TimeCreated.ToString('HH:mm:ss.fff') + "  id " + $e.Id + "  " + ($e.Message -replace "\s+", ' ').Substring(0, [Math]::Min(240, ($e.Message -replace "\s+", ' ').Length)))
}
Say ''
Say 'The same events for the task, any time since the log was enabled (newest 60) - an install that failed shows here:'
$all = @(Get-WinEvent -LogName $log -ErrorAction SilentlyContinue | Where-Object { $_.Message -match [regex]::Escape($name) } | Select-Object -First 60)
foreach ($e in $all) { Say ("  " + $e.TimeCreated.ToString('HH:mm:ss') + "  id " + $e.Id + "  " + ($e.Message -replace "\s+", ' ').Substring(0, [Math]::Min(200, ($e.Message -replace "\s+", ' ').Length))) }

[IO.File]::WriteAllLines($out, [string[]]$lines.ToArray())
Write-Host ''
Write-Host "Written to $out"
