# probe-solo-s4u.ps1 - SOLO 1(a): can a process run AS THE USER with nobody
# signed in, started by Windows at boot, registered WITHOUT elevation?
#
#   powershell -ExecutionPolicy Bypass -File probe-solo-s4u.ps1 [-Port 47431]
#
# Run it UNELEVATED - that is the per-user installer's case, and the question.
#
# What it does, in order, and it prints each step's real inputs and outcome:
#   1. registers a scheduled task running as the current user with an S4U
#      principal ("run whether the user is signed in or not, do not store the
#      password") and an AT-STARTUP trigger; if Windows refuses that, retries
#      with NO trigger, so the two questions - S4U at all, and a boot trigger -
#      come apart;
#   2. starts it on demand.  The run context of such a task is the same whether
#      the user is signed in or not - its own logon, session 0 - so this
#      measures that context without a reboot.  WHAT IT CANNOT MEASURE: the
#      boot trigger actually firing, and reachability while signed out; those
#      need a reboot and a second machine, and are reported as NOT MEASURED;
#   3. connects to the task's loopback listener and exchanges one line;
#   4. prints the task's own report of who and where it is;
#   5. unregisters the task, and shows that it is gone.
#
# Exit 0 only when every measured step passed; 1 when one failed; 3 when
# Windows would not register the task at all.  The task and the folder
# %USERPROFILE%\SDCoreSoloSpike are its only side effects, and the task is
# always removed.

param(
    [int] $Port = 47431
)

$ErrorActionPreference = 'Stop'
$TaskName = 'SDCoreSolo-spike-s4u'
$Dir      = Join-Path $env:USERPROFILE 'SDCoreSoloSpike'
$Out      = Join-Path $Dir 'report.txt'
$Payload  = Join-Path $PSScriptRoot 'probe-solo-s4u-payload.ps1'
$Ps       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$UserId   = $env:USERDOMAIN + '\' + $env:USERNAME

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

'=== probe-solo-s4u ' + (Get-Date -Format s)
'caller          : ' + $UserId + '   elevated: ' + $elevated
'payload         : ' + $Payload + '   exists: ' + (Test-Path -LiteralPath $Payload)
'report          : ' + $Out
'port            : ' + $Port
if (-not (Test-Path -LiteralPath $Payload)) { 'REFUSED: the payload script is missing'; exit 1 }
if ($elevated) { 'NOTE: run ELEVATED - this does not answer the per-user question' }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    'REFUSED: a task named ' + $TaskName + ' already exists - remove it first'; exit 1
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Remove-Item -LiteralPath $Out, ($Out + '.ready'), (Join-Path $Dir 'write-test.txt') -ErrorAction SilentlyContinue

$TaskArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Payload + '" -Out "' + $Out + '" -Port ' + $Port
'task command    : ' + $Ps + ' ' + $TaskArgs
$action    = New-ScheduledTaskAction -Execute $Ps -Argument $TaskArgs
$principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType S4U -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

$pass = $true
$registeredWith = ''
try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) | Out-Null
    $registeredWith = 'S4U + AT STARTUP'
    'register (1)    : S4U with an at-startup trigger - ACCEPTED'
} catch {
    'register (1)    : S4U with an at-startup trigger - REFUSED: ' + $_.Exception.Message
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registeredWith = 'S4U, no trigger'
        'register (2)    : S4U with no trigger - ACCEPTED'
    } catch {
        'register (2)    : S4U with no trigger - REFUSED: ' + $_.Exception.Message
        'VERDICT         : Windows will not register an S4U task for this user unelevated.'
        exit 3
    }
}

try {
    $t = Get-ScheduledTask -TaskName $TaskName
    'registered      : ' + $registeredWith + '   principal ' + $t.Principal.UserId + ' / ' + $t.Principal.LogonType + ' / ' + $t.Principal.RunLevel

    Start-ScheduledTask -TaskName $TaskName
    'started         : on demand'

    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath ($Out + '.ready')) -and -not (Test-Path -LiteralPath $Out) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath ($Out + '.ready')) {
        $c = New-Object Net.Sockets.TcpClient
        $c.Connect('127.0.0.1', $Port)
        $s = $c.GetStream()
        $w = New-Object IO.StreamWriter($s); $r = New-Object IO.StreamReader($s)
        $w.WriteLine('hello-from-probe'); $w.Flush()
        $reply = $r.ReadLine()
        $c.Close()
        'reply           : ' + $reply
        if ($reply -ne 'hello-from-s4u-task') { $pass = $false }
    } else {
        'reply           : NONE - the task never reported it was listening'
        $pass = $false
    }

    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $Out) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    '--- the task''s own report:'
    if (Test-Path -LiteralPath $Out) {
        $report = @(Get-Content -LiteralPath $Out)
        $report | ForEach-Object { '    ' + $_ }
        if (-not ($report -contains 'DONE'))                                   { $pass = $false }
        if (-not ($report -match '^accepted, got\s+: hello-from-probe$'))      { $pass = $false }
        if (-not ($report -match ('^user\s+: ' + [regex]::Escape($UserId) + '$'))) { $pass = $false }
    } else {
        '    NONE - the task wrote no report (it did not run, or died before writing)'
        $pass = $false
    }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    'task last result: ' + $info.LastTaskResult + '   last run: ' + $info.LastRunTime
}
finally {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    'cleanup         : task present afterwards = ' + [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
}

'NOT MEASURED    : the at-startup trigger firing at a real boot, and reaching the task from another machine while nobody is signed in.'
if ($pass) { 'VERDICT         : PASS - the measured steps all held'; exit 0 }
'VERDICT         : FAIL - see the lines above'
exit 1
