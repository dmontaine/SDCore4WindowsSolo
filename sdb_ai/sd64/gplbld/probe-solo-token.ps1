# probe-solo-token.ps1 - SOLO 3: WHAT TOKEN does a task running as the user,
# with nobody signed in, actually carry?
#
#   powershell -ExecutionPolicy Bypass -File probe-solo-token.ps1
#
# Run it ELEVATED: Windows refuses to register an S4U task otherwise (SOLO 1,
# measured).  The task itself runs as YOU, not as the elevated caller.
#
# WHY.  SOLO 1's probe reported "admin role: True" for such a task under
# -RunLevel Limited, which would mean every remote session the daemon serves
# holds an administrator's FULL token.  Its integrity line came back empty, so
# that was never read directly.  The owner's decision in SOLO 3 waits on this.
#
# WHAT IT DOES, for -RunLevel Limited and then Highest:
#   1. registers a task, S4U principal = the current user, no trigger, whose
#      action is "whoami /all /fo list" into a file under
#      %USERPROFILE%\SDCoreSoloSpike;
#   2. starts it, waits for the file, reads it;
#   3. unregisters the task, and shows that it is gone.
# It prints, for each: the user the task ran as, its integrity level, how
# BUILTIN\Administrators is held (ENABLED, or deny-only), the enabled and
# disabled privilege counts, and whether SeDebugPrivilege is present - and the
# raw lines those came from.  For contrast it prints the same for THIS
# (elevated) window.
#
# It reports and does not judge: which answer is acceptable is the owner's call.
# Exit 0 when both runs produced a readable report, 1 otherwise, 2 if refused.

$ErrorActionPreference = 'Stop'
$Dir    = Join-Path $env:USERPROFILE 'SDCoreSoloSpike'
$UserId = $env:USERDOMAIN + '\' + $env:USERNAME
$Cmd    = Join-Path $env:SystemRoot 'System32\cmd.exe'
$Whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

'=== probe-solo-token ' + (Get-Date -Format s)
'caller          : ' + $UserId + '   elevated: ' + $elevated
'report folder   : ' + $Dir
if (-not $elevated) { 'REFUSED: run this from an ELEVATED PowerShell (S4U registration needs it).'; exit 2 }

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

function Show-Token([string[]] $lines, [string] $label) {
    $user  = ($lines | Where-Object { $_ -match '^User Name:' } | Select-Object -First 1)
    $integ = ($lines | Where-Object { $_ -match 'Mandatory Label\\' } | Select-Object -First 1)
    # whoami /all /fo list prints each group as a block: Group Name, Type, SID,
    # Attributes.  Find the Administrators block by its SID and read its
    # Attributes line.
    $adminAttr = '(not in the token)'
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^SID:\s+S-1-5-32-544\s*$') {
            for ($j = $i + 1; $j -lt [Math]::Min($i + 3, $lines.Count); $j++) {
                if ($lines[$j] -match '^Attributes:\s*(.*)$') { $adminAttr = $Matches[1].Trim() }
            }
        }
    }
    $privEnabled  = @($lines | Where-Object { $_ -match '^State:\s+Enabled' }).Count
    $privDisabled = @($lines | Where-Object { $_ -match '^State:\s+Disabled' }).Count
    $debug = [bool]($lines | Where-Object { $_ -match 'SeDebugPrivilege' })
    '--- ' + $label
    '    user            : ' + $(if ($user) { $user.Trim() } else { '(no User Name line)' })
    '    integrity       : ' + $(if ($integ) { $integ.Trim() } else { '(no Mandatory Label line)' })
    '    Administrators  : ' + $adminAttr
    '    privileges      : ' + $privEnabled + ' enabled, ' + $privDisabled + ' disabled; SeDebugPrivilege present: ' + $debug
}

# Contrast: this elevated window.
$mine = @(& $Whoami /all /fo list)
Show-Token $mine 'THIS elevated window (for contrast)'

$ok = $true
foreach ($level in @('Limited', 'Highest')) {
    $task = 'SDCoreSolo-spike-token-' + $level
    $out  = Join-Path $Dir ('token-' + $level + '.txt')
    Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        'REFUSED: a task named ' + $task + ' already exists - remove it first'; exit 1
    }
    $args1 = '/c ""' + $Whoami + '" /all /fo list > "' + $out + '" 2>&1"'
    ''
    '=== RunLevel ' + $level
    'task command    : ' + $Cmd + ' ' + $args1
    try {
        $action    = New-ScheduledTaskAction -Execute $Cmd -Argument $args1
        $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType S4U -RunLevel $level
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
        $t = Get-ScheduledTask -TaskName $task
        'registered      : ' + $t.Principal.UserId + ' / ' + $t.Principal.LogonType + ' / ' + $t.Principal.RunLevel
        Start-ScheduledTask -TaskName $task
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            if ((Test-Path -LiteralPath $out) -and ((Get-ScheduledTask -TaskName $task).State -ne 'Running')) { break }
            Start-Sleep -Milliseconds 250
        }
        $info = Get-ScheduledTaskInfo -TaskName $task
        'task last result: ' + $info.LastTaskResult
        if (Test-Path -LiteralPath $out) {
            $lines = @(Get-Content -LiteralPath $out)
            if ($lines.Count -lt 5) { 'report          : only ' + $lines.Count + ' line(s):'; $lines | ForEach-Object { '    ' + $_ }; $ok = $false }
            else { Show-Token $lines ('the S4U task at RunLevel ' + $level) }
        } else {
            'report          : NONE - the task wrote nothing'
            $ok = $false
        }
    } finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        'cleanup         : task present afterwards = ' + [bool](Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)
    }
}

''
'Raw reports are kept in ' + $Dir + ' (token-Limited.txt, token-Highest.txt).'
if ($ok) { 'DONE: both runs reported - read the integrity and Administrators lines above'; exit 0 }
'INCOMPLETE: see above'
exit 1
