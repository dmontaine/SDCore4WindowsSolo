# solo-start.ps1 - what the SIGN-IN startup task runs (SOLO 38).  Runs as the user, unelevated, with no window.
#
# WHY IT EXISTS.  Windows refuses the boot-time startup task (S4U) for a standard account, so solo-machine.ps1
# registers a task that runs when the user signs in instead.  Two things measured on a guest (6 Oct 2026) make
# "run sd-solo -start" not enough:
#   - SIGNING OUT KILLS sdwind (the server), and it leaves the shared segment behind.  The next "sd-solo -start" then
#     refuses: "SD did not shut down cleanly: the shared segment is still here but sdwind is not running.  Run
#     sd-solo -stop to clear it, then sd-solo -start again."  The sign-in task's start was that refusal, reported as
#     success by the hidden launcher, so after one sign-out SD never started again (the log-on trigger had fired, the
#     task's result was 0x0, no sdwind).
#   - the refusal is on stderr, with exit 1, and "SD is already started" is ALSO exit 1 - so the message, not the
#     exit code, says which it is, and only the first may be answered with -stop.
# WHAT IT DOES.  Starts SD.  If that failed AND no sdwind is running, it clears the leftover with "sd-solo -stop" and
# starts once more.  It never stops an SD that is running (sd-solo -start said "already started" and sdwind is up),
# and it does not loop.  Everything it does is written to solo-start.log beside it, so a failure is not silent.
# sd-solo.exe is started with Start-Process -WindowStyle Hidden, so sdwind gets a console with no window to close.
# It waits for sd-solo.exe ALONE (WaitForExit), never Start-Process -Wait, which would wait for sdwind too.
#
# Exit 0 = SD is running when it ends; 1 = it is not.

param(
    [string]$AppDir = $PSScriptRoot
)

function Write-StartLog([string]$LogFile, [string]$Text) {
    try {
        if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt 65536) {
            $keep = @(Get-Content -LiteralPath $LogFile -Tail 200)
            [IO.File]::WriteAllLines($LogFile, [string[]]$keep)
        }
        [IO.File]::AppendAllText($LogFile, ((Get-Date -Format 's') + '  ' + $Text + "`r`n"))
    } catch { }
}

# True while an sdwind process exists.  The sign-in task is the only thing that starts SD on this computer's
# behalf, and two Solo installs cannot share a computer, so the name is enough.
function Test-SdRunning {
    return (@(Get-Process -Name sdwind -ErrorAction SilentlyContinue).Count -gt 0)
}

# Runs sd-solo.exe with one argument, hidden, waits for IT (not for the daemon it leaves), and returns its exit code
# and its stderr.  stderr goes to a file with a name of its own: sdwind inherits that handle and keeps it open.
function Invoke-SoloSd([string]$SdExe, [string]$Arg) {
    $err = Join-Path $env:TEMP ('solo-start-' + [guid]::NewGuid().ToString('N') + '.err')
    $code = $null; $msg = ''
    try {
        # NOT "Start-Process -Wait": it waits for the process AND its descendants, and "sd-solo -start" leaves sdwind
        # running for as long as SD is up - so the first version of this helper never finished (the task sat at
        # "Running", 0x41301, and the installer failed the step) although SD had started.  WaitForExit() waits for
        # sd-solo.exe alone.  PowerShell 5.1 gives a null ExitCode after -PassThru unless the handle is cached first.
        $p = Start-Process -FilePath $SdExe -ArgumentList $Arg -WindowStyle Hidden -PassThru -RedirectStandardError $err -ErrorAction Stop
        $null = $p.Handle
        $p.WaitForExit()
        $code = $p.ExitCode
        if (Test-Path -LiteralPath $err) { $msg = ((@(Get-Content -LiteralPath $err -ErrorAction SilentlyContinue)) -join ' ').Trim() }
    } catch { $msg = 'could not run it: ' + $_.Exception.Message }
    return [pscustomobject]@{ Code = $code; Message = $msg }
}

function Start-SoloSd([string]$SdExe, [string]$LogFile) {
    Write-StartLog $LogFile ('--- sign-in start, user ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + ', ' + $SdExe)
    if (-not (Test-Path -LiteralPath $SdExe)) { Write-StartLog $LogFile 'sd-solo.exe is not there - nothing started'; return 1 }
    $r = Invoke-SoloSd $SdExe '-start'
    Write-StartLog $LogFile ('sd-solo -start: exit ' + $r.Code + $(if ($r.Message) { ' | ' + $r.Message } else { '' }))
    if ($r.Code -ne 0 -and -not (Test-SdRunning)) {
        Write-StartLog $LogFile 'the start failed and no sdwind is running (a sign-out or a crash left it): clearing with sd-solo -stop, then starting once more'
        $s = Invoke-SoloSd $SdExe '-stop'
        Write-StartLog $LogFile ('sd-solo -stop: exit ' + $s.Code + $(if ($s.Message) { ' | ' + $s.Message } else { '' }))
        $r = Invoke-SoloSd $SdExe '-start'
        Write-StartLog $LogFile ('sd-solo -start (second): exit ' + $r.Code + $(if ($r.Message) { ' | ' + $r.Message } else { '' }))
    }
    $up = Test-SdRunning
    Write-StartLog $LogFile ('result: sdwind running = ' + $up)
    if ($up) { return 0 } else { return 1 }
}

# Not run when a test loads the functions above out of the file.
if ($MyInvocation.InvocationName -ne '.' -and $AppDir) {
    exit (Start-SoloSd (Join-Path $AppDir 'usr\bin\sd-solo.exe') (Join-Path $AppDir 'solo-start.log'))
}
