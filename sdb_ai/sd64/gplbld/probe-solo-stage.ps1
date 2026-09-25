# probe-solo-stage.ps1 - SOLO 2's witness, run in an ELEVATED PowerShell.
#
# 1. stage.py --bootstrap into <repo>\stage, exactly as cycle.ps1 step 2 does
#    (MSYS2 login shell, output to the console - see cycle.ps1 on why not a pipe).
# 2. probe-solo-stage.py against that tree with SD_CONFIG removed: does the
#    staged sd.exe find sd.conf, SDSYS and the account folders from its own
#    location?  Its output is also written to <repo>\stage\probe-solo-stage.log.
#
# Installs nothing and touches nothing outside <repo>\stage.  Elevated because
# the bootstrap's "sd -internal" sessions need it (bootstrap.py says so too).

$ErrorActionPreference = 'Stop'
$Sd64  = Split-Path -Parent $PSScriptRoot
$Repo  = Split-Path -Parent (Split-Path -Parent $Sd64)
$Stage = Join-Path $Repo 'stage'
$Log   = Join-Path $Stage 'probe-solo-stage.log'
$Bash  = 'C:\msys64\usr\bin\bash.exe'

function ToMsys([string] $p) {
    $p = $p -replace '\\', '/'
    if ($p -match '^([A-Za-z]):(.*)$') { return "/$($Matches[1].ToLower())$($Matches[2])" }
    return $p
}

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "probe-solo-stage.ps1"
Write-Host "  sd64     $Sd64"
Write-Host "  stage    $Stage"
Write-Host "  log      $Log"
Write-Host "  elevated $elevated"
if (-not $elevated) { Write-Host 'REFUSED: run this from an ELEVATED PowerShell.'; exit 2 }
if (-not (Test-Path -LiteralPath $Bash)) { Write-Host "REFUSED: no MSYS2 bash at $Bash"; exit 2 }

Write-Host ''
Write-Host '=== 1. stage.py --bootstrap ==='
$cmd = "cd '$(ToMsys $Sd64)' && python3 gplbld/stage.py --stage '$(ToMsys $Stage)' --force --bootstrap"
Write-Host "  bash -lc $cmd"
& $Bash -lc $cmd
$stageExit = $LASTEXITCODE
Write-Host "  stage.py exit $stageExit"
if ($stageExit -ne 0) { Write-Host 'FAILED at staging - nothing to probe.'; exit 1 }

Write-Host ''
Write-Host '=== 2. probe-solo-stage.py (SD_CONFIG removed) ==='
$cmd = "cd '$(ToMsys $Sd64)' && python3 gplbld/probe-solo-stage.py --stage '$(ToMsys $Stage)' 2>&1 | tee '$(ToMsys $Log)'; exit `${PIPESTATUS[0]}"
Write-Host "  bash -lc $cmd"
& $Bash -lc $cmd
$probeExit = $LASTEXITCODE
Write-Host ''
Write-Host "probe-solo-stage.ps1: stage.py exit $stageExit, probe exit $probeExit"
Write-Host "  log: $Log"
exit $probeExit
