# solo-sshkey.ps1 - add, remove or list the SD Core server's ssh keys for THIS user.
# Run by gpl.bp/apisrvr (API request 49, SrvrSshKey) in the signed-in user's own
# process.  UNELEVATED BY DESIGN: it writes only <app>\ssh\authorized_keys.
#
#   powershell -File solo-sshkey.ps1 -Verb ADD    -Key '<one-line public key>'
#   powershell -File solo-sshkey.ps1 -Verb REMOVE -Fingerprint 'SHA256:...'
#   powershell -File solo-sshkey.ps1 -Verb LIST
#
# SOLO 24, 30 Sep 2026, agreed with the Linux Solo agent (Linux does the same job
# with tools/solo-ssh.sh key-add|key-remove|key-list).  What the master sees is the
# same on both systems; this is only the Windows method.
#
# SOLO 28, 2 Oct 2026 - THE KEY FILE MOVED.  Solo's ssh is now its OWN sshd on port 4251
# (solo-sshd.ps1), run by the Solo owner, and it reads ITS OWN key file,
# <app>\ssh\authorized_keys - not the user's ~\.ssh\authorized_keys, which the system sshd's
# "Match User" block used to read.  The owner's ruling (via the Linux agent, mail T3410/T3510):
# Solo has ONE route, its own sshd and its own key file.  That also ends the old problem this
# header used to explain at length - Win32-OpenSSH reads a ProgramData file only an elevated
# process can write for a user in Administrators - because Solo's sshd has no such Match block:
# it reads the file named in its own configuration for everybody.
#
# THE HELPER PREPARES FIRST.  Every verb runs "solo-sshd.ps1 -Prepare" (idempotent: it makes the
# folder, host key, configuration and key file if missing, and moves the master's old key lines out
# of ~\.ssh\authorized_keys), so what it reports is what sshd will read.  ADD refuses when there is
# no sshd.exe on this computer at all, because a key line that nothing will ever read is worse than
# a refusal.
#
# OUTPUT, one machine-readable line each (anchor on these, nothing else):
#   OSUSER=<name as sshd matches it>   HOSTKEY=<SHA256:...>   PORT=<Solo's ssh port, 4251>
#   FPR=<SHA256:...>                   COUNT=<our lines now>
#   RESULT=ADDED|PRESENT|REMOVED|ABSENT|LISTED
#   ERROR=<text>                       (exit 1; nothing was changed)
# Exit 0 only with a RESULT= line.  HOSTKEY is now Solo's OWN sshd's ed25519 host key, read from
# <app>\ssh\ssh_host_ed25519_key.pub (readable by the user - no elevated step records it any more);
# before this change it was the system sshd's, read from a file an elevated step had written.
# PORT is new: the master needs it to reach Solo's sshd; apisrvr appends it to the ADD answer.
#
# OUR LINES are "restrict <type> <key> sdcoresolo-managed" and nothing else is ever
# added, listed or removed: any other line in the file is the owner's own and is never touched.
# At most 4.

param(
    [Parameter(Mandatory = $true)] [ValidateSet('ADD', 'REMOVE', 'LIST')] [string]$Verb,
    [string]$Key = '',
    [string]$Fingerprint = ''
)

$ErrorActionPreference = 'Stop'
$Tag = 'sdcoresolo-managed'
$Cap = 4

function Stop-With([string]$m) { Write-Output ('ERROR=' + $m); exit 1 }

function Get-Fingerprint([string]$b64) {
    try { $bytes = [Convert]::FromBase64String($b64) } catch { return '' }
    if ($bytes.Length -lt 8) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    return 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash($bytes)).TrimEnd('=')
}

# ---- prepare Solo's sshd files and read what it says ---------------------------------------
$prep = Join-Path $PSScriptRoot 'solo-sshd.ps1'
if (-not (Test-Path -LiteralPath $prep)) { Stop-With 'solo-sshd.ps1 is missing from the Solo folder' }
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$prepOut = Join-Path $env:TEMP ('sdsolo-prepare-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
try {
    # Start-Process to a file, not "2>&1": under ErrorActionPreference Stop a native command's stderr
    # is a terminating error even on success (PROJECT_STATUS 6).
    $null = Start-Process -FilePath $psExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $prep + '"'), '-Prepare') `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $prepOut
    $facts = @()
    if (Test-Path -LiteralPath $prepOut) { $facts = @([IO.File]::ReadAllLines($prepOut)) }
}
finally { Remove-Item -LiteralPath $prepOut -Force -ErrorAction SilentlyContinue }
$osUser = ''; $hostKey = ''; $port = ''; $ak = ''
foreach ($l in $facts) {
    $l = $l.Trim()
    if ($l.StartsWith('OSUSER=')) { $osUser = $l.Substring(7) }
    elseif ($l.StartsWith('HOSTKEY=')) { $hostKey = $l.Substring(8) }
    elseif ($l.StartsWith('PORT=')) { $port = $l.Substring(5) }
    elseif ($l.StartsWith('KEYFILE=')) { $ak = $l.Substring(8) }
    elseif ($l.StartsWith('ERROR=')) { Stop-With ('ssh is not set up for SD Core Solo (' + $l.Substring(6) + ')') }
}
if (-not ($facts -contains 'RESULT=PREPARED')) { Stop-With 'ssh is not set up for SD Core Solo (its sshd files could not be prepared)' }
if ($ak -eq '' -or $osUser -eq '' -or $port -notmatch '^\d+$') { Stop-With 'ssh is not set up for SD Core Solo (its sshd did not answer)' }
if ($hostKey -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') { $hostKey = '' }

$lines = @()
if (Test-Path -LiteralPath $ak) { $lines = @([IO.File]::ReadAllLines($ak)) }
$ours = @($lines | Where-Object { $_ -match ('^restrict\s+\S+\s+\S+\s+' + $Tag + '$') })

function Get-LineFpr([string]$line) {
    $p = $line -split '\s+'
    if ($p.Count -lt 3) { return '' }
    return (Get-Fingerprint $p[2])
}

function Write-Lines([string[]]$l) {
    [IO.File]::WriteAllLines($ak, $l, (New-Object Text.UTF8Encoding($false)))
}

Write-Output ('OSUSER=' + $osUser)
Write-Output ('HOSTKEY=' + $hostKey)
Write-Output ('PORT=' + $port)

switch ($Verb) {
    'LIST' {
        foreach ($l in $ours) { Write-Output ('FPR=' + (Get-LineFpr $l)) }
        Write-Output ('COUNT=' + $ours.Count)
        Write-Output 'RESULT=LISTED'
    }
    'REMOVE' {
        if ($Fingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') { Stop-With 'not a SHA256 fingerprint' }
        $keep = @(); $gone = 0
        foreach ($l in $lines) {
            if ($ours -contains $l -and (Get-LineFpr $l) -eq $Fingerprint) { $gone++ } else { $keep += $l }
        }
        if ($gone -gt 0) { Write-Lines ([string[]]$keep) }
        Write-Output ('COUNT=' + ($ours.Count - $gone))
        if ($gone -gt 0) { Write-Output 'RESULT=REMOVED' } else { Write-Output 'RESULT=ABSENT' }
    }
    'ADD' {
        $parts = $Key.Trim() -split '\s+'
        if ($parts.Count -lt 2) { Stop-With 'not a public key line' }
        if ($parts[0] -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)$') { Stop-With 'unsupported key type' }
        if ($parts[1] -notmatch '^[A-Za-z0-9+/]+={0,2}$') { Stop-With 'the key is not base64' }
        $fpr = Get-Fingerprint $parts[1]
        if ($fpr -eq '') { Stop-With 'the key does not decode' }

        # Refuse unless there is an sshd on this computer to read the file at all.
        $hasSshd = (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe')) -or
                   (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))
        if (-not $hasSshd) { Stop-With 'ssh is not set up for SD Core Solo (there is no sshd.exe on this computer)' }

        foreach ($l in $ours) {
            if ((Get-LineFpr $l) -eq $fpr) {
                Write-Output ('FPR=' + $fpr); Write-Output ('COUNT=' + $ours.Count)
                Write-Output 'RESULT=PRESENT'
                exit 0
            }
        }
        if ($ours.Count -ge $Cap) { Stop-With ('already ' + $Cap + ' SD Core Solo keys installed') }
        Write-Lines ([string[]]($lines + ('restrict ' + $parts[0] + ' ' + $parts[1] + ' ' + $Tag)))
        Write-Output ('FPR=' + $fpr); Write-Output ('COUNT=' + ($ours.Count + 1))
        Write-Output 'RESULT=ADDED'
    }
}

exit 0
