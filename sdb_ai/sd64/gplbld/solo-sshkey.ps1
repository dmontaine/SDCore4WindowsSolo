# solo-sshkey.ps1 - add, remove or list the SD Core server's ssh keys for THIS user.
# Run by gpl.bp/apisrvr (API request 49, SrvrSshKey) in the signed-in user's own
# process.  UNELEVATED BY DESIGN: it writes only %USERPROFILE%\.ssh\authorized_keys.
#
#   powershell -File solo-sshkey.ps1 -Verb ADD    -Key '<one-line public key>'
#   powershell -File solo-sshkey.ps1 -Verb REMOVE -Fingerprint 'SHA256:...'
#   powershell -File solo-sshkey.ps1 -Verb LIST
#
# SOLO 24, 30 Sep 2026, agreed with the Linux Solo agent (Linux does the same job
# with tools/solo-ssh.sh key-add|key-remove|key-list).  What the master sees is the
# same on both systems; this is only the Windows method.
#
# WHY THE USER'S OWN FILE WORKS FOR AN ADMINISTRATOR: Win32-OpenSSH reads
# %ProgramData%\ssh\administrators_authorized_keys for a user in Administrators,
# a file only an elevated process can write - unless the user's own Match block
# comes BEFORE the stock "Match Group administrators" block and names
# "AuthorizedKeysFile .ssh/authorized_keys".  Measured 30 Sep 2026
# (probe-sshd-keyfile.ps1).  solo-machine.ps1 writes the block in that position;
# ADD refuses when it is not there, because a key line that sshd never reads, or
# one that gave a shell, is worse than a refusal.
#
# OUTPUT, one machine-readable line each (anchor on these, nothing else):
#   OSUSER=<name as sshd matches it>   HOSTKEY=<SHA256:... or empty>
#   FPR=<SHA256:...>                   COUNT=<our lines now>
#   RESULT=ADDED|PRESENT|REMOVED|ABSENT|LISTED
#   ERROR=<text>                       (exit 1; nothing was changed)
# Exit 0 only with a RESULT= line.
#
# OUR LINES are "restrict <type> <key> sdcoresolo-managed" and nothing else is ever
# added, listed or removed: the user's own keys are never touched.  At most 4.

param(
    [Parameter(Mandatory = $true)] [ValidateSet('ADD', 'REMOVE', 'LIST')] [string]$Verb,
    [string]$Key = '',
    [string]$Fingerprint = ''
)

$ErrorActionPreference = 'Stop'
$Tag = 'sdcoresolo-managed'
$Cap = 4
$Begin = '# BEGIN SD Core Solo - added by its installer, removed by its uninstaller'
$End = '# END SD Core Solo'

function Stop-With([string]$m) { Write-Output ('ERROR=' + $m); exit 1 }

function Get-Fingerprint([string]$b64) {
    try { $bytes = [Convert]::FromBase64String($b64) } catch { return '' }
    if ($bytes.Length -lt 8) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    return 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash($bytes)).TrimEnd('=')
}

function Get-OsUser {
    $n = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $u = $n.Split('\')
    $name = $u[$u.Count - 1]
    if ($u.Count -gt 1 -and $u[0] -ine $env:COMPUTERNAME) { $name = $name + '@' + $u[0] }
    return $name.ToLower()
}

$home1 = $env:USERPROFILE
if (-not $home1) { Stop-With 'no user profile folder' }
$sshDir = Join-Path $home1 '.ssh'
$ak = Join-Path $sshDir 'authorized_keys'

$lines = @()
if (Test-Path -LiteralPath $ak) { $lines = @([IO.File]::ReadAllLines($ak)) }
$ours = @($lines | Where-Object { $_ -match ('^restrict\s+\S+\s+\S+\s+' + $Tag + '$') })

function Get-LineFpr([string]$line) {
    $p = $line -split '\s+'
    if ($p.Count -lt 3) { return '' }
    return (Get-Fingerprint $p[2])
}

function Write-Lines([string[]]$l) {
    if (-not (Test-Path -LiteralPath $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
    [IO.File]::WriteAllLines($ak, $l, (New-Object Text.UTF8Encoding($false)))
}

Write-Output ('OSUSER=' + (Get-OsUser))

# sshd's own host key, so the master can pin it.  Empty when unknown.  The key's
# .pub is in ProgramData\ssh and NOT readable unelevated (measured 30 Sep 2026), so
# the elevated installer records the fingerprint in sdsys\ssh-hostkey (SOLO 24);
# the .pub is only a fallback for a machine where it happens to be readable.
$hk = ''
try {
    $rec = Join-Path $PSScriptRoot 'sdsys\ssh-hostkey'
    if (Test-Path -LiteralPath $rec) {
        $line = ([IO.File]::ReadAllText($rec).Trim())
        if ($line -match '^SHA256:[A-Za-z0-9+/]{43}$') { $hk = $line }
    }
} catch { $hk = '' }
if ($hk -eq '') {
    $pub = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub'
    try {
        $t = ([IO.File]::ReadAllText($pub).Trim() -split '\s+')
        if ($t.Count -ge 2) { $hk = Get-Fingerprint $t[1] }
    } catch { $hk = '' }
}
Write-Output ('HOSTKEY=' + $hk)

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

        # Refuse unless sshd will read THIS file and force sd.exe for this user.
        $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
        if (-not (Test-Path -LiteralPath $cfg)) { Stop-With 'ssh is not set up for SD Core Solo (no sshd_config)' }
        $c = @([IO.File]::ReadAllLines($cfg))
        $bi = [Array]::IndexOf($c, $Begin); $ei = [Array]::IndexOf($c, $End)
        if ($bi -lt 0 -or $ei -lt $bi) { Stop-With 'ssh is not set up for SD Core Solo (its sshd_config block is missing)' }
        $blk = $c[$bi..$ei] -join "`n"
        if ($blk -notmatch 'ForceCommand' -or $blk -notmatch 'AuthorizedKeysFile\s+\.ssh/authorized_keys') {
            Stop-With 'ssh is not set up for SD Core Solo (its sshd_config block does not read the user key file)'
        }
        $firstMatch = -1
        for ($i = 0; $i -lt $c.Count; $i++) { if ($c[$i] -match '^\s*Match\s') { $firstMatch = $i; break } }
        if ($firstMatch -lt $bi -or $firstMatch -gt $ei) { Stop-With 'ssh is not set up for SD Core Solo (its block is not ahead of the other Match blocks)' }

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
