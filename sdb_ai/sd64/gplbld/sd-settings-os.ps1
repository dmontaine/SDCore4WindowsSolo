# sd-settings-os.ps1 - the Windows sections of SETTINGS.REPORT, SD Core Solo
#
#   powershell -ExecutionPolicy Bypass -File "%USERPROFILE%\SDCoreSolo\sd-settings-os.ps1"
#
# Run by SD through !ps_script_out, from gpl.bp SETTINGS_OS (SOLO 25; the
# multi-user product's RELEASE_1.1 116, ported), as the Windows user.  Every
# report line is printed as "REPORT <text>", section headers as "REPORT [name]",
# and the LAST line on success is "SETTINGS-OS OK SECTIONS <n>" - the only text
# a caller may anchor on.  Exit 0 done, 1 failed.
#
# SOLO'S SECTIONS DIFFER FROM THE MULTI-USER COPY: sd.conf and sd-tls sit in the
# install folder (this script's own folder - sddefs.h, "sd.conf in the
# installation's own folder"), there is no service but the startup task "SD Core
# Solo" (solo-machine.ps1), and there are no SD groups and no os.users.
#
# THE REPORT IS REFERENCE TEXT THAT NOTHING READS BACK (owner, 1 Oct 2026), so a
# section that cannot be read says so in its own lines and the rest still go
# out.  A section with no data on this machine is left out, not printed empty.
#
# NEVER IN IT: a private key, $cred, a password.  api.pem holds the API's
# private key AND its certificate in one file, so only the CERTIFICATE block is
# ever decoded - Get-PemCertificates below.

param()

$ErrorActionPreference = 'Stop'

# --- pure helpers ------------------------------------------------------------

# The base64 bodies of every CERTIFICATE block in PEM text, and nothing else.
function Get-PemCertificates([string]$pem) {
    $out = @()
    $rx = [regex]'(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
    foreach ($m in $rx.Matches($pem)) { $out += ($m.Groups[1].Value -replace '\s', '') }
    return ,$out
}

# The sshd_config lines a reader of the report needs: active (uncommented)
# Port, ListenAddress, AllowGroups/AllowUsers/DenyGroups/DenyUsers, Match and
# ForceCommand lines.
function Select-SshdLines([string[]]$lines) {
    $keep = @()
    foreach ($l in $lines) {
        $t = $l.Trim()
        if ($t -match '^(?i)(Port|ListenAddress|AllowGroups|AllowUsers|DenyGroups|DenyUsers|Match|ForceCommand)\b') { $keep += $t }
    }
    return ,$keep
}

# sd.conf lines worth reporting: everything but blanks and comments.
function Select-ConfLines([string[]]$lines) {
    $keep = @()
    foreach ($l in $lines) {
        $t = $l.Trim()
        if ($t -ne '' -and -not $t.StartsWith('#')) { $keep += $t }
    }
    return ,$keep
}

# --- sections ----------------------------------------------------------------

$script:sections = 0
function Section([string]$name) { Write-Output "REPORT [$name]"; $script:sections++ }
function Line([string]$text) { Write-Output "REPORT $text" }
function Failed([string]$what) { Line "(could not be read: $what)" }

$appDir = $PSScriptRoot

try {
    # sd.conf
    $conf = Join-Path $appDir 'sd.conf'
    if (Test-Path -LiteralPath $conf) {
        Section 'sd.conf'
        Line "file: $conf"
        try { foreach ($l in (Select-ConfLines ([System.IO.File]::ReadAllLines($conf)))) { Line $l } }
        catch { Failed $_.Exception.Message }
    }

    # ssh - SOLO 28: Solo's OWN sshd, <app>\ssh, started at boot by the task "SD Core Solo
    # SSH".  The Windows OpenSSH Server service and its sshd_config are not Solo's any
    # more and are not reported; no key text is printed, only a count.
    $sshDir = Join-Path $appDir 'ssh'
    $sshCfg = Join-Path $sshDir 'sshd_config'
    $sshTask = Get-ScheduledTask -TaskName 'SD Core Solo SSH' -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $sshCfg) -or $sshTask) {
        Section 'ssh'
        Line 'SD Core Solo runs its own sshd; it does not use the Windows OpenSSH Server service'
        if (Test-Path -LiteralPath $sshCfg) {
            Line "file: $sshCfg"
            try {
                $cfgLines = [System.IO.File]::ReadAllLines($sshCfg)
                foreach ($l in (Select-SshdLines $cfgLines)) { Line $l }
                if (@($cfgLines | Where-Object { $_.Trim() -match '^(?i)AuthenticationMethods\s+publickey$' }).Count -gt 0) {
                    Line 'logins: public key only'
                }
            } catch { Failed $_.Exception.Message }
            $akf = Join-Path $sshDir 'authorized_keys'
            if (Test-Path -LiteralPath $akf) {
                try {
                    $n = @([System.IO.File]::ReadAllLines($akf) | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') }).Count
                    Line "keys in ${akf}: $n"
                } catch { Failed "key file - $($_.Exception.Message)" }
            } else { Line "key file: none yet ($akf)" }
            # By the PORT, not by command line.  A process the startup task started has no readable
            # path, command line or owner from an ordinary shell of the same user (measured 2 Oct
            # 2026), so a search by command line says "not running" about a running sshd.
            try {
                $lst = @(Get-NetTCPConnection -State Listen -LocalPort 4251 -ErrorAction SilentlyContinue)
                if ($lst.Count -gt 0) { Line "Solo's ssh port 4251: listening (pid $($lst[0].OwningProcess))" } else { Line "Solo's ssh port 4251: not listening" }
            } catch { Failed "ssh port - $($_.Exception.Message)" }
        }
        if ($sshTask) {
            try {
                $ti = $sshTask | Get-ScheduledTaskInfo
                Line ("SD Core Solo SSH task: {0}, last run {1:yyyy-MM-dd HH:mm}, result 0x{2:X}" -f $sshTask.State, $ti.LastRunTime, $ti.LastTaskResult)
            } catch { Failed "ssh task info - $($_.Exception.Message)" }
        } else { Line 'SD Core Solo SSH task: not registered' }
    }

    # api
    $pem = Join-Path $appDir 'sd-tls\api.pem'
    # 01 Oct 26 - Solo's rule has its own name; SD-API-In-TCP is the full product's
    # (api-firewall.ps1), and listing it here would report another product's rule.
    $apiRule = Get-NetFirewallRule -Name 'SD-Solo-API-In-TCP' -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $pem) -or $apiRule) {
        Section 'api'
        if (Test-Path -LiteralPath $pem) {
            try {
                $certs = Get-PemCertificates ([System.IO.File]::ReadAllText($pem))
                if ($certs.Count -eq 0) { Line "certificate: none in $pem" }
                foreach ($b in $certs) {
                    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($b))
                    Line "certificate subject: $($c.Subject)"
                    Line ("certificate expires: {0:yyyy-MM-dd HH:mm}" -f $c.NotAfter)
                    Line "certificate thumbprint: $($c.Thumbprint)"
                }
            } catch { Failed "certificate in $pem - $($_.Exception.Message)" }
        } else {
            Line 'certificate: not yet generated'
        }
    }

    # firewall
    # SOLO 28: Solo's ssh rule is SD-Solo-SSH-In-TCP (solo-ssh-firewall.ps1); Microsoft's
    # "OpenSSH SSH Server" rule for port 22 is not Solo's and is no longer listed.
    $rules = @()
    if ($apiRule) { $rules += $apiRule }
    $rules += @(Get-NetFirewallRule -Name 'SD-Solo-SSH-In-TCP' -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 0) {
        Section 'firewall'
        foreach ($r in $rules) {
            try {
                $port = ($r | Get-NetFirewallPortFilter).LocalPort -join ','
                $addr = ($r | Get-NetFirewallAddressFilter).RemoteAddress -join ','
                Line "$($r.DisplayName): enabled $($r.Enabled), $($r.Action), port $port, from $addr"
            } catch { Failed "$($r.DisplayName) - $($_.Exception.Message)" }
        }
    }

    # startup task - Solo's daemon starts from it, not from a service
    $task = Get-ScheduledTask -TaskName 'SD Core Solo' -ErrorAction SilentlyContinue
    if ($task) {
        Section 'startup task'
        Line "SD Core Solo task: $($task.State)"
        try {
            $ti = $task | Get-ScheduledTaskInfo
            Line ("last run: {0:yyyy-MM-dd HH:mm}, result 0x{1:X}" -f $ti.LastRunTime, $ti.LastTaskResult)
        } catch { Failed "task info - $($_.Exception.Message)" }
    }

    Write-Output "SETTINGS-OS OK SECTIONS $($script:sections)"
    exit 0
} catch {
    Write-Output "SETTINGS-OS ERROR $($_.Exception.Message)"
    exit 1
}
