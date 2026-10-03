# solo-ssh-firewall.ps1 - decide whether other computers may reach SD Core Solo's own ssh
# port.  SOLO 28 (the multi-user port's RELEASE_1.1 118), modelled on api-firewall.ps1.
#
#   powershell -ExecutionPolicy Bypass -File solo-ssh-firewall.ps1 -Open              any address
#   powershell -ExecutionPolicy Bypass -File solo-ssh-firewall.ps1 -Restrict          this machine only
#   powershell -ExecutionPolicy Bypass -File solo-ssh-firewall.ps1 -Remove            take the rule away
#   powershell -ExecutionPolicy Bypass -File solo-ssh-firewall.ps1 -Show              report, change nothing
#   powershell -ExecutionPolicy Bypass -File solo-ssh-firewall.ps1 -ScopeFile <path>  write one word and stop
#
# Exit 0 applied, 1 failed, 2 refused.  ELEVATED for -Open, -Restrict and -Remove: creating a
# firewall rule is a machine-wide change, and it is the one step of Solo's ssh that still needs
# an administrator (the sshd itself does not - solo-sshd.ps1).  -Show and -ScopeFile are
# read-only and take no elevation gate.
#
# THE PORT IS 4251 AND THERE IS NO -Port.  The owner ruled it (2 Oct 2026, via the Linux agent,
# mail T3410): Solo's ssh has its OWN port, fixed and not adjustable, next to the API pair
# 4247/4249; the full product keeps the system sshd on 22.  This script does NOT touch Microsoft's
# OpenSSH-Server-In-TCP rule for 22 - that is the full product's (ssh-firewall.ps1 there) and an
# earlier Solo build's "ssh firewall scope" choice is gone with the system-sshd route.
#
# THE RULE IS OURS, AND THE NAME SAYS SO: SD-Solo-SSH-In-TCP.  Nothing else creates a rule for
# 4251, so this script owns it - it makes it and -Remove takes it away at uninstall.  RemoteAddress,
# not Enabled=False, for -Restrict: both leave a local client working because Windows does not
# filter loopback, but a DISABLED rule reads as something that got switched off.
#
# ***NO '::1'.  WINDOWS REFUSES ANY IPv6 LOOPBACK LITERAL IN -RemoteAddress*** and then leaves the
# rule at RemoteAddress=Any (api-firewall.ps1 has the whole story, 30 Aug 2026).  Loopback is not
# filtered by Windows Firewall at all, so 127.0.0.1 alone loses nothing.
#
# THE VERDICT IS GATED ON A READ-BACK, NOT ON HAVING MADE THE CALL (PRE_RELEASE_FIXES 81): the
# rule is re-read and compared with what was asked for, because a CIM error came back
# NON-TERMINATING once and the script went on to report success over an open port.
#
# NOT MEASURED: that Windows Firewall admits a REMOTE client to 4251 through this rule (only
# loopback was exercised); that is a cycle-time witness from a second computer.

param(
    [switch]$Open,
    [switch]$Restrict,
    [switch]$Remove,
    [switch]$Show,
    [string]$ScopeFile = ''
)

$ErrorActionPreference = 'Stop'

# SOLO_SSH_PORT.  Not a parameter, on purpose - see the header.  solo-sshd.ps1 carries the same
# number and test-solosshd-units.ps1 checks the two agree.
$Port = 4251

$ruleName    = 'SD-Solo-SSH-In-TCP'
$displayName = 'SD Core Solo ssh (port 4251)'

function Get-SshPortRule {
    return (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
}

# THE PORT THE RULE NAMES, as text ('' when there is no rule).
function Get-RulePort($rule) {
    if ($null -eq $rule) { return '' }
    return [string](($rule | Get-NetFirewallPortFilter).LocalPort)
}

function Test-RulePortOk($rule) {
    return ((Get-RulePort $rule) -eq [string]$Port)
}

# ONE PLACE DECIDES OPEN OR SHUT: -ScopeFile, -Show and the read-back verdict below all come
# here, so the three cannot disagree.  A LIST, NOT A SCALAR - RemoteAddress can hold several
# entries - and a missing rule is not open.
function Test-RuleOpen($rule) {
    if ($null -eq $rule) { return $false }
    $addrs = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
    return ($addrs -contains 'Any')
}

function Write-State($rule) {
    if ($null -eq $rule) {
        Write-Output '  rule: not present'
        return
    }
    $filter = $rule | Get-NetFirewallPortFilter
    $addr   = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
    Write-Output ('  rule: {0}  Enabled {1}  Direction {2}  Action {3}' -f
                  $rule.Name, $rule.Enabled, $rule.Direction, $rule.Action)
    Write-Output ('        LocalPort {0}  RemoteAddress {1}' -f
                  $filter.LocalPort, ($addr -join ', '))
}

try {
    # ANSWERED FIRST and before the elevation gate: it changes nothing, and a caller that gets no
    # answer is worse than one that gets "none".  THREE ANSWERS, because the rule is ours and
    # may be ABSENT.  A rule that names another port admits nothing on this one, so it is 'none'.
    if ($ScopeFile -ne '') {
        $rule = Get-SshPortRule
        if (($null -eq $rule) -or (-not (Test-RulePortOk $rule))) { $verdict = 'none' }
        elseif (Test-RuleOpen $rule)                              { $verdict = 'open' }
        else                                                      { $verdict = 'restricted' }
        [System.IO.File]::WriteAllText($ScopeFile, $verdict, [System.Text.Encoding]::ASCII)
        Write-Output ('solo-ssh-firewall: current scope is ' + $verdict)
        exit 0
    }

    if ($Show) {
        $rule = Get-SshPortRule
        Write-State $rule
        if ($null -eq $rule) {
            Write-Output ('solo-ssh-firewall: state is OFF at the firewall - no rule, so only this computer may reach ssh port ' + $Port)
        } elseif (-not (Test-RulePortOk $rule)) {
            Write-Output ('solo-ssh-firewall: state is OFF at the firewall - the rule is for port ' +
                          (Get-RulePort $rule) + ' and Solo''s ssh is on port ' + $Port +
                          ', so only this computer may reach it')
        } elseif (Test-RuleOpen $rule) {
            Write-Output ('solo-ssh-firewall: state is ON - other computers on your network may reach ssh port ' + $Port)
        } else {
            Write-Output ('solo-ssh-firewall: state is LOCAL - only this computer may reach ssh port ' + $Port)
        }
        exit 0
    }

    $modes = @($Open, $Restrict, $Remove) | Where-Object { $_ }
    if ($modes.Count -ne 1) {
        Write-Output 'solo-ssh-firewall: give exactly one of -Open, -Restrict, -Remove or -Show'
        exit 1
    }

    $pr = New-Object Security.Principal.WindowsPrincipal(
              [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Output 'solo-ssh-firewall: this needs an ELEVATED PowerShell - a firewall rule is machine-wide.'
        exit 2
    }

    if ($Remove) {
        $rule = Get-SshPortRule
        if ($null -eq $rule) {
            Write-Output 'solo-ssh-firewall: no rule to remove'
            exit 0
        }
        Remove-NetFirewallRule -Name $ruleName
        if ($null -ne (Get-SshPortRule)) {
            Write-Output "solo-ssh-firewall: FAILED - $ruleName is still there after Remove-NetFirewallRule"
            exit 1
        }
        Write-Output "solo-ssh-firewall: removed $ruleName"
        exit 0
    }

    $remote = if ($Open) { 'Any' } else { '127.0.0.1' }

    # IDEMPOTENT, because the installer runs it on every install including a reinstall: an
    # existing rule is UPDATED, not removed and remade (remaking loses any grouping or profile
    # scoping an administrator applied by hand, and leaves a window with no rule).
    $rule = Get-SshPortRule
    if ($null -eq $rule) {
        $null = New-NetFirewallRule -Name $ruleName -DisplayName $displayName `
                    -Description ('Inbound TCP for SD Core Solo''s own ssh server (solo-sshd.ps1), which the ' +
                                  'SD Core Solo SSH startup task runs as the Solo owner.') `
                    -Direction Inbound -Protocol TCP -LocalPort $Port `
                    -Action Allow -Enabled True -RemoteAddress $remote
        Write-Output "solo-ssh-firewall: created $ruleName for port $Port"
    }
    else {
        Set-NetFirewallRule -Name $ruleName -LocalPort $Port -Protocol TCP `
                            -Enabled True -RemoteAddress $remote
        Write-Output "solo-ssh-firewall: updated $ruleName for port $Port"
    }

    # THE READ-BACK GATE (see the header).  The state compared is the state on the machine, not
    # the state the script intended to set.
    $applied = Get-SshPortRule
    $addrs   = @($applied | Get-NetFirewallAddressFilter).RemoteAddress
    $isOpen  = Test-RuleOpen $applied

    if (($null -eq $applied) -or (-not (Test-RulePortOk $applied)) -or ($isOpen -ne [bool]$Open)) {
        Write-Output ('solo-ssh-firewall: FAILED - the rule does not read back as asked.  Asked for port ' + $Port +
                      ', ' + $(if ($Open) { 'Any' } else { $remote }) + '; the rule reads port ' + (Get-RulePort $applied) +
                      ', ' + ($addrs -join ','))
        Write-State $applied
        exit 1
    }

    if ($Open) {
        Write-Output "solo-ssh-firewall: other computers MAY reach Solo's ssh on port $Port"
    } else {
        Write-Output "solo-ssh-firewall: Solo's ssh is reachable FROM THIS MACHINE ONLY"
    }

    Write-State $applied
    exit 0
}
catch {
    Write-Output ('solo-ssh-firewall: FAILED - ' + $_.Exception.Message)
    Write-Output $_.ScriptStackTrace
    exit 1
}
