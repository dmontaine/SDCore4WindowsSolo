#!/usr/bin/env python3
"""test-soloport22-units.py - a Solo install does not leave port 22 open (SOLO 84).

    python C:\\Users\\Don\\SDCoreProject\\SDCore4WindowsSolo\\sdb_ai\\sd64\\gplbld\\test-soloport22-units.py [--selftest]

The owner, 21 Nov 2026: "Since we use non-standard ports in solo, we can assume that if they are open we have done it.  Port 22 should not
be opened by a solo install as we dont use it."  Microsoft's OpenSSH MSI, which Solo's installer runs when the computer has no ssh server,
starts the system sshd SERVICE on port 22 and opens its rule (sit9).  Solo's own sshd runs sshd.exe from its own task on 4251.
FREE: reads solo-machine.ps1 only.  Exit 0 every check passed, 1 a check failed, 2 it could not run.

WHAT IT HOLDS:
  P1  Install-SshMsi returns before the MSI when an ssh server is already here, reads port 22 before the MSI, and calls Close-MsiPort22
      only after the MSI ran and its programs were checked, and only when 22 was closed before (the owner, 21 Nov: "if 22 is already
      open at the time of the install we do not manage it") - so a server or a port Solo did not open is never closed
  P2  Close-MsiPort22 stops the system sshd, sets it Disabled, disables the MSI's port-22 rule, reads all three back and fails out loud
  P3  Close-MsiPort22 is called from nowhere else, and nothing else in the script stops or disables the system sshd or a port-22 rule
--selftest breaks each the way an edit plausibly would and requires the check aimed at it to notice.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MACHINE = os.path.join(HERE, "solo-machine.ps1")


def ps_code(src):
    return "\n".join(ln for ln in src.split("\n") if not re.match(r"^\s*#", ln))


def ps_func(text, name):
    m = re.search(r"^function " + re.escape(name) + r"\b.*?^\}\s*$", text, re.M | re.S)
    return m.group(0) if m else ""


def checks(raw):
    rows = []
    mc = ps_code(raw)
    ism = ps_func(mc, "Install-SshMsi")
    cl = ps_func(mc, "Close-MsiPort22")
    i_exist = ism.find("if ($existing) {")
    i_ret = ism.find("return }", i_exist)
    i_msi = ism.find("Start-Process -FilePath $msiexec")
    i_pass = ism.find("PASS  OpenSSH server programs installed")
    i_close = ism.find("Close-MsiPort22")
    i_was = ism.find("$was22 = @(Get-NetTCPConnection -State Listen -LocalPort 22")
    rows.append(("P1", "Install-SshMsi returns before the MSI when a server is already here, reads port 22 before the MSI, and closes it only after the MSI ran, its programs were checked, and only when 22 was closed before",
                 ism != "" and 0 < i_exist < i_ret < i_was < i_msi < i_pass < i_close and ism.count("Close-MsiPort22") == 1
                 and "if ($was22) { Note '  port 22 was open before this install: left as it is" in ism and "else { Close-MsiPort22 }" in ism
                 and "Get-NetFirewallRule -Direction Inbound -Enabled True" in ism,
                 repr((i_exist, i_ret, i_was, i_msi, i_pass, i_close))))
    rows.append(("P2", "Close-MsiPort22 stops the system sshd, sets it Disabled, disables the port-22 rule, reads them back, and fails out loud",
                 cl != "" and "Stop-Service sshd -Force" in cl and "Set-Service sshd -StartupType Disabled" in cl
                 and "Disable-NetFirewallRule -Name $r.Name" in cl and "Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'" in cl
                 and "[string]$svc.StartType -ne 'Disabled'" in cl and "Get-NetTCPConnection -State Listen -LocalPort 22" in cl
                 and cl.find("Set-Service sshd") < cl.find("Fail 'port 22"), ""))
    rest = mc.replace(cl, "")
    rows.append(("P3", "Close-MsiPort22 is called only from Install-SshMsi, and nothing else stops or disables the system sshd or a port-22 rule",
                 mc.count("Close-MsiPort22") == 2 and "Stop-Service sshd" not in rest and "Set-Service sshd" not in rest
                 and "Disable-NetFirewallRule" not in rest, ""))
    return rows


def sub(old, new):
    return lambda raw: raw.replace(old, new, 1) if old in raw else None


MUTANTS = [
    ("an existing server is closed too", "P1", sub("    Note ('  msi sha256 : '", "    Close-MsiPort22\n    Note ('  msi sha256 : '")),
    ("port 22 is left open after the MSI", "P1", sub("    else { Close-MsiPort22 }\n", "")),
    ("a port 22 open before the install is closed too", "P1", sub("    if ($was22) { Note '  port 22 was open before this install: left as it is (Solo does not manage a port it did not open)' }\n    else { Close-MsiPort22 }", "    Close-MsiPort22")),
    ("the service is stopped but still starts at boot", "P2", sub("        Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue\n", "")),
    ("the rule stays on", "P2", sub("    foreach ($r in $rules) { Disable-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue }\n", "")),
    ("the uninstall closes port 22 as well", "P3", sub("        $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @('-Remove')\n", "        Close-MsiPort22\n        $c = Invoke-Shipped 'solo-ssh-firewall.ps1' @('-Remove')\n")),
]


def main(argv):
    try:
        with open(MACHINE, encoding="latin-1", newline="") as f:
            raw = f.read().replace("\r\n", "\n")
    except OSError as e:
        print("test-soloport22-units: CANNOT RUN - " + str(e))
        return 2
    print("test-soloport22-units: " + MACHINE)
    if "--selftest" in argv:
        base = checks(raw)
        if any(not ok for _, _, ok, _ in base):
            print("REFUSING - the unmutated source already fails: " + ", ".join(i for i, _, ok, _ in base if not ok))
            return 1
        missed = 0
        for name, tag, f in MUTANTS:
            m = f(raw)
            if m is None:
                print("  [MISSED] %s: the mutation changed nothing" % name)
                missed += 1
                continue
            failed = [i for i, _, ok, _ in checks(m) if not ok]
            print("  [%s] %s: %s" % ("pass" if tag in failed else "MISSED", name, "caught by " + tag if tag in failed else "%s did not fail (%s)" % (tag, failed)))
            missed += 0 if tag in failed else 1
        print("self-test: %d mutants, %d not caught" % (len(MUTANTS), missed))
        return 1 if missed else 0
    rows = checks(raw)
    bad = 0
    for i, what, ok, detail in rows:
        print("  [%s] %s %s%s" % ("PASS" if ok else "FAIL", i, what, "" if ok or not detail else "   <- " + detail))
        bad += 0 if ok else 1
    print("test-soloport22-units: %d checks, %d failed" % (len(rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
