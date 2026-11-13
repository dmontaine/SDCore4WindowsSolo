#!/usr/bin/env python3
"""test-doors-units.py - SOLO 62: REMOTE.API / REMOTE.SSH (gpl.bp/remotedoor), the doors helper (solo-doors.ps1), the page
(gpl.bp/tool_remote) and the installer's half (solo-machine.ps1) still agree, and nothing they run in a user's session is CIM.

WHY (12 Nov 2026, the VM witness in Win11VM Solo WS2.0-0).  Each check below is a fault that sitting paid for:
  N  in an SD session reached over ssh, EVERY CIM cmdlet fails (CimJob_BrokenCimSession, "Cannot connect to CIM server.
     Access denied"): the report's Get-NetTCPConnection / Get-ScheduledTask / Get-NetFirewallRule, then the verb's
     Start-ScheduledTask.  They are now .NET and COM (903d7668, 0840ff24).  solo-doors.ps1 and remotedoor must stay CIM-free;
     solo-machine.ps1 is NOT checked - it runs elevated at the installer's desktop or as the SYSTEM helper.
  F  the report reads each firewall rule through COM by its DISPLAY NAME and port, written in solo-doors.ps1 a second time;
     each must equal the $displayName and $Port of api-firewall.ps1 / solo-ssh-firewall.ps1, or the report says "none".
  T  the helper task's name is written in three files (the installer registers it, the verb starts it, the report looks it up).
  A  the proof is HMAC over 'sd-solo-doors|v1|door|mode|nonce|time', built in BASIC by the verb and in PowerShell by the helper;
     the same literal and the same field order, or every change is refused as a bad proof.
  R  every key the verb writes into doors.request is one the helper reads, and the other way round.
  W  the owner's rule (12 Nov 2026): a line before any wait over 2 s - the verb displays 12982 or 12981 before EACH
     ps_script_out, and the page puts 12982 on its status line (through $tk_frame) before read.all runs the reports.

It reads files; no SD, no install, no elevation.  CONTROLS: every check is also run on an in-memory copy with one planted
fault (a mutant), which must be refused, and each mutant is asserted to have changed the text (a replace that matched nothing
would pass trivially).  Exit 0 all rows passed, 1 a row failed, 2 it could not run.

  python gplbld/test-doors-units.py
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GPLBP = os.path.normpath(os.path.join(HERE, os.pardir, "sdsys", "gpl.bp"))
MSGS = os.path.normpath(os.path.join(HERE, os.pardir, "sdsys", "messages"))
FILES = {
    "doors": os.path.join(HERE, "solo-doors.ps1"),
    "machine": os.path.join(HERE, "solo-machine.ps1"),
    "apifw": os.path.join(HERE, "api-firewall.ps1"),
    "sshfw": os.path.join(HERE, "solo-ssh-firewall.ps1"),
    "verb": os.path.join(GPLBP, "remotedoor"),
    "page": os.path.join(GPLBP, "tool_remote"),
}
passed = failed = 0

CIM = re.compile(r"\b(?:Get|Set|New|Remove|Start|Stop|Enable|Disable|Register|Unregister|Invoke)-"
                 r"(?:NetTCPConnection|NetUDPEndpoint|ScheduledTask\w*|NetFirewall\w*|Cim\w*|NetAdapter\w*)\b"
                 r"|\bGet-WmiObject\b", re.I)


def row(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  [PASS] " + name)
    else:
        failed += 1
        print("  [FAIL] " + name + ("   <- " + detail if detail else ""))


def text(p):
    with open(p, "rb") as f:
        return f.read().replace(b"\r\n", b"\n").decode("latin-1")


def ps_code(t):
    """PowerShell lines with comments dropped: a whole '#' line, and a ' # ' tail."""
    out = []
    for ln in t.split("\n"):
        if ln.strip().startswith("#"):
            continue
        out.append(ln.split(" # ")[0])
    return out


def basic_code(t):
    """SD BASIC lines with comments dropped: a '*' line and a ';*' tail."""
    out = []
    for ln in t.split("\n"):
        if re.match(r"^\s*(\*|!|rem\b)", ln, re.I):
            continue
        out.append(ln.split(";*")[0])
    return out


# ------------------------------------------------------------------ the checks: each returns a list of problems ([] = good)

def chk_cim(lines, label):
    return ["%s: %s" % (label, ln.strip()[:110]) for ln in lines if CIM.search(ln)]


def chk_firewall(doors, fw_texts):
    probs = []
    ports = dict(re.findall(r"^\$(ApiPort|SshPort)\s*=\s*(\d+)", doors, re.M))
    calls = re.findall(r"Get-Scope\s+'([^']+)'\s+\$(\w+)", doors)
    if not calls:
        return ["solo-doors.ps1 calls Get-Scope with no display name"]
    for label, fw in fw_texts:
        m_n = re.search(r"^\$displayName\s*=\s*'([^']+)'", fw, re.M)
        m_p = re.search(r"^\$Port\s*=\s*(\d+)", fw, re.M)
        if not (m_n and m_p):
            probs.append("%s: no $displayName or $Port" % label)
            continue
        hit = [c for c in calls if c[0] == m_n.group(1) and ports.get(c[1]) == m_p.group(1)]
        if not hit:
            probs.append("%s makes '%s' on %s; solo-doors.ps1 reads %s with ports %s"
                         % (label, m_n.group(1), m_p.group(1), calls, ports))
    return probs


def task_names(doors, machine, verb):
    return {
        "solo-machine.ps1": re.findall(r"^\$DoorsTaskName\s*=\s*'([^']+)'", machine, re.M),
        "solo-doors.ps1": re.findall(r"Get-Task\s+'([^']+)'", doors),
        "remotedoor": re.findall(r"GetTask\(' : q : '([^']+)'", verb),
    }


def chk_task(doors, machine, verb):
    found = task_names(doors, machine, verb)
    probs = ["%s names no doors task" % k for k, v in found.items() if not v]
    names = set(n for v in found.values() for n in v)
    if len(names) > 1:
        probs.append("three files disagree: %s" % found)
    return probs


def verb_keys(verb):
    """The request keys the verb writes and the BASIC variable behind each."""
    keys = set(re.findall(r"q : '([a-z]+)=", verb))
    var = dict(re.findall(r"q : '([a-z]+)=' : ([\w.]+)", verb))
    return keys, var


def chk_authmsg(doors, verb):
    m_ps = re.search(r"^\$authmsg\s*=\s*('[^']*'(?:\s*\+\s*(?:\$\w+|'[^']*'))*)", doors, re.M)
    m_bb = re.search(r"^\s*authmsg\s*=\s*('[^']*'(?:\s*:\s*(?:[\w.]+|'[^']*'))*)", verb, re.M)
    if not (m_ps and m_bb):
        return ["authmsg not found (helper %s, verb %s)" % (bool(m_ps), bool(m_bb))]
    _, var = verb_keys(verb)
    back = {v: k for k, v in var.items()}                    # BASIC variable -> request key
    ps = [t if t.startswith("'") else t[1:] for t in re.findall(r"'[^']*'|\$\w+", m_ps.group(1))]
    bb = [t if t.startswith("'") else back.get(t, "?" + t) for t in re.findall(r"'[^']*'|[\w.]+", m_bb.group(1))]
    return [] if ps == bb else ["helper builds %s, verb builds %s" % (ps, bb)]


def chk_request(doors, verb):
    wrote, _ = verb_keys(verb)
    read = set(re.findall(r"req\['([a-z]+)'\]", doors))
    if not wrote or not read:
        return ["no request keys found (verb %s, helper %s)" % (sorted(wrote), sorted(read))]
    return [] if wrote == read else ["verb writes %s, helper reads %s" % (sorted(wrote), sorted(read))]


def chk_verb_waits(verb):
    probs, armed, calls = [], False, 0
    for ln in basic_code(verb):
        if re.search(r"\bdisplay\s+sysmsg\(1298[12]\)", ln):
            armed = True
        if "ps_script_out(" in ln and "deffun" not in ln:
            calls += 1
            if not armed:
                probs.append("ps_script_out with no wait line before it: " + ln.strip()[:90])
            armed = False
    if calls < 2:
        probs.append("only %d ps_script_out call(s) found; the verb has a report and a change" % calls)
    return probs


def chk_page_wait(page):
    m = re.search(r"^read\.all:\n(.*?)^\s+return\b", page, re.M | re.S)
    if not m:
        return ["tool_remote has no read.all block"]
    code = "\n".join(basic_code(m.group(1)))
    i_msg, i_frame, i_run = code.find("sysmsg(12982)"), code.find("$tk_frame("), code.find("gosub run.report")
    if min(i_msg, i_frame, i_run) < 0 or not (i_msg < i_frame < i_run):
        return ["read.all: 12982 at %d, $tk_frame at %d, first report at %d (want all present, in that order)"
                % (i_msg, i_frame, i_run)]
    return []


def all_checks(t):
    return {
        "N": chk_cim(ps_code(t["doors"]), "solo-doors.ps1") + chk_cim(basic_code(t["verb"]), "remotedoor"),
        "F": chk_firewall(t["doors"], [("api-firewall.ps1", t["apifw"]), ("solo-ssh-firewall.ps1", t["sshfw"])]),
        "T": chk_task(t["doors"], t["machine"], t["verb"]),
        "A": chk_authmsg(t["doors"], t["verb"]),
        "R": chk_request(t["doors"], t["verb"]),
        "W": chk_verb_waits(t["verb"]) + chk_page_wait(t["page"]),
    }


def mutant(t, key, old, new):
    m = dict(t)
    m[key] = t[key].replace(old, new, 1)
    return m, m[key] != t[key]


def main():
    missing = [p for p in FILES.values() if not os.path.isfile(p)]
    if missing:
        print("test-doors-units: cannot run - not found: " + ", ".join(missing))
        return 2
    t = {k: text(p) for k, p in FILES.items()}
    for k, p in FILES.items():
        print("  read %-8s %s (%d lines)" % (k, p, t[k].count("\n")))

    for m in ("12981", "12982"):
        p = os.path.join(MSGS, m)
        row("message %s is there and says something" % m, os.path.isfile(p) and text(p).strip() != "")

    names = {"N": "no CIM cmdlet in solo-doors.ps1 or remotedoor (an ssh logon breaks them)",
             "F": "the report reads the firewall scripts' own rule names and ports",
             "T": "one doors task name in solo-machine.ps1, solo-doors.ps1 and remotedoor",
             "A": "the proof's message is built the same way by the verb and the helper",
             "R": "the request keys the verb writes are the ones the helper reads",
             "W": "a wait line before each PowerShell wait, in the verb and on the page"}
    real = all_checks(t)
    for k in "NFTARW":
        row(k + "  " + names[k], not real[k], "; ".join(real[k])[:400])

    # the controls: one planted fault each; the check it aims at must refuse it
    planted = [
        ("N", "doors", "$t = Get-Task $SshTaskName", "$t = Get-ScheduledTask -TaskName $SshTaskName"),
        ("N", "verb", ".GetTask(' : q : 'SD Core Solo Doors' : q : ').Run($null)",
                      ".GetTask(' : q : 'SD Core Solo Doors' : q : ').Run($null); Start-ScheduledTask x"),
        ("F", "apifw", "$displayName = 'SD Core Solo API (SDClient)'", "$displayName = 'SD Core Solo API'"),
        ("F", "doors", "$SshPort = 4251", "$SshPort = 4252"),
        ("T", "machine", "$DoorsTaskName = 'SD Core Solo Doors'", "$DoorsTaskName = 'SD Core Solo Door'"),
        ("A", "doors", "$authmsg = 'sd-solo-doors|v1|' + $door + '|' + $mode + '|' + $nonce + '|' + $time",
                       "$authmsg = 'sd-solo-doors|v1|' + $door + '|' + $mode + '|' + $time + '|' + $nonce"),
        ("A", "verb", "authmsg = 'sd-solo-doors|v1|'", "authmsg = 'sd-solo-doors|v2|'"),
        ("R", "doors", "req['proof']", "req['proofs']"),
        ("W", "verb", "display sysmsg(12981)", "crt ''"),
        ("W", "page", "msg = sysmsg(12982)", "msg = ''"),
    ]
    for k, key, old, new in planted:
        m, changed = mutant(t, key, old, new)
        if not changed:
            row("control %s on %s: the planted text was found" % (k, key), False, "no match for: " + old[:70])
            continue
        got = all_checks(m)[k]
        row("control %s refuses a planted fault in %s (%s)" % (k, key, new[:60]), bool(got))
    # and a CIM name in a comment is not code
    row("control N leaves a comment alone",
        not chk_cim(ps_code("# Get-NetTCPConnection was here\n$x = 1 # Get-ScheduledTask"), "c")
        and not chk_cim(basic_code("* Start-ScheduledTask\n   x = 1  ;* Get-NetFirewallRule"), "c"))

    print("test-doors-units: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
