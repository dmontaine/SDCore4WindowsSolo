#!/usr/bin/env python3
# test-openseq-else-units.py - an OPENSEQ that takes ELSE keeps the name locked until the file variable is closed (26 Oct 2026; found on the VM in home_entry, where the first
# session at the home screen kept an update lock on the ABSENT start.default for as long as it lived and the next session waited at sign-on).  A program that lives as long as a page
# or an editor is open must close the variable in the ELSE branch.  home_entry, setstart, tool_menus, viewlist and osread are held by test-home-units.py (H28a); this holds the long-lived
# programs the audit of the same day added: SED's open of a file by path (SD Core's configuration and catalogue pages, which the audit also fixed, are not in Solo - Solo carry 21, copied from SD Core).
# 11 Nov 26 SOLO 56 group 4: gpl.bp/sed is retired (SED is the IDE, as in SD Core and Linux Solo), so the held program is SD Core's: ide_osfile, whose
# open the IDE's tab holds for as long as it is open.  tool_config and tool_catalog come with the pages (SOLO 56 group 5).
# Left alone on purpose: apisrvr (seqfiles(os.slot) is an array element, and `unassigned()` of one is not known to compile; the failed open of an API request leaves the lock until the slot
# is used again - open item), and the short programs that end at once (acc_archive, acc_os_bakdir, netcred, netdefs, locktracer, importdata, ...), whose variable goes with them.
# FREE CHECK: the BASIC read as text; no install, no sd.
#
#   python3 /home/don/Projects/SDCore4Linux/sdb_ai/sd64/gplbld/test-openseq-else-units.py
#   python3 /home/don/Projects/SDCore4Linux/sdb_ai/sd64/gplbld/test-openseq-else-units.py --selftest
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BP = os.environ.get("BPDIR", os.path.normpath(os.path.join(HERE, "..", "sdsys", "gpl.bp")))
# program -> the file variables whose OPENSEQ must close in ELSE
WANT = {"ide_osfile": ["f"]}       # as SD Core's copy, without tool_config and tool_catalog (not in Solo until SOLO 56 group 5)


def read(name):
    with open(os.path.join(BP, name), encoding="latin-1") as f:
        return f.read()


def indent(l):
    return len(l) - len(l.lstrip())


def else_branch(lines, i):
    """the lines of the ELSE branch of the OPENSEQ at line i: after `end else` at the statement's indent, or after a trailing `else`, up to the `end` at that indent"""
    n = indent(lines[i])
    s = lines[i].rstrip()
    out = []
    if s.endswith(" else"):
        j = i + 1
    else:
        j = None
        for k in range(i + 1, min(i + 400, len(lines))):
            if not lines[k].strip() or lines[k].lstrip().startswith("*"):       # blank lines and whole-line comments (column 0 in this source) have no indent to judge
                continue
            if indent(lines[k]) == n and lines[k].strip().startswith("end else"):
                j = k + 1
                break
            if lines[k].strip() and indent(lines[k]) < n:
                break
        if j is None:
            return None
    for k in range(j, min(j + 200, len(lines))):
        if lines[k].strip() and indent(lines[k]) <= n and lines[k].strip().split()[0] == "end":
            break
        out.append(lines[k])
    return out


def checks(programs):
    rows = []
    for prog, variables in WANT.items():
        lines = programs[prog].split("\n")
        found = {v: [] for v in variables}
        for i, l in enumerate(lines):
            if l.lstrip().startswith("*"):
                continue
            m = re.match(r"\s*openseq\b.*?\bto\s+([A-Za-z_.][\w.]*)\b", l, re.I)
            if m and m.group(1) in found:
                found[m.group(1)].append(i)
        for v, idx in found.items():
            if not idx:
                rows.append(("O %s: no OPENSEQ to %s found (the check has nothing to hold)" % (prog, v), False, ""))
                continue
            for i in idx:
                br = else_branch(lines, i)
                closes = [] if br is None else [k for k, b in enumerate(br) if re.search(r"\bclose\s+%s\b" % re.escape(v), b, re.I)]      # CLOSESEQ is gone (S.87): CLOSE closes a sequential file variable
                reopens = [] if br is None else [k for k, b in enumerate(br) if re.match(r"\s*openseq\b.*?\bto\s+%s\b" % re.escape(v), b, re.I)]
                # the close comes BEFORE a second OPENSEQ into the same variable (SED retries with the name in upper case): the first lock is let go, not overwritten
                ok = bool(closes) and (not reopens or closes[0] < reopens[0])
                rows.append(("O %s line %d: the ELSE of OPENSEQ to %s closes it" % (prog, i + 1, v), ok, "branch: %s" % (None if br is None else [b.strip()[:60] for b in br][:6])))
    return rows


def load():
    return {p: read(p) for p in WANT}


def run():
    rows = checks(load())
    bad = 0
    for name, ok, detail in rows:
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "   <- " + detail))
        bad += 0 if ok else 1
    print("test-openseq-else-units: %d passed, %d failed" % (len(rows) - bad, bad))
    return 1 if bad or not rows else 0


def selftest():
    progs = load()
    if not all(ok for _, ok, _ in checks(progs)):
        print("  [FAIL] the real programs do not pass")
        return 1
    print("  [ok] the real programs pass")
    caught = missed = 0

    def mutant(name, prog, old, new):
        nonlocal caught, missed
        p = dict(progs)
        if old not in p[prog]:
            print("  [MISSED] %s: the text to change is not there" % name)
            missed += 1
            return
        p[prog] = p[prog].replace(old, new, 1)
        failing = [n for n, ok, _ in checks(p) if not ok]
        if failing and all(prog in f for f in failing):
            print("  [caught] %s (%d row)" % (name, len(failing)))
            caught += 1
        else:
            print("  [MISSED] %s: failing rows %s" % (name, failing))
            missed += 1

    # 11 Nov 26: SD Core's form of this mutant broke the first "close f" in ide_osfile, which is in the ON ERROR clause, not the ELSE branch the check reads, so it
    # was never caught (SD Core's self-test stops earlier, on tool_config, so it never said so).  This one breaks the close in the ELSE branch of the first open.
    mutant("ide_osfile open", "ide_osfile", "   end else\n      op.st = status()\n      if not(unassigned(f)) then close f\n",
           "   end else\n      op.st = status()\n      if not(unassigned(f)) then null\n")
    print("selftest: %d of %d mutants caught, %d missed" % (caught, caught + missed, missed))
    return 0 if missed == 0 else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else run())
