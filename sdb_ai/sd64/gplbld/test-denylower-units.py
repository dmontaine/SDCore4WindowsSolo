#!/usr/bin/env python3
# test-denylower-units.py - the deny list is stored in lower case (S.290; the owner, 22 Nov 2026: "Lower case"), read off the source as text.
#
#   python C:\Users\Don\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\test-denylower-units.py [--selftest]
#
#   D1  DENY.VERBS makes a name lower case when it takes it (hyphens as dots), and never upper case
#   D2  DENY.VERBS folds the record it reads to lower case, so a list an older install wrote in capitals is the same list; it writes what it holds
#   D3  the never-denied names are lower case in DENY.VERBS and in CPROC, and are the same four
#   D4  CPROC folds the verb typed AND the list it reads to lower case, before the name is looked for, and reads the VOC by the list's own spelling
#
# It cannot say that a verb is refused: verify-solo.ps1 does, on an install.  Exit 0 every check held, 1 one did not, 2 it could not run.
#
# START-HISTORY:
# 22 Nov 26 SD Core Solo - SOLO 92, carried from Linux Solo ab3fab0 (S.290).  Linux's D5 and its mutant are left out: they read Linux's
#           verify-solo-install.sh, which looks for the stored name; verify-solo.ps1 does not read the record, so there is nothing here to hold.
# END-HISTORY

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
BP = os.path.join(TREE, "sdsys", "gpl.bp")
ME = "test-denylower-units"
FILES = {"denyvrbs": os.path.join(BP, "denyvrbs"), "cproc": os.path.join(BP, "cproc")}


def read(path):
    try:
        with open(path, encoding="latin-1") as f:
            return f.read()
    except OSError:
        print("%s: CANNOT RUN - no %s" % (ME, path))
        sys.exit(2)


def code(src):
    """BASIC without comment lines and ;* tails."""
    return "\n".join(re.sub(r"\s*;\*.*$", "", ln) for ln in src.split("\n") if not ln.lstrip().startswith("*"))


def ordered(text, *needles):
    at = 0
    for n in needles:
        at = text.find(n, at)
        if at < 0:
            return False
        at += len(n)
    return True


def never_of(text, pattern):
    m = re.search(pattern, text)
    return sorted(re.findall(r"'([A-Za-z]+)'", m.group(0))) if m else []


def checks(raw):
    out = []

    def ck(n, what, ok):
        out.append((n, what, bool(ok)))

    dv = code(raw["denyvrbs"])
    ck("D1", "DENY.VERBS takes a name in lower case, hyphens as dots, and never makes one upper case",
       "name = change(downcase(field(arg, ',', i)), '-', '.')" in dv and "name = change(downcase(id), '-', '.')" in dv
       and re.search(r"upcase\((field\(arg|id\)|name|list)", dv) is None)
    ck("D2", "DENY.VERBS folds the record it reads; what it writes is the list it holds",
       "read rec from pol.f, 'denied.verbs' then list = downcase(convert(@fm, @vm, rec))" in dv
       and ordered(dv, "read rec from pol.f, 'denied.verbs' then list = downcase(", "locate name in list<1,1> setting pos else list<1,-1> = name",
                   "write convert(@vm, @fm, list) to pol.f, 'denied.verbs'")
       and "read r from voc.f, list<1,i> else r = ''" in dv)
    cp = code(raw["cproc"])
    at = cp.find("\ncheck.denied.verb:")
    cd = cp[at:cp.find("\nget.voc.parser.rec:", at)] if at >= 0 else ""
    n1 = never_of(dv, r"never = '[^\n]*")
    n2 = never_of(cd, r"if dv\.name = '[^\n]* then return")
    ck("D3", "the never-denied names: lower case, the same four in both programs (%s)" % " ".join(n1),
       n1 == ["admin", "lo", "off", "quit"] and n2 == n1)
    ck("D4", "CPROC folds the verb typed and the list it reads, before the name is looked for; the VOC is read by the list's own spelling",
       ordered(cd, "dv.name = change(downcase(verb), '-', '.')", "read dv.rec from dv.f, 'denied.verbs' then", "dv.rec = downcase(dv.rec)",
               "locate dv.name in dv.rec<1> setting dv.pos then verb.denied = @true", "read dv.other from voc, dv.rec<dv.i> else dv.other = ''")
       and "upcase(verb)" not in cd and cd.count("dv.rec = downcase(dv.rec)") == 1)
    return out


MUTANTS = [
    ("a name is stored in capitals again", "denyvrbs", "name = change(downcase(field(arg, ',', i)), '-', '.')", "name = change(upcase(field(arg, ',', i)), '-', '.')"),
    ("an older list is not folded by DENY.VERBS", "denyvrbs", "then list = downcase(convert(@fm, @vm, rec))", "then list = convert(@fm, @vm, rec)"),
    ("the never list in capitals", "denyvrbs", "never = 'admin' : @vm : 'off' : @vm : 'quit' : @vm : 'lo'", "never = 'ADMIN' : @vm : 'OFF' : @vm : 'QUIT' : @vm : 'LO'"),
    ("a never-denied name dropped", "denyvrbs", "never = 'admin' : @vm : 'off' : @vm : 'quit' : @vm : 'lo'", "never = 'admin' : @vm : 'off' : @vm : 'quit'"),
    ("the same-command pass compares capitals", "denyvrbs", "name = change(downcase(id), '-', '.')", "name = change(upcase(id), '-', '.')"),
    ("CPROC compares the verb in capitals", "cproc", "dv.name = change(downcase(verb), '-', '.')", "dv.name = change(upcase(verb), '-', '.')"),
    ("CPROC does not fold an older list", "cproc", "         dv.rec = downcase(dv.rec)\n", ""),
    ("CPROC folds after it looked", "cproc", "         dv.rec = downcase(dv.rec)\n", "         dv.pos = 0\n"),
    ("CPROC's never names in capitals", "cproc", "if dv.name = 'admin' or dv.name = 'off' or dv.name = 'quit' or dv.name = 'lo' then return",
     "if dv.name = 'ADMIN' or dv.name = 'OFF' or dv.name = 'QUIT' or dv.name = 'LO' then return"),
]


def main():
    raw = {k: read(p) for k, p in FILES.items()}
    if "--selftest" in sys.argv:
        if not all(ok for _, _, ok in checks(raw)):
            print("%s: the real tree does not pass" % ME)
            return 1
        missed = 0
        for label, name, old, new in MUTANTS:
            if old not in raw[name]:
                print("  [MISSED] %s: nothing to change" % label)
                missed += 1
                continue
            changed = dict(raw)
            changed[name] = raw[name].replace(old, new, 1)
            caught = not all(ok for _, _, ok in checks(changed))
            print("  [%s] %s" % ("caught" if caught else "MISSED", label))
            missed += not caught
        print("selftest: %d caught, %d missed" % (len(MUTANTS) - missed, missed))
        return 1 if missed else 0
    print("%s: tree %s" % (ME, TREE))
    res = checks(raw)
    for n, what, ok in res:
        print("  [%s] %s %s" % ("PASS" if ok else "FAIL", n, what))
    bad = sum(1 for r in res if not r[2])
    print("%s: %d passed, %d failed" % (ME, len(res) - bad, bad))
    return 1 if bad or not res else 0


if __name__ == "__main__":
    sys.exit(main())
