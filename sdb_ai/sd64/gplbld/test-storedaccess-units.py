#!/usr/bin/env python3
"""test-storedaccess-units.py - SOLO 81, from Linux Solo b664ea9 (S.247; owner, 18 Nov 2026: "restrict the stored password"): the kept
account password ($cred $stored) signs in only a one-shot that is exactly run.job <name> or mcp.call <id> [agent], unless
SET.STORED.ACCESS ON (register field 24).

    python C:/Users/Don/Projects/SDCore4WindowsSolo/sdb_ai/sd64/gplbld/test-storedaccess-units.py [--selftest]

FREE: reads files only.  Exit 0 every check passed, 1 a check failed, 2 it could not run.

WHAT IT HOLDS:
  S1  login: the kept-password attempt runs only when the one-shot is run.job <name> (two words) or mcp.call <id> [agent] (two or three),
      or field 24 says yes; the field is read from the register at every sign-in
  S2  login: a refused use, when a kept copy for this account is there, is said (15186) and audited in Linux's words, and the input is then
      read as before (the refusal is before the attempt, the attempt is gated by the same test)
  S3  login: run.job's Windows-identity route still follows the gated attempt (it needs pw.dpapi.fail, which only that attempt sets)
  S4  keys.h: ACC$STORED.ANY is field 24
  S5  SET.STORED.ACCESS: the administrator first, ONE word, only 'yes' is on, writes field 24 alone, audits in lower case, answers 15188
  S6  the VOC records (voc_template, newvoc) name $setstoredacc; messages 15186-15188 exist
It cannot say a one-shot is refused on a real install: that is verify-solo's (a Solo install).
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SD64 = os.path.normpath(os.path.join(HERE, ".."))
SDSYS = os.path.join(SD64, "sdsys")
GPL = os.path.join(SDSYS, "gpl.bp")
FILES = {
    "login": os.path.join(GPL, "login"),
    "acc": os.path.join(GPL, "setstoredacc"),
    "keys": os.path.join(SDSYS, "syscom", "keys.h"),
    "voct": os.path.join(SDSYS, "voc_template", "set.stored.access"),
    "vocn": os.path.join(SDSYS, "newvoc", "set.stored.access"),
}
MSGS = ("15186", "15187", "15188")


def load():
    raw = {}
    for k, p in FILES.items():
        try:
            with open(p, encoding="latin-1", newline="") as f:
                raw[k] = f.read()
        except OSError:
            raw[k] = None
    for m in MSGS:
        raw["msg" + m] = os.path.isfile(os.path.join(SDSYS, "messages", m))
    return raw


def code(src):
    return "\n".join(l for l in (src or "").replace("\r\n", "\n").split("\n") if not l.lstrip().startswith("*"))


def checks(raw):
    rows = []

    def ck(name, what, ok, why=""):
        rows.append((name, what, bool(ok), why))

    lg = code(raw["login"])
    one = lg.find("pw.one = trim(system(1026))")
    job = lg.find("if pw.verb = 'run.job' and dcount(pw.one, ' ') = 2 then pw.job = @true")
    mcp = lg.find("if pw.verb = 'mcp.call' and (dcount(pw.one, ' ') = 2 or dcount(pw.one, ' ') = 3) then pw.job = @true")
    anyf = lg.find("if upcase(trim(pw.acc<ACC$STORED.ANY>)) = 'YES' then pw.any = @true")
    refuse = lg.find("if not(pw.interactive) and not(pw.job or pw.any) then")
    msg = lg.find("display sysmsg(15186)", refuse)
    aud = lg.find("void kernel(K$AUDIT, 'login password account=' : initial.account : ' via=stored refused reason=not a scheduled job')", refuse)
    gate = lg.find("if not(pw.interactive) and (pw.job or pw.any) then")
    unprot = lg.find("pw.text = SDEXT(pw.rec<2>, @false, SD_DPAPI_UNPROTECT)")
    ident = lg.find("if not(pw.interactive) and pw.dpapi.fail then")
    ck("S1", "login: the kept password is tried only for run.job <name>, mcp.call <id> [agent], or field 24 yes, read at every sign-in",
       0 <= one < job and job < mcp < anyf < gate < unprot and "openpath @sdsys:@ds:'accounts' to pw.acc.f then" in lg[one:gate]
       and lg.count("if not(pw.interactive) and (pw.job or pw.any) then") == 1 and lg.count("SD_DPAPI_UNPROTECT)") == 1,
       "one %d job %d mcp %d any %d gate %d unprotect %d" % (one, job, mcp, anyf, gate, unprot))
    ck("S2", "login: a refused use with a kept copy for this account says 15186 and is audited in Linux's words, before the gated attempt",
       0 <= anyf < refuse < msg < aud < gate and "if pw.kept<1> = upcase(initial.account) and pw.kept<2> # '' then" in lg[refuse:gate],
       "refuse %d msg %d audit %d gate %d" % (refuse, msg, aud, gate))
    ck("S3", "login: run.job's Windows-identity route still follows the gated attempt", 0 <= unprot < ident and "pw.dpapi.fail = @false" in lg[:gate])
    ck("S4", "keys.h: ACC$STORED.ANY is field 24", re.search(r"^\s*\$define ACC\$STORED\.ANY\s+24\b", raw["keys"] or "", re.M) is not None)
    ac = code(raw["acc"])
    adm = ac.find("if not(kernel(K$ADMINISTRATOR, -1)) then\n      stop sysmsg(2001)")
    opn = ac.find("openpath @sdsys:@ds:'accounts' to acc.f else")
    ck("S5", "SET.STORED.ACCESS: the administrator first, one word, only 'yes' on, field 24 alone, audited lower case, 15188",
       raw["acc"] is not None and 0 <= adm < opn and "if token.type # PARSER$END then word.2 = token" in ac
       and ac.count("upcase(trim(acc.rec<ACC$STORED.ANY>)) = 'YES'") == 2
       and "if st.want then acc.new<ACC$STORED.ANY> = 'yes' else acc.new<ACC$STORED.ANY> = 'no'" in ac
       and len(re.findall(r"acc\.new<ACC\$[A-Z.]+>\s*=", ac)) == 2
       and "void kernel(K$AUDIT, 'set.stored.access ' : downcase(word.1) : ' account=' : acc.name)" in ac and ac.count("sysmsg(15188, st.now)") == 2
       and "$catalog $SETSTOREDACC" in ac and "$internal" in ac, "adm %d open %d" % (adm, opn))
    vocs = [(raw[k] or "").replace("\r\n", "\n") for k in ("voct", "vocn")]
    ck("S6", "the VOC records name $setstoredacc and messages 15186-15188 exist",
       all(v.split("\n")[:3] == ["V", "CA", "$setstoredacc"] for v in vocs) and all(raw["msg" + m] for m in MSGS))
    return rows


def sub(key, old, new):
    return (key, old, new)


MUTANTS = [
    ("any one-shot tries the kept password", sub("login", "if not(pw.interactive) and (pw.job or pw.any) then", "if not(pw.interactive) then")),
    ("run.job with more words is let in", sub("login", "if pw.verb = 'run.job' and dcount(pw.one, ' ') = 2 then pw.job = @true",
                                               "if pw.verb = 'run.job' then pw.job = @true")),
    ("field 24 not read", sub("login", "if upcase(trim(pw.acc<ACC$STORED.ANY>)) = 'YES' then pw.any = @true", "null")),
    ("the refusal is not said", sub("login", "         display sysmsg(15186) ;*", "         null ;*")),
    ("the refusal is not audited", sub("login", " via=stored refused reason=not a scheduled job')", " via=stored')")),
    ("the field number differs", sub("keys", "$define ACC$STORED.ANY   24", "$define ACC$STORED.ANY   25")),
    ("the verb skips the administrator", sub("acc", "   if not(kernel(K$ADMINISTRATOR, -1)) then\n      stop sysmsg(2001)", "   if 0 then\n      stop sysmsg(2001)")),
    ("the verb takes any word as on", sub("acc", "if upcase(trim(acc.rec<ACC$STORED.ANY>)) = 'YES' then st.now = 'yes'", "st.now = 'yes'")),
    ("the verb is not audited", sub("acc", "   void kernel(K$AUDIT, 'set.stored.access ' : downcase(word.1) : ' account=' : acc.name)\n", "")),
    ("the VOC names another program", sub("voct", "$setstoredacc", "$setjobsacc")),
]


def main():
    raw = load()
    missing = [k for k in FILES if raw[k] is None]
    if missing:
        print("test-storedaccess-units: CANNOT RUN - missing %s" % ", ".join(FILES[k] for k in missing))
        return 2
    print("test-storedaccess-units: %s" % ", ".join(os.path.relpath(p, SD64) for p in FILES.values()))
    rows = checks(raw)
    for n, w, ok, why in rows:
        print("  [%s] %s %s%s" % ("PASS" if ok else "FAIL", n, w, ("   <- " + why) if (not ok and why) else ""))
    bad = [r for r in rows if not r[2]]
    if "--selftest" in sys.argv:
        if bad:
            print("test-storedaccess-units: CANNOT SELFTEST - the live files already fail")
            return 1
        missed = 0
        for what, (key, old, new) in MUTANTS:
            if old not in (raw[key] or ""):
                print("  [MUTANT CANNOT APPLY] %s" % what)
                missed += 1
                continue
            m = dict(raw)
            m[key] = raw[key].replace(old, new, 1)
            red = [r[0] for r in checks(m) if not r[2]]
            print("  [%s] %s%s" % ("CAUGHT" if red else "MISSED", what, (" by " + ", ".join(red)) if red else ""))
            missed += 0 if red else 1
        print("test-storedaccess-units --selftest: %d of %d mutants caught" % (len(MUTANTS) - missed, len(MUTANTS)))
        if missed:
            return 1
    print("test-storedaccess-units: %d checks, %d failed" % (len(rows), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
