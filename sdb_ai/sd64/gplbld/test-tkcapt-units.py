#!/usr/bin/env python3
# test-tkcapt-units.py - what a captured message is ($tk_capt, S.300; SD Core for Windows' row 380), read off the source as text.
#
#   python3 /home/don/Projects/SDCore4LinuxSolo/sdb_ai/sd64/gplbld/test-tkcapt-units.py [--selftest]
#
# Carried from SD Core (68856fc1), 22 Nov 2026.  Differs only where Solo does: PAGES (no tool_accounts or tool_jobs; its jobs page is tool_solojobs), no
# local.sdsys skip in tool_remote (C7), and 11 calls, not 12 (C8).
# Windows Solo: carried from Linux Solo eac819a byte for byte, 22 Nov 2026 (RELEASE_1.1 380); test-tkrunwrap-units retired with it, as in Windows Core.
#
#   C1  the cause is still where the rule says: messages.c turns a written line break into LF and CR
#   C2  $tk_capt is $internal, catalogued, takes four arguments; its common block has a $ name
#   C3  'clean' keeps what was captured and returns it with the CR dropped and nothing else changed (never a change of the lines)
#   C4  the kept text is used only when out is the text that was cleaned, compared as text
#   C5  a piece led by CR goes on with the message before it, joined by one space; an empty piece ends a message; first stops, last goes on; skip passes one over
#   C6  $tk_run and $tk_runx clean right after the EXECUTE, before the log of commands has it
#   C7  every page that shows a message of $tk_run's or $tk_runx's command on one line asks $tk_capt, the first or the last as that page did, and has no loop of its own left
#   C7b tool.bulk, which runs its own EXECUTE, asks $tk_capt for its first message too (S.304)
#   C8  every call passes four arguments
#
# It cannot say what a page shows: that is the pages' sandbox suites.  Exit 0 every check held, 1 one did not, 2 it could not run.

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
BP = os.path.join(TREE, "sdsys", "gpl.bp")
PAGES = {"tool_backups": "last", "tool_config": "last", "tool_gates": "last", "tool_solojobs": "last", "tool_remote": "last",
         "tool_files": "first", "tool_catalog": "first", "tool_voc": "first", "tool_sessions": "first"}
# S.304: page -> (the call, how many times)
OWN_EXECUTE = {"tool_bulk": (("call $tk_capt('first', sout, '', sline)", 1), ("call $tk_capt('first', mkout, '', mkw)", 1))}


def read(path):
    try:
        with open(path, encoding="latin-1") as f:
            return f.read()
    except OSError:
        print("test-tkcapt-units: CANNOT RUN - no %s" % path)
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


def load():
    raw = {"messages.c": read(os.path.join(TREE, "gplsrc", "messages.c"))}
    for name in sorted(os.listdir(BP)):
        p = os.path.join(BP, name)
        if os.path.isfile(p) and (name.startswith("tool_") or name.startswith("tk_")):
            raw[name] = read(p)
    return raw


def checks(raw):
    out = []
    ck = lambda n, what, ok: out.append((n, what, bool(ok)))
    cap = code(raw.get("tk_capt", ""))
    ck("C1", "messages.c makes a written line break LF and CR", ordered(raw["messages.c"], "case 'n':", "*p = '\\n';", "*(p+1) = '\\r';"))
    ck("C2", "$internal, catalogued, four arguments, a $ common",
       "$internal" in cap and "subroutine tk_capt(op, out, skip, res)" in cap and "$catalog $tk_capt" in cap and "common /$tkcapt/" in cap)
    ck("C3", "clean keeps the capture and drops only the CR",
       ordered(cap, "if op = 'clean' then", "tc.raw = out", "res = convert(char(13), '', out)", "tc.out = res", "return") and "change(out" not in cap)
    ck("C4", "the kept text only for the out that was cleaned", "if ('S' : tc.out) = ('S' : out) then text = tc.raw" in cap)
    ck("C5", "the rule",
       ordered(cap, "goes.on = (piece[1, 1] = char(13))", "piece = trim(convert(char(13), '', piece))", "if piece # '' and goes.on and cur # '' then",
               "cur = cur : ' ' : piece", "gosub message.ends", "if op = 'first' and res # '' then exit", "cur = piece", "next pi", "gosub message.ends",
               "message.ends:", "if cur = '' then return", "if cur[1, len(skip)] = skip then return", "if op = 'last' or res = '' then res = cur"))
    for name in ("tk_run", "tk_runx"):
        ck("C6", "%s cleans right after the EXECUTE" % name,
           re.search(r"execute s trapping aborts capturing out\s*\n\s*status = @system\.return\.code\s*\n\s*call \$tk_capt\('clean', out, '', cap\)\s*\n\s*out = cap\s*\n[\s\S]*call \$tk_out\('log'",
                     code(raw.get(name, ""))) is not None)
    for name, which in PAGES.items():
        src = code(raw.get(name, ""))
        want = "call $tk_capt('%s', out, '', " % which          # Solo: tool_remote skips nothing either (Core's passes cskip)
        ck("C7", "%s asks for the %s message" % (name, which),
           want in src and re.search(r"(said|lastl|ol) = trim\(out<", src) is None)     # Solo: no local.sdsys, so tool_remote skips nothing (Core's clause left out)
    # S.304 (carried from SD Core, 22 Nov 26): the page that runs its own EXECUTE (no $tk_run, so nothing was cleaned: $tk_capt reads the capture as it came).  Solo has no tool_entries.
    for name, wants in OWN_EXECUTE.items():
        src = code(raw.get(name, ""))
        ck("C7b", "%s takes the first message of its own EXECUTE (%d places) and cuts no first line itself" % (name, sum(n for _, n in wants)),
           all(src.count(w) == n for w, n in wants) and re.search(r"trim\((sout|mkout)<", src) is None
           and "change(change(change(sout" not in src and "change(change(change(mkout" not in src)
    calls = [m for name, src in raw.items() if name != "messages.c" for m in re.findall(r"call \$tk_capt\(.*\)", code(src))]
    four = all(len(re.split(r",(?=(?:[^']*'[^']*')*[^']*$)", c[c.index("(") + 1:-1])) == 4 for c in calls)
    ck("C8", "%d calls, four arguments each" % len(calls), len(calls) >= 11 and four)     # Solo: 9 pages and tk_run, tk_runx (Core 12)
    return out


MUTANTS = [
    ("the cause moved", "messages.c", "*(p+1) = '\\r';", "*(p+1) = ' ';"),
    ("a plain common", "tk_capt", "common /$tkcapt/", "common /tkcapt/"),
    ("the capture not kept", "tk_capt", "      tc.raw = out\n", ""),
    ("the lines joined in clean", "tk_capt", "res = convert(char(13), '', out)", "res = change(out, @fm : char(13), ' ')"),
    ("any out uses the kept text", "tk_capt", "if ('S' : tc.out) = ('S' : out) then text = tc.raw", "text = tc.raw"),
    ("every line joined", "tk_capt", "if piece # '' and goes.on and cur # '' then", "if piece # '' and cur # '' then"),
    ("nothing joined", "tk_capt", "cur = cur : ' ' : piece", "cur = piece"),
    ("first is last", "tk_capt", "if op = 'last' or res = '' then res = cur", "res = cur"),
    ("skip ignored", "tk_capt", "if cur[1, len(skip)] = skip then return", "null"),
    ("run does not clean", "tk_run", "   out = cap\n", ""),
    ("runx does not clean", "tk_runx", "   out = cap\n", ""),
    ("backups takes the first", "tool_backups", "$tk_capt('last'", "$tk_capt('first'"),
    ("voc takes the last", "tool_voc", "$tk_capt('first'", "$tk_capt('last'"),
    ("a fifth argument", "tool_solojobs", "$tk_capt('last', out, '', said)", "$tk_capt('last', out, '', said, 1)"),     # Solo: Core's "remote keeps 14183" has no code here
    ("bulk's select takes its first line (S.304)", "tool_bulk", "   call $tk_capt('first', sout, '', sline)", "   sline = trim(sout<1>)"),
    ("bulk's undo file takes the last message (S.304)", "tool_bulk", "call $tk_capt('first', mkout, '', mkw)", "call $tk_capt('last', mkout, '', mkw)"),
]


def main():
    raw = load()
    if "--selftest" in sys.argv:
        if not all(ok for _, _, ok in checks(raw)):
            print("test-tkcapt-units: the real tree does not pass")
            return 1
        missed = 0
        for label, name, old, new in MUTANTS:
            if old not in raw.get(name, ""):
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
    print("test-tkcapt-units: tree %s" % TREE)
    res = checks(raw)
    for n, what, ok in res:
        print("  [%s] %s %s" % ("PASS" if ok else "FAIL", n, what))
    bad = sum(1 for r in res if not r[2])
    print("test-tkcapt-units: %d passed, %d failed" % (len(res) - bad, bad))
    return 1 if bad or not res else 0


if __name__ == "__main__":
    sys.exit(main())
