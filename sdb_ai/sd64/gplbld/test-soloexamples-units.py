#!/usr/bin/env python3
"""test-soloexamples-units.py - examples.bp in Solo's one account (S.261) as invariants read off the source.  Free: no install, no elevation, no sd.

    python C:/Users/Don/SDCoreProject/SDCore4WindowsSolo/sdb_ai/sd64/gplbld/test-soloexamples-units.py [--selftest]

16 Nov 2026, RELEASE_1.1 335: Linux Solo's guard of the same name (fb685f0) with SD Core for Windows' test-examples-units.py (9ba9d612) folded in.  The
owner, 17 Nov 2026: "there should be a examples.bp file available to all users that contains those programs and a set of training programs typical for a
Computer Science 101 course"; for Solo: "just include examples.bp in the single account, no need to load or remove".  What it holds:
  E1  the shipped programs are SD Core for Windows' (the sibling checkout SDCore4Windows), byte for byte; Core's own guard holds those to the TUI guide.
      Exit 2 when that checkout is missing
  E2  every shipped file has a name solo_examples takes, begins "* <name> -", has no CR, each training program (cs..) is "program <name>" ... "end";
      and no shipped program writes a doubled quote inside a string (test-sqescape-units.py's rule)
  E3  gpl.bp/solo_examples: the installer's alone (K$INTERNAL before it opens anything), sduser from the register through the token form, no LOGTO,
      its two temporary pointers in the SESSION's VOC written before the first compile and removed after the last (and before the first write),
      a program it does not ship kept, every compile judged on the compiler's success line, the line the installer anchors on
  E4  solo-setup.ps1's EXAMPLES block: once, at the top level of the steps - NOT inside the -Upgrade, -ReloadFrom or -Passwords branches - so a new
      tree, a reload AND AN UPGRADE all run it; after the reload and UPDATE.ACCOUNTS, before DELETE VOC gpl.bp; RUN gpl.bp solo_examples internally,
      anchored on 0 failed; a failure is a WARNING and never a failed install; ten minutes allowed
  E5  sd-solo.iss runs solo-setup.ps1 once, unconditionally, after choosing -Upgrade for an existing tree (the upgrade path reaches E4)
  E6  stage.py ships sdsys\\examples (replaced on upgrade) and lists it as a mirror
  E7  there is NO verb: no load.examples, remove.examples or solo_examples record in voc_template or newvoc, no loadexamples or removeexamples program
It cannot say a program compiles or runs: that needs an installed system.
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("sqescape_for_soloexamples", os.path.join(HERE, "test-sqescape-units.py"))
SQ = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SQ)                         # its rule (doubled, COMMENT_LINE) is the one gpl.bp is held to; main() is not run
SD64 = os.path.normpath(os.path.join(HERE, ".."))
ROOT = os.path.normpath(os.path.join(SD64, "..", ".."))
SDSYS = os.path.join(SD64, "sdsys")
EX = os.path.join(SDSYS, "examples")
CORE_EX = os.path.normpath(os.path.join(ROOT, "..", "SDCore4Windows", "sdb_ai", "sd64", "sdsys", "examples"))


def rd(p):
    try:
        with open(p, encoding="latin-1", newline="") as f:
            return f.read()
    except OSError:
        return None


def load():
    raw = {"prog": rd(os.path.join(SDSYS, "gpl.bp", "solo_examples")), "setup": rd(os.path.join(HERE, "solo-setup.ps1")),
           "iss": rd(os.path.join(HERE, "sd-solo.iss")), "stage": rd(os.path.join(HERE, "stage.py"))}
    raw["files"] = {n: rd(os.path.join(EX, n)) for n in sorted(os.listdir(EX))} if os.path.isdir(EX) else {}
    raw["core"] = {n: rd(os.path.join(CORE_EX, n)) for n in sorted(os.listdir(CORE_EX))} if os.path.isdir(CORE_EX) else {}
    raw["verbs"] = {d + "/" + n: rd(os.path.join(SDSYS, d, n)) for d in ("voc_template", "newvoc") for n in ("load.examples", "remove.examples", "solo_examples")}
    raw["progs"] = {n: rd(os.path.join(SDSYS, "gpl.bp", n)) for n in ("loadexamples", "removeexamples")}
    return raw


def code(src):
    return "\n".join(re.sub(r"\s*;\*.*$", "", l) for l in (src or "").split("\n") if not re.match(r"^\s*\*", l))


def ps_code(src):
    return "\n".join(l for l in (src or "").split("\n") if not l.lstrip().startswith("#"))


def iss_code(src):
    """sd-solo.iss without its { } and (* *) comments, so a call that is only mentioned in a comment does not count."""
    s = re.sub(r"\(\*.*?\*\)", "", src or "", flags=re.S)
    return re.sub(r"\{[^}]*\}", "", s, flags=re.S)


def py_list(src, name):
    m = re.search(r"\n%s = \[\n(.*?)\n\]\n" % re.escape(name), src or "", re.S)
    return m.group(1) if m else ""


def checks(raw):
    rows = []

    def ck(i, what, ok, detail=""):
        rows.append((i, what, bool(ok), detail))

    files, core = raw["files"], raw["core"]
    diff = sorted(n for n in set(files) | set(core) if files.get(n) != core.get(n))
    ck("E1", "the %d shipped programs are SD Core for Windows', byte for byte" % len(files), len(files) >= 25 and not diff, repr(diff[:6]))
    badname = [n for n in files if not re.match(r"^[a-z][a-z0-9._-]{0,79}$", n)]
    badhead = [n for n, t in files.items() if not (t or "").startswith("* %s -" % n)]
    badcs = [n for n, t in files.items() if n.startswith("cs") and not (re.search(r"^program %s\s*$" % re.escape(n), t or "", re.M) and (t or "").rstrip().endswith("end"))]
    crlf = [n for n, t in files.items() if "\r" in (t or "")]
    dq = [n for n, t in files.items() for l in (t or "").split("\n") if not SQ.COMMENT_LINE.match(l) and SQ.doubled(l)]
    ck("E2", "every name is a key, every file begins '* <name> -', no CR, every training program is program <name> ... end, no doubled quote in a string",
       not badname and not badhead and not badcs and not crlf and not dq and len([n for n in files if n.startswith("cs")]) >= 20,
       repr((badname, badhead, badcs, crlf, dq)))
    p = code(raw["prog"])
    ck("E3a", "solo_examples is the installer's alone: K$INTERNAL asked before the examples directory or the register is opened",
       raw["prog"] is not None and 0 <= p.find("if not(kernel(K$INTERNAL, -1)) then") < p.find("dir(src)") < p.find("openpath @sdsys : @ds : 'accounts'"))
    ck("E3b", "it reads sduser from the register, through the token form, and has no LOGTO",
       "read acc.rec from acc.f, 'sduser' else" in p and "if acct.dir[1, 1] = '@' then acct.dir = parse.pathname.tokens(acct.dir)" in p and "logto" not in p.lower())
    o = p.find("open 'VOC' to svoc else")
    d0 = p.find("gosub drop.pointers", o)
    w1 = p.find("write tmp to svoc, src.voc\n")
    w2 = p.find("write tmp to svoc, src.voc : '.out'")
    first = p.find("execute 'basic ' : src.voc : ' ' : todo<p> capturing out")
    d1 = p.find("gosub drop.pointers", first)
    ck("E3c", "the two temporary pointers go into the SESSION's VOC: removed first, written before the first compile, removed after the last; nothing else is executed",
       0 < o < d0 < w1 < w2 < first < d1 and p.count("execute ") == 1 and "src.voc = 'solo.examples.src'" in p
       and "read drec from svoc, did then delete svoc, did" in p and "openpath @sdsys : @ds : 'voc'" not in p)
    ck("E3d", "a program it does not ship is kept (no delete or clear of the examples file), every compile is judged on the compiler's success line",
       "delete xf" not in p and "clear.file" not in p.lower() and "if index(out, 'Compiled 1 program(s) with no errors', 1) then" in p)
    ck("E3e", "it ends on the line the installer anchors on, and is told 'only the installer' when it is not",
       "solo_examples: examples.bp ready: ' : n.new : ' new, ' : n.changed : ' changed, ' : n.same : ' the same, compiled ' : n.compiled : ' of ' : n.tried : ', ' : n.bad : ' failed'" in p
       and "solo_examples: only the installer may run this." in p)
    st = raw["setup"] or ""
    b, e = st.find("# EXAMPLES-BEGIN"), st.find("# EXAMPLES-END")
    blk = st[b:e] if 0 <= b < e else ""
    sc = ps_code(st)
    t0 = sc.find("    $script:leaked = $false\n")                 # the first line inside try { of the steps
    call = sc.find("$t = Invoke-Sd '-internal RUN gpl.bp solo_examples' '' 600000")
    between = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", "", sc[t0:call]) if 0 <= t0 < call else "{"
    depth = between.count("{") - between.count("}")
    ck("E4a", "solo-setup.ps1 runs solo_examples once, at the TOP level of the steps (brace depth %d: not inside -Upgrade, -ReloadFrom or -Passwords), "
              "so a new tree, a reload and an upgrade all reach it" % depth,
       st.count("# EXAMPLES-BEGIN") == 1 and call > 0 and sc.count("RUN gpl.bp solo_examples") == 1 and depth == 0
       and blk.find("    $t = Invoke-Sd '-internal RUN gpl.bp solo_examples'") >= 0)
    ck("E4b", "after the reload and UPDATE.ACCOUNTS, before DELETE VOC gpl.bp",
       0 < sc.find("Judge 'reloaded account VOC refreshed'") < call < sc.find("$t = Invoke-Sd '-internal DELETE VOC gpl.bp' ''"))
    ck("E4c", "judged on solo_examples' own last line with 0 failed and the disqualifiers; a failure is a WARNING, never a failed step",
       "'(?m)^solo_examples: examples\\.bp ready: \\d+ new, \\d+ changed, \\d+ the same, compiled \\d+ of \\d+, 0 failed\\s*$'" in blk
       and "$disqualify" in blk and "WARNING  the example programs were not put into the account" in blk
       and "fails" not in ps_code(blk) and "Judge " not in ps_code(blk) and "exit" not in ps_code(blk))
    ck("E4d", "Invoke-Sd waits as long as it is told (ten minutes here), 120 s by default",
       "function Invoke-Sd([string]$SdArgs, [string]$InputText, [int]$WaitMs = 120000, [switch]$NoMarker) {" in sc and "if (-not $p.WaitForExit($WaitMs)) {" in sc)   # 17 Nov 26: -NoMarker (P-3791)
    iss = iss_code(raw["iss"])
    ss = iss.find("\\solo-setup.ps1\" -AppDir \"")
    dt = iss.find("if DataTreeWasAbsent then", ss)
    up = iss.find("Params := Params + ' -Upgrade';", ss)
    ex = iss.find("if not Exec(PowerShellExe, Params, ExpandConstant(", ss)     # iss_code drops '{app}' with the comments
    ck("E5", "sd-solo.iss runs solo-setup.ps1 once, with -Upgrade for an existing tree, in the same unconditional Exec as a new tree's",
       iss.count("\\solo-setup.ps1\" -AppDir \"") == 1 and 0 < ss < dt < up < ex and ex - up < 200)
    stg = raw["stage"] or ""
    ck("E6", "stage.py ships sdsys\\examples (replaced on upgrade) and lists it as a mirror",
       "('examples'," in py_list(stg, "SDSYS_SHIP") and "('examples'," in py_list(stg, "SDSYS_MIRROR"))
    ck("E7", "no verb: no load.examples, remove.examples or solo_examples record in voc_template or newvoc, no loadexamples or removeexamples program",
       all(v is None for v in raw["verbs"].values()) and all(v is None for v in raw["progs"].values()),
       repr([k for k, v in list(raw["verbs"].items()) + list(raw["progs"].items()) if v is not None]))
    return rows


def sub(key, old, new):
    def f(raw):
        if raw.get(key) is None or old not in raw[key]:
            return None
        r = dict(raw)
        r[key] = raw[key].replace(old, new, 1)
        return r
    return f


def subfile(name, old, new):
    def f(raw):
        t = raw["files"].get(name)
        if t is None or old not in t:
            return None
        r = dict(raw)
        r["files"] = dict(raw["files"])
        r["files"][name] = t.replace(old, new, 1)
        return r
    return f


MUTANTS = [
    ("a shipped program drifts from Core's", "E1", subfile("hello", "Ctrl-Q", "Ctrl-X")),
    ("a shipped program is copied with CR LF line ends", "E2", lambda raw: dict(raw, files=dict(raw["files"], **{"cs01.hello": raw["files"]["cs01.hello"].replace("\n", "\r\n")}),
                                                                             core=dict(raw["core"], **{"cs01.hello": raw["files"]["cs01.hello"].replace("\n", "\r\n")}))),
    ("a doubled quote in a string", "E2", lambda raw: dict(raw, files=dict(raw["files"], **{"cs09.subroutines": raw["files"]["cs09.subroutines"].replace("\"the main program's i\"", "'the main program''s i'", 1)}))),
    ("solo_examples does not ask for the installer", "E3a", sub("prog", "if not(kernel(K$INTERNAL, -1)) then", "if 0 then")),
    ("solo_examples enters the account with logto", "E3b", sub("prog", "   openpath xpath to xf else", "   execute 'logto sduser' capturing lt\n   openpath xpath to xf else")),
    ("the temporary pointers are not removed after the compile", "E3c", sub("prog", "      next p\n      gosub drop.pointers", "      next p")),
    ("the temporary pointers go into the system VOC by path, as on Linux", "E3c", sub("prog", "      open 'VOC' to svoc else", "      openpath @sdsys : @ds : 'voc' to svoc else")),
    ("the pointers are named examples.bp in the session's VOC", "E3c", sub("prog", "src.voc = 'solo.examples.src'", "src.voc = 'examples.bp'")),
    ("the examples file is cleared first", "E3d", sub("prog", "   openpath xpath to xf else", "   execute 'clear.file examples.bp'\n   openpath xpath to xf else")),
    ("the compile is not judged", "E3d", sub("prog", "if index(out, 'Compiled 1 program(s) with no errors', 1) then", "if 1 then")),
    ("the closing line changes", "E3e", sub("prog", "' failed'", "' fail'")),
    ("the examples step runs only on a new tree (the upgrade misses it)", "E4a", sub("setup", "    # EXAMPLES-BEGIN\n", "    # EXAMPLES-BEGIN\n    if (-not $Upgrade) {\n")),
    ("the examples step moves inside the upgrade branch", "E4a", sub("setup", "    # EXAMPLES-BEGIN\n", "    # EXAMPLES-BEGIN\n    if ($Upgrade) {\n")),
    ("the examples step runs another program", "E4a", sub("setup", "Invoke-Sd '-internal RUN gpl.bp solo_examples' '' 600000", "Invoke-Sd '-internal RUN gpl.bp solo_account' '' 600000")),
    ("the examples step runs after DELETE VOC gpl.bp", "E4b", sub("setup", "    $t = Invoke-Sd '-internal DELETE VOC gpl.bp' ''", "    $t = ''")),
    ("a bad examples run fails the install", "E4c", sub("setup", "    else { Note '  WARNING  the example programs", "    else { $script:fails += 'examples'; Note '  WARNING  the example programs")),
    ("the examples step is judged on any text", "E4c", sub("setup", ", compiled \\d+ of \\d+, 0 failed\\s*$'", ", compiled'")),
    ("Invoke-Sd ignores the wait it is given", "E4d", sub("setup", "if (-not $p.WaitForExit($WaitMs)) {", "if (-not $p.WaitForExit(120000)) {")),
    ("sd-solo.iss stops passing -Upgrade", "E5", sub("iss", "    Params := Params + ' -Upgrade';", "    Params := Params;")),
    ("stage.py does not ship sdsys\\examples", "E6", sub("stage", "    ('examples',      'the example programs solo_examples", "    ('examplez',      'the example programs solo_examples")),
    ("load.examples is given to the account", "E7", lambda raw: dict(raw, verbs=dict(raw["verbs"], **{"newvoc/load.examples": "V\nCA\n$loadexamples\n"}))),
]


def main(argv):
    print("examples  : %s" % EX)
    print("core      : %s" % CORE_EX)
    raw = load()
    if not raw["core"]:
        print("test-soloexamples-units: NO TREE - no SD Core for Windows checkout at %s" % CORE_EX)
        return 2
    if not raw["files"] or raw["prog"] is None:
        print("test-soloexamples-units: CANNOT RUN - no %s or no solo_examples" % EX)
        return 2
    print("read      : %d example files (%d in Core), solo_examples %s, solo-setup.ps1 %s, sd-solo.iss %s, stage.py %s"
          % (len(raw["files"]), len(raw["core"]), raw["prog"] is not None, raw["setup"] is not None, raw["iss"] is not None, raw["stage"] is not None))
    if "--selftest" in argv:
        if any(not ok for _, _, ok, _ in checks(raw)):
            print("REFUSING - the unmutated source already fails")
            return 1
        missed = 0
        for name, tag, f in MUTANTS:
            m = f(raw)
            failed = [] if m is None else [i for i, _, ok, _ in checks(m) if not ok]
            if m is None or tag not in failed:
                print("  [MISSED] %s%s" % (name, " (the text to mutate is not there)" if m is None else ""))
                missed += 1
            else:
                print("  [pass] %s: caught by %s" % (name, tag))
        print("self-test: %d mutants, %d not caught" % (len(MUTANTS), missed))
        return 1 if missed else 0
    rows = checks(raw)
    bad = 0
    for i, what, ok, detail in rows:
        print("  [%s] %s %s%s" % ("PASS" if ok else "FAIL", i, what, "" if ok else "   <- " + str(detail)[:300]))
        bad += 0 if ok else 1
    print("test-soloexamples-units: %d checks, %d failed" % (len(rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
