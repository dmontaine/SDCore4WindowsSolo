#!/usr/bin/env python3
# test-solokeep87-units.py - free guard for what a Solo reload puts back of the deny list, the PDF reader list and the documentation PDFs.
#
# 21 Nov 26 - SOLO 87 (the three-layer audit's layer B, Linux Solo S.287; R3: "settings do not change after delete and install if the user
# chooses keep data").  Pinned from the text of solo-setup.ps1 (the reload) and sd-solo.iss (Keep):
#   K  Keep keeps sdsys\solo.policy (the deny list, a folder), sdsys\pdf (the documentation, a folder) and sdsys\viewers (the PDF reader
#      allow-list, a file), and its dialog no longer says the deny list is removed;
#   R  the reload table (RELOAD-KEPT) has viewers as a file and solo.policy as a folder, takes the kept deny list only when this install is
#      given no deny verbs (DENY.VERBS SET replaces it), and does not copy sdsys\pdf over the release's;
#   P  the kept PDFs are merged AFTER the documentation step, only on a reload, each plain lower case named file added only where this install
#      did not already make one (the release's stay the release's), a link or another name named and left.
# Free: reads two files.  --selftest breaks a copy of the text in memory and each break must turn a named row red; the live files are not
# written (their SHA-256 is printed before and after).
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ISS = os.path.join(HERE, "sd-solo.iss")
SETUP = os.path.join(HERE, "solo-setup.ps1")


def read(p):
    with open(p, encoding="utf-8", errors="replace", newline="") as f:
        return f.read().replace("\r\n", "\n")


def between(t, a, b):
    i = t.find(a)
    if i < 0:
        return ""
    j = t.find(b, i + len(a))
    return t[i:j] if j > i else t[i:]


def rows_for(iss, setup):
    rows = []

    def ck(i, what, ok, detail=""):
        rows.append((i, what, bool(ok), detail))

    ck("N0", "both files hold the places this guard reads (a guard that read nothing would pass)",
       "function KeepDataPass" in iss and "# RELOAD-KEPT-BEGIN" in setup and "# RELOAD-KEPT-END" in setup and "$pdfDir = Join-Path $sdsys 'pdf'" in setup)

    kdp = between(iss, "function KeepDataPass", "\nend;")
    ck("K1", "Keep keeps solo.policy and pdf (folders) and viewers (a file) in sdsys",
       re.search(r"RemoveFolderContents\(Root \+ '\\sdsys', '\|[^']*\|solo\.policy\|pdf\|'", kdp) is not None
       and "'|audit|audit.*|start.default|viewers|'" in kdp, "")
    ask = between(iss, "procedure AskDataChoice", "\nend;")
    ck("K2", "the Keep dialog names the deny list and the documentation as kept, and no longer lists the deny list as removed",
       "the list of denied commands, the documentation PDFs and your settings" in ask
       and "Keep removes these: the system files, GLOBAL.BP.OUT and the install logs." in ask
       and "the system files, the list of denied commands" not in ask, "")

    table = between(setup, "$keptItems = @(", "foreach ($k in $keptItems)")
    ck("R1", "the reload table has sdsys\\viewers as a file and sdsys\\solo.policy as a folder, and does not copy sdsys\\pdf",
       "@{ Rel = 'sdsys\\viewers';           Dir = $false }" in table and "@{ Rel = 'sdsys\\solo.policy';       Dir = $true }" in table
       and "sdsys\\pdf" not in table, "")
    loop = between(setup, "foreach ($k in $keptItems)", "# RELOAD-KEPT-END")
    ck("R2", "the kept deny list is not used when this install is given deny verbs (DENY.VERBS SET replaces it), as the kept passwords are not when given",
       "if ($k.Rel -eq 'sdsys\\solo.policy' -and $denyVerbs) {" in loop and "continue }" in loop
       and loop.find("$k.Rel -eq 'sdsys\\solo.policy'") < loop.find("if (-not (Test-Path -LiteralPath $src))"), "")
    i_deny = setup.find("DENY.VERBS SET")
    ck("R3", "the deny list is reloaded before DENY.VERBS SET runs, so verbs given to this install win",
       0 < setup.find("# RELOAD-KEPT-BEGIN") < i_deny, "")

    merge = between(setup, "if ($ReloadFrom) {\n        $keptPdf = Join-Path $ReloadFrom 'sdsys\\pdf'", "\n    }\n")
    i_docs = setup.find("DOCS.INSTALL")
    i_merge = setup.find("$keptPdf = Join-Path $ReloadFrom 'sdsys\\pdf'")
    ck("P1", "the kept PDFs are merged on a reload only, after the documentation step has made the release's own",
       merge != "" and 0 < i_docs < i_merge, "docs %d merge %d" % (i_docs, i_merge))
    ck("P2", "each kept file is added only where none is already there, a link or an odd name is named and left, and nothing is overwritten",
       "if (Test-Path -LiteralPath $to) { $already++; continue }" in merge
       and "-cnotmatch '^[a-z0-9][a-z0-9._-]{0,79}$'" in merge and "ReparsePoint" in merge
       and "-Force" not in merge.split("Copy-Item")[1].split("\n")[0] if "Copy-Item" in merge else False, "")
    return rows


MUTANTS = [
    ("Keep drops the deny list and the PDFs", "iss", "accounts|solo.policy|pdf|'", "accounts|'", "K1"),
    ("Keep drops the viewers file", "iss", "'|audit|audit.*|start.default|viewers|'", "'|audit|audit.*|start.default|'", "K1"),
    ("the dialog lists the deny list as removed again", "iss", "Keep removes these: the system files, GLOBAL.BP.OUT and the install logs.",
     "Keep removes these: the system files, the list of denied commands, GLOBAL.BP.OUT and the install logs.", "K2"),
    ("the reload does not take viewers", "setup", "@{ Rel = 'sdsys\\viewers';           Dir = $false }", "@{ Rel = 'sdsys\\viewerz';           Dir = $false }", "R1"),
    ("the reload copies sdsys\\pdf over the release's", "setup", "@{ Rel = 'sdsys\\solo.policy';       Dir = $true })",
     "@{ Rel = 'sdsys\\solo.policy';       Dir = $true },\n            @{ Rel = 'sdsys\\pdf';               Dir = $true })", "R1"),
    ("the kept deny list overrides given deny verbs", "setup", "if ($k.Rel -eq 'sdsys\\solo.policy' -and $denyVerbs) {", "if ($false) {", "R2"),
    ("the merge overwrites a release file", "setup", "if (Test-Path -LiteralPath $to) { $already++; continue }", "if ($false) { $already++; continue }", "P2"),
    ("the merge copies with -Force", "setup", "try { Copy-Item -LiteralPath $f.FullName -Destination $to -ErrorAction Stop } catch { }",
     "try { Copy-Item -LiteralPath $f.FullName -Destination $to -Force -ErrorAction Stop } catch { }", "P2"),
    ("the merge runs on a fresh install too", "setup", "    if ($ReloadFrom) {\n        $keptPdf", "    if ($true) {\n        $keptPdf", "P1"),
]


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def selftest():
    iss, setup = read(ISS), read(SETUP)
    before = (sha(ISS), sha(SETUP))
    print("live files, SHA-256 before: sd-solo.iss %s  solo-setup.ps1 %s" % (before[0][:12], before[1][:12]))
    bad = [r[0] for r in rows_for(iss, setup) if not r[2]]
    ok = not bad
    print("  [%s] control: the unbroken text passes every row%s" % ("PASS" if ok else "FAIL", "" if ok else " - red: %s" % bad))
    for name, which, old, new, row in MUTANTS:
        src = iss if which == "iss" else setup
        n = src.count(old)
        if n != 1:
            print("  [FAIL] mutant '%s': its anchor occurs %d times (needs exactly 1)" % (name, n))
            ok = False
            continue
        mi, ms = (iss.replace(old, new), setup) if which == "iss" else (iss, setup.replace(old, new))
        red = [r[0] for r in rows_for(mi, ms) if not r[2]]
        hit = row in red
        print("  [%s] mutant '%s' turns %s red%s" % ("PASS" if hit else "FAIL", name, row, "" if hit else " (red rows: %s)" % red))
        ok = ok and hit
    after = (sha(ISS), sha(SETUP))
    print("  [%s] the live files are unchanged" % ("PASS" if before == after else "FAIL"))
    print("test-solokeep87-units --selftest: %s (%d mutants)" % ("PASSED" if ok and before == after else "FAILED", len(MUTANTS)))
    return 0 if ok and before == after else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    for p in (ISS, SETUP):
        if not os.path.isfile(p):
            print("test-solokeep87-units: NO TREE - %s is not here" % p)
            return 2
    rows = rows_for(read(ISS), read(SETUP))
    bad = 0
    for i, what, ok, detail in rows:
        print("  [%s] %s %s%s" % ("PASS" if ok else "FAIL", i, what, "" if ok or not detail else "  <- " + detail))
        bad += 0 if ok else 1
    if len(rows) < 7:
        print("test-solokeep87-units: FAILED - only %d rows (the null case)" % len(rows))
        return 1
    print("test-solokeep87-units: %d rows, %d failed" % (len(rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
