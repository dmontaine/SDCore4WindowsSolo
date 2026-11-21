#!/usr/bin/env python3
# test-solokeep85-units.py - free guard for what a Solo Keep uninstall and a reload do about the API and ssh doors.
#
# 21 Nov 26 - SOLO 85 (the three-layer audit's layer B, Linux Solo S.282 DOORS-NOTE and DOORS-KEPT, commit e5a2c3e; R3: "settings do not
# change after delete and install if the user chooses keep data").  Sit11 measured the defect: the API the administrator had opened came
# back shut, and (the audit) an ssh he had switched off came back on, because the reinstall asked again with the boxes at their defaults.
# Pinned from the text of solo-machine.ps1 (the uninstall's elevated step) and sd-solo.iss (Keep, and the reload):
#   M  the Remove step notes the doors ONLY on a Keep (-KeepHostKey is how the uninstaller says so), FIRST, before any door is removed, by
#      running solo-doors.ps1 -Show, taking only the exact words (api: off, local, open; ssh: those and notsetup, which is off), and writing
#      doors.saved only when BOTH were read - never a half note, and a failure to read is a warning that leaves the reinstall to ask;
#   I  Keep keeps doors.saved beside sd.conf; Setup reads it only for kept data, only from a plain file (not a link), only lines that are
#      exactly key=off, key=local or key=open, and uses it only when both are there;
#   A  a reload that keeps the data takes the noted doors as its answers: a control file's api= or ssh= still wins for that door, then the
#      note, then the boxes; the Tasks page is skipped for them; a declined reload does not use it;
#   F  the install summary and the finish page say what was taken, and only then.
# Free: reads two files.  --selftest breaks a copy of the text in memory and each break must turn a named row red; the live files are not
# written (their SHA-256 is printed before and after).
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ISS = os.path.join(HERE, "sd-solo.iss")
MACH = os.path.join(HERE, "solo-machine.ps1")


def read(p):
    with open(p, encoding="utf-8", errors="replace", newline="") as f:
        return f.read().replace("\r\n", "\n")


def between(t, a, b):
    i = t.find(a)
    if i < 0:
        return ""
    j = t.find(b, i + len(a))
    return t[i:j] if j > i else t[i:]


def in_order(text, *needles):
    pos = -1
    for n in needles:
        i = text.find(n, pos + 1)
        if i < 0:
            return False
        pos = i
    return True


def rows_for(iss, mach):
    rows = []

    def ck(i, what, ok, detail=""):
        rows.append((i, what, bool(ok), detail))

    ck("N0", "both files hold the places this guard reads (a guard that read nothing would pass)",
       "function KeptDoorsUsed" in iss and "function KeptDoorWord" in iss and "function PlainFile" in iss and "function KeepDataPass" in iss
       and "function ApiWanted" in iss and "function SshOpenWanted" in iss and "$KeepHostKey" in mach and "--- scheduled jobs" in mach, "")

    # ---- M: the elevated Remove step ------------------------------------------------------------------------------------------
    start = "if ($Action -eq 'Remove' -and $KeepHostKey) {"
    block = between(mach, start, "    if ($Action -eq 'Remove') {\n        Note ''\n        Note '--- scheduled jobs")
    ck("M1", "the Remove step notes the doors only on a Keep, FIRST (before the jobs' tasks, the startup task and the firewall rule go), by running solo-doors.ps1 -Show",
       block != "" and "'solo-doors.ps1'" in block and "-Show" in block
       and 0 <= mach.find(start) < mach.find("Note '--- scheduled jobs (their tasks") and mach.find(start) < mach.find("Note '--- startup task'")
       and mach.find(start) < mach.find("Note '--- API firewall rule'"), "")
    ck("M2", "only the exact words are taken (api: off, local, open; ssh: those and notsetup, which is off), and doors.saved is written only when BOTH were read",
       "-cmatch '^api mode: (off|local|open)$'" in block and "-cmatch '^ssh mode: (off|local|open|notsetup)$'" in block
       and "if ($doorSsh -ceq 'notsetup') { $doorSsh = 'off' }" in block
       and "if (($doorApi -ne '') -and ($doorSsh -ne '')) {" in block
       and "('api=' + $doorApi + \"`r`n\" + 'ssh=' + $doorSsh + \"`r`n\")" in block, "")
    ck("M3", "a door that could not be read is a warning, never a failed step (the reinstall asks, as before)",
       "WARN  not noted" in block and "Fail" not in block and "catch {" in block, "")

    # ---- I: Keep, and Setup's reading -----------------------------------------------------------------------------------------
    kdp = between(iss, "function KeepDataPass", "\nend;")
    ck("I1", "Keep keeps doors.saved at the top of the Solo folder, beside sd.conf",
       "'|sd.conf|.sdcore-kept|doors.saved|'" in kdp, "")
    init = between(iss, "function InitializeSetup", "\nend;")
    ck("I2", "Setup reads doors.saved only for kept data and only from a plain file, takes both words or neither",
       "if KeptWasFound and PlainFile(SoloRoot + '\\doors.saved') then" in init
       and "KeptApi := KeptDoorWord(SoloRoot + '\\doors.saved', 'api');" in init and "KeptSsh := KeptDoorWord(SoloRoot + '\\doors.saved', 'ssh');" in init
       and "if (KeptApi = '') or (KeptSsh = '') then" in init, "")
    pf = between(iss, "function PlainFile", "\nend;")
    kdw = between(iss, "function KeptDoorWord", "\nend;")
    ck("I3", "PlainFile refuses a folder and a reparse point; KeptDoorWord takes only a line that is exactly key=off, key=local or key=open",
       "((FR.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0) and ((FR.Attributes and $400) = 0);" in pf
       and "(L = Key + '=off') or (L = Key + '=local') or (L = Key + '=open')" in kdw and "Trim(Lines[I])" in kdw, "")

    # ---- A: the answers ---------------------------------------------------------------------------------------------------------
    kdu = between(iss, "function KeptDoorsUsed", "\nend;")
    ck("A1", "the noted doors are used only when the reload is chosen and both were noted",
       "Result := ReloadChosen and (KeptApi <> '') and (KeptSsh <> '');" in kdu, "")
    aw = between(iss, "function ApiWanted", "\nend;")
    anw = between(iss, "function ApiNetworkWanted", "\nend;")
    sw = between(iss, "function SshWanted", "\nend;")
    sow = between(iss, "function SshOpenWanted", "\nend;")
    ck("A2", "for each answer the control file comes first, then the noted door, then the box",
       in_order(aw, "if ApiAnswered then", "else if KeptDoorsUsed then", "WizardIsTaskSelected('api')")
       and in_order(anw, "if ApiAnswered then", "else if KeptDoorsUsed then", "WizardIsTaskSelected('api\\network')")
       and in_order(sw, "if SshAnswered then", "else if KeptDoorsUsed then", "WizardIsTaskSelected('ssh')")
       and in_order(sow, "if SshAnswered then", "else if KeptDoorsUsed then", "WizardIsTaskSelected('ssh\\network')"), "")
    ck("A3", "the noted words map to the answers: api on unless off, open to the network when open; ssh the same",
       "Result := KeptApi <> 'off'\n" in aw and "Result := KeptApi = 'open'\n" in anw
       and "Result := KeptSsh <> 'off'\n" in sw and "Result := KeptSsh = 'open'\n" in sow, "")
    ck("A4", "the Tasks page is not shown for doors the note answers",
       "Result := SoloWasInstalled or KeptDoorsUsed or (ApiAnswered and SshAnswered)" in iss, "")

    # ---- F: what is said --------------------------------------------------------------------------------------------------------
    ac = between(iss, "procedure AppendChoices", "\nend;")
    cpc = between(iss, "procedure CurPageChanged", "\nend;")
    ck("F1", "the install summary and the finish page say what was taken from the note, only when it was used",
       re.search(r"if KeptDoorsUsed then\s*\n\s*S := S \+ 'doors kept     : api ' \+ KeptApi \+ ', ssh ' \+ KeptSsh", ac) is not None
       and re.search(r"if \(CurPageID = wpFinished\) and KeptDoorsUsed then\s*\n\s*WizardForm\.FinishedLabel\.Caption := WizardForm\.FinishedLabel\.Caption \+ #13#10#13#10 \+\s*\n\s*'The API is ' \+ KeptApi \+ ' and ssh is ' \+ KeptSsh \+ ', as they were before the uninstall\.';", cpc) is not None, "")
    return rows


MUTANTS = [
    # (name, file, old, new, row that must go red)
    ("the doors are noted on every removal, not only a Keep", "mach", "if ($Action -eq 'Remove' -and $KeepHostKey) {", "if ($Action -eq 'Remove') {", "M1"),
    ("ssh never set up is no longer read as off", "mach", "if ($doorSsh -ceq 'notsetup') { $doorSsh = 'off' }", "", "M2"),
    ("a half note is written", "mach", "if (($doorApi -ne '') -and ($doorSsh -ne '')) {", "if (($doorApi -ne '') -or ($doorSsh -ne '')) {", "M2"),
    ("the api word is taken from any text", "mach", "-cmatch '^api mode: (off|local|open)$'", "-match 'api mode: (.*)'", "M2"),
    ("a door that cannot be read fails the step", "mach", "else { Note ('  WARN  not noted (api", "else { Fail ('  WARN  not noted (api", "M3"),
    ("Keep drops doors.saved", "iss", "'|sd.conf|.sdcore-kept|doors.saved|'", "'|sd.conf|.sdcore-kept|'", "I1"),
    ("the note is read without kept data", "iss", "if KeptWasFound and PlainFile(SoloRoot + '\\doors.saved') then", "if PlainFile(SoloRoot + '\\doors.saved') then", "I2"),
    ("a half note is used", "iss", "if (KeptApi = '') or (KeptSsh = '') then", "if (KeptApi = '') and (KeptSsh = '') then", "I2"),
    ("a link is read as the note", "iss", " and ((FR.Attributes and $400) = 0);", " and True;", "I3"),
    ("any line is taken as a door word", "iss", "if (L = Key + '=off') or (L = Key + '=local') or (L = Key + '=open') then", "if Copy(L, 1, Length(Key) + 1) = Key + '=' then", "I3"),
    ("a declined reload uses the note", "iss", "Result := ReloadChosen and (KeptApi <> '') and (KeptSsh <> '');", "Result := (KeptApi <> '') and (KeptSsh <> '');", "A1"),
    ("the note beats the control file", "iss", "  if ApiAnswered then\n    Result := CfApi <> 'off'\n  else if KeptDoorsUsed then\n    Result := KeptApi <> 'off'",
     "  if KeptDoorsUsed then\n    Result := KeptApi <> 'off'\n  else if ApiAnswered then\n    Result := CfApi <> 'off'", "A2"),
    ("an ssh noted off is read as on", "iss", "Result := KeptSsh <> 'off'\n", "Result := KeptSsh = 'off'\n", "A3"),
    ("an api noted local is read as open", "iss", "Result := KeptApi = 'open'\n", "Result := KeptApi <> 'off'\n", "A3"),
    ("the Tasks page is still asked", "iss", "Result := SoloWasInstalled or KeptDoorsUsed or (ApiAnswered and SshAnswered)", "Result := SoloWasInstalled or (ApiAnswered and SshAnswered)", "A4"),
    ("the finish page says nothing about the doors", "iss", "'The API is ' + KeptApi + ' and ssh is ' + KeptSsh + ', as they were before the uninstall.';", "'';", "F1"),
]


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def selftest():
    iss, mach = read(ISS), read(MACH)
    before = (sha(ISS), sha(MACH))
    print("live files, SHA-256 before: sd-solo.iss %s  solo-machine.ps1 %s" % (before[0][:12], before[1][:12]))
    bad = [r[0] for r in rows_for(iss, mach) if not r[2]]
    ok = not bad
    print("  [%s] control: the unbroken text passes every row%s" % ("PASS" if ok else "FAIL", "" if ok else " - red: %s" % bad))
    for name, which, old, new, row in MUTANTS:
        src = iss if which == "iss" else mach
        n = src.count(old)
        if n != 1:
            print("  [FAIL] mutant '%s': its anchor occurs %d times (needs exactly 1)" % (name, n))
            ok = False
            continue
        mi, mm = (iss.replace(old, new), mach) if which == "iss" else (iss, mach.replace(old, new))
        red = [r[0] for r in rows_for(mi, mm) if not r[2]]
        hit = row in red
        print("  [%s] mutant '%s' turns %s red%s" % ("PASS" if hit else "FAIL", name, row, "" if hit else " (red rows: %s)" % red))
        ok = ok and hit
    after = (sha(ISS), sha(MACH))
    print("  [%s] the live files are unchanged" % ("PASS" if before == after else "FAIL"))
    print("test-solokeep85-units --selftest: %s (%d mutants)" % ("PASSED" if ok and before == after else "FAILED", len(MUTANTS)))
    return 0 if ok and before == after else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    for p in (ISS, MACH):
        if not os.path.isfile(p):
            print("test-solokeep85-units: NO TREE - %s is not here" % p)
            return 2
    rows = rows_for(read(ISS), read(MACH))
    bad = 0
    for i, what, ok, detail in rows:
        print("  [%s] %s %s%s" % ("PASS" if ok else "FAIL", i, what, "" if ok or not detail else "  <- " + detail))
        bad += 0 if ok else 1
    if len(rows) < 10:
        print("test-solokeep85-units: FAILED - only %d rows (the null case)" % len(rows))
        return 1
    print("test-solokeep85-units: %d rows, %d failed" % (len(rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
