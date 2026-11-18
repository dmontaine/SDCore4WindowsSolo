#!/usr/bin/env python3
# test-auditjournal-units.py - P-0288 in SD Core Solo for Windows: every audit record is ALSO sent to the Windows Application event
# log (source sd-audit), which stamps the sending process's user SID and its own time, and which the Solo user cannot rewrite (the
# audit file is that user's own).  Carried from SD Core Solo for Linux's test-auditjournal-units.py (a71033e, the journal copy), with
# the Windows mechanism in place of syslog().  FREE CHECK, text only (comments removed), no install, no elevation, no sd.
#
#   python C:\Users\<you>\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\test-auditjournal-units.py
#   python C:\Users\<you>\Projects\SDCore4WindowsSolo\sdb_ai\sd64\gplbld\test-auditjournal-units.py --selftest      (mutants)
#
# START-HISTORY
# 18 Nov 26 SD Core Solo - written for P-0288, from Linux Solo's guard of the same name.  J2 asks for win32_audit_event(buff) where
#               Linux asks for syslog(LOG_AUTHPRIV | LOG_NOTICE, "sd-audit %s", buff); J6 asks that the record is an insertion string
#               of ReportEventA (data, never a format) under the source "sd-audit"; J7 that the installer's elevated step
#               (solo-machine.ps1) registers the source on Install and Upgrade and removes it on Remove, without failing a step.
# END-HISTORY
#
#   J1  k_error.c includes win32audit.h, which declares win32_audit_event()
#   J2  audit_message() makes exactly one win32_audit_event() call, with the record buffer buff (k_error.c makes no other)
#   J3  it is made AFTER EndExclusive(ERRLOG_SEM): an event log that stalls must not hold the semaphore every session's logging waits on
#   J4  it is made whether or not the file could be written, guarded only by "bytes > 0", outside the file branch
#   J5  the record's line end is removed first, and the text is the SAME buffer the file got (one record, two places)
#   J6  win32audit.c's win32_audit_event() registers the source "sd-audit" and passes the record as ReportEventA's one insertion string
#   J7  solo-machine.ps1 registers HKLM's ...\EventLog\Application\sd-audit on Install and Upgrade, removes it on Remove, and a
#       failure there is a WARNING note, not a Fail
# NOT SAID HERE: that the Application log holds the record with the session's SID - that is a real-install witness.
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "..", "gplsrc"))
F = os.environ.get("AJ_KERROR", os.path.join(SRC, "k_error.c"))
FA = os.environ.get("AJ_AUDITC", os.path.join(SRC, "win32audit.c"))
FH = os.path.join(SRC, "win32audit.h")
FM = os.environ.get("AJ_MACHINE", os.path.join(HERE, "solo-machine.ps1"))
passed = failed = 0


def row(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  [PASS] " + name)
    else:
        failed += 1
        print("  [FAIL] " + name + ("   <- " + detail if detail else ""))


def code(path):
    s = open(path, encoding="latin-1").read()
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return re.sub(r"//[^\n]*", "", s)


def func(src, head):
    m = re.search(re.escape(head) + r"[^;{]*\{.*?\n\}", src, re.S)
    return m.group(0) if m else ""


def run():
    for p in (F, FA, FH, FM):
        if not os.path.isfile(p):
            print("NO TREE: %s missing" % p)
            return 2
    print("files: %s | %s | %s" % (F, FA, FM))
    k = code(F)
    row("J1 k_error.c includes win32audit.h, and it declares win32_audit_event()",
        '#include "win32audit.h"' in k and "void win32_audit_event(const char* text);" in code(FH))
    am = func(k, "void audit_message(char* msg)")
    row("J0 audit_message() is found", bool(am))
    calls = re.findall(r"\bwin32_audit_event\s*\(([^;]*)\);", k)
    row("J2 k_error.c makes exactly one win32_audit_event() call, in audit_message(), with buff",
        len(calls) == 1 and "win32_audit_event(" in am and calls[0].strip() == "buff", "calls: %r" % (calls,))
    i_start, i_end, i_ev = am.find("StartExclusive(ERRLOG_SEM"), am.rfind("EndExclusive(ERRLOG_SEM);"), am.find("win32_audit_event(")
    row("J3 audit_message() takes ERRLOG_SEM once, for the file, and the event log call comes after it is released",
        am.count("StartExclusive") == 1 and am.count("EndExclusive") == 1 and 0 <= i_start < i_end < i_ev,
        "start at %d, end at %d, event at %d" % (i_start, i_end, i_ev))
    tail = am[i_end:] if i_end >= 0 else ""
    row("J4 and the copy is made whether or not the file was written: guarded only by 'bytes > 0', outside the file branch",
        re.search(r"EndExclusive\(ERRLOG_SEM\);\s*if \(bytes > 0\) \{", tail) is not None, tail[:200])
    i_wr, i_nul = am.find("win32_audit_append(path, buff, bytes)"), am.find("buff[bytes] = '\\0';")
    row("J5 the line end is removed (CR and LF) and the string ended before the record goes to the event log",
        re.search(r"while \(\(bytes > 0\) && \(\(buff\[bytes - 1\] == '\\n'\) \|\| \(buff\[bytes - 1\] == '\\r'\)\)\)\s*bytes--;\s*"
                  r"buff\[bytes\] = '\\0';\s*win32_audit_event\(buff\);", tail) is not None, tail[:300])
    row("J5b and the file got the record WITH its line end first (the append precedes the cut)", 0 <= i_wr < i_nul,
        "append at %d, cut at %d" % (i_wr, i_nul))
    ev = func(code(FA), "void win32_audit_event(const char* text)")
    row("J6 win32_audit_event() opens the source \"sd-audit\" and passes the record as ReportEventA's one insertion string",
        'RegisterEventSourceA(NULL, "sd-audit")' in ev and "strs[0] = text;" in ev
        and re.search(r"ReportEventA\(src, EVENTLOG_INFORMATION_TYPE, 0, 1, sid, 1, 0, strs, NULL\)", ev) is not None, ev[:200])
    m = open(FM, encoding="utf-8-sig").read()
    reg = re.search(r"(?s)function Register-AuditEventSource \{.*?\n\}", m)
    rm = re.search(r"(?s)function Remove-AuditEventSource \{.*?\n\}", m)
    regb = reg.group(0) if reg else ""
    row("J7 solo-machine.ps1 registers ...\\EventLog\\Application\\sd-audit (EventMessageFile, TypesSupported 7) on Install and Upgrade, "
        "removes it on Remove, and a failure is a WARNING note, not Fail",
        "$AuditSourceKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\sd-audit'" in m
        and "-Name 'EventMessageFile' -PropertyType ExpandString" in regb and "-Name 'TypesSupported' -PropertyType DWord -Value 7" in regb
        and "Fail" not in regb and rm is not None and "Fail" not in rm.group(0)
        and "if ($Action -eq 'Remove') { Remove-AuditEventSource } else { Register-AuditEventSource }" in m, regb[:200])
    print("test-auditjournal-units: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


MUTANTS = [
    (F, "AJ_KERROR", "no-event-call", "    win32_audit_event(buff);\n", ""),
    (F, "AJ_KERROR", "inside-the-semaphore", "  EndExclusive(ERRLOG_SEM);\n\n  if (bytes > 0) {",
     "  if (bytes > 0)\n    win32_audit_event(buff);\n  EndExclusive(ERRLOG_SEM);\n\n  if (bytes > 0) {"),
    (F, "AJ_KERROR", "only-when-the-path-was-made", "  EndExclusive(ERRLOG_SEM);\n\n  if (bytes > 0) {",
     "  EndExclusive(ERRLOG_SEM);\n\n  if ((bytes > 0) && (*path != '\\0')) {"),
    (F, "AJ_KERROR", "line-end-kept", "    while ((bytes > 0) && ((buff[bytes - 1] == '\\n') || (buff[bytes - 1] == '\\r')))\n      bytes--;\n", ""),
    (FA, "AJ_AUDITC", "record-as-format", "strs[0] = text;", "strs[0] = \"%s\";"),
    (FA, "AJ_AUDITC", "wrong-source", 'RegisterEventSourceA(NULL, "sd-audit")', 'RegisterEventSourceA(NULL, "sd")'),
    (FM, "AJ_MACHINE", "not-on-upgrade", "if ($Action -eq 'Remove') { Remove-AuditEventSource } else { Register-AuditEventSource }",
     "if ($Action -eq 'Remove') { Remove-AuditEventSource } elseif ($Action -eq 'Install') { Register-AuditEventSource }"),
    (FM, "AJ_MACHINE", "a-failure-fails-the-install", "    catch { Note ('  WARNING: the source could not be registered (",
     "    catch { Fail ('  WARNING: the source could not be registered ("),
]


def selftest():
    import shutil
    t = tempfile.mkdtemp()
    caught = missed = 0
    print("selftest: the real files first (must pass), then mutants (each must not)")
    r = subprocess.run([sys.executable, os.path.abspath(__file__)], capture_output=True, text=True)
    if r.returncode != 0:
        print("  [FAIL] the real files do not pass:\n" + r.stdout[-600:])
        return 1
    print("  [ok] the real files pass")
    for path, var, name, old, new in MUTANTS:
        real = open(path, encoding="latin-1", newline="").read()
        if real.count(old) != 1:
            print("  [MISSED] %s: the text to change is there %d times, not once" % (name, real.count(old)))
            missed += 1
            continue
        f = os.path.join(t, name + os.path.splitext(path)[1])
        open(f, "w", encoding="latin-1", newline="").write(real.replace(old, new, 1))
        env = dict(os.environ)
        env[var] = f
        r = subprocess.run([sys.executable, os.path.abspath(__file__)], env=env, capture_output=True, text=True)
        if r.returncode == 1:
            print("  [caught] %s (exit %d)" % (name, r.returncode))
            caught += 1
        else:
            print("  [MISSED] %s: the check exited %d" % (name, r.returncode))
            missed += 1
    shutil.rmtree(t, ignore_errors=True)
    print("selftest: %d of %d mutants caught, %d missed" % (caught, caught + missed, missed))
    return 0 if missed == 0 and caught > 0 else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else run())
