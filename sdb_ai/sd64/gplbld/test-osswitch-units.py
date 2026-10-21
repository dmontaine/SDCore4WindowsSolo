#!/usr/bin/env python3
"""test-osswitch-units.py - the Solo OS switch (RELEASE_1.1 165) as invariants: off as delivered, an administrator act to turn on, every gate asks.

  python gplbld/test-osswitch-units.py
  python gplbld/test-osswitch-units.py --selftest

No install, no elevation, no sd.  Exit 0 all checks passed, 1 a check failed, 2 it could not run.

20 Oct 26 SD Core Solo - ADAPTED FROM LINUX SOLO 7c6bbfc (gplbld/test-osgate-units.py, 64 rows), NOT COPIED: the gates sit in different places in this
tree (Windows' own containment helpers in op_dio2.c, its own OSPATH and DIGEST code, the Python gate in sdpy_session.c through os_user_permitted),
so the rows are written against this tree.  The live witness (a session that is refused, then turned on with SET.OS.ACCESS) is owed on an install.

  K   key numbers and user-table bits: the same numbers in the C and BASIC headers, no clash with another flag
  G   the gate: os_gate_open (administrator or USR_OS_EXEC), os_user_permitted answers it, the path test and its trust of an $internal program
  S   the call sites: OPENSEQ, DELETESEQ, OPENPATH, DIR, DIGEST, the OSPATH keys, a print file, K_PATH_OK
  B   BASIC: LOGIN and APISRVR load the two switches, CPROC's shell gate, EDIT, SETPTR, QPROC, _voc_ref
  V   the verb: setosacc is administrator only, one action, sduser, audited; its records, messages and register fields
  I   the installer: the control-file key, the question on a new install and an upgrade, the hand-off to solo-setup.ps1, the sample file

--selftest breaks each fact in turn and requires the check to say so.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SD64 = os.path.normpath(os.path.join(HERE, ".."))

FILES = {
    "keys_h": "gplsrc/keys.h",
    "sysseg_h": "gplsrc/sysseg.h",
    "op_kernel": "gplsrc/op_kernel.c",
    "op_sh": "gplsrc/op_sh.c",
    "op_dio2": "gplsrc/op_dio2.c",
    "op_seqio": "gplsrc/op_seqio.c",
    "op_dio1": "gplsrc/op_dio1.c",
    "op_dio4": "gplsrc/op_dio4.c",
    "op_xfun": "gplsrc/op_xfun.c",
    "to_file": "gplsrc/to_file.c",
    "int_keys": "sdsys/gpl.bp/int$keys.h",
    "syscom_keys": "sdsys/syscom/keys.h",
    "login": "sdsys/gpl.bp/login",
    "apisrvr": "sdsys/gpl.bp/apisrvr",
    "cproc": "sdsys/gpl.bp/cproc",
    "edit": "sdsys/gpl.bp/edit",
    "setptr": "sdsys/gpl.bp/setptr",
    "qproc": "sdsys/gpl.bp/qproc",
    "voc_ref": "sdsys/gpl.bp/_voc_ref",
    "setosacc": "sdsys/gpl.bp/setosacc",
    "m12185": "sdsys/messages/12185",
    "m12931": "sdsys/messages/12931",
    "m10102": "sdsys/messages/10102",
    "newvoc": "sdsys/newvoc/set.os.access",
    "voctemplate": "sdsys/voc_template/set.os.access",
    "iss": "gplbld/sd-solo.iss",
    "setup": "gplbld/solo-setup.ps1",
    "sample": "gplbld/sd-solo-setup.conf.sample",
}


def slurp(rel):
    with open(os.path.join(SD64, rel), encoding="latin-1") as f:
        return f.read()


def load():
    return {k: slurp(v) for k, v in FILES.items()}


def between(text, start, end):
    i = text.find(start)
    if i < 0:
        return ""
    j = text.find(end, i + len(start))
    return text[i:j] if j >= 0 else text[i:]


def has(text, *needles):
    return all(n in text for n in needles)


def checks(t):
    res = []

    def ck(name, ok, detail=""):
        res.append((name, bool(ok), detail))

    # ---- K ----
    kc = {n: re.search(r"#define %s\s+(\d+)" % n, t["keys_h"]) for n in ("K_SH", "K_OS_EXEC", "K_PATH_OK")}
    kb = {n: re.search(r"\$define %s\s+(\d+)" % re.escape(n), t["int_keys"]) for n in ("K$SH", "K$OS.EXEC", "K$PATH.OK")}
    nums_c = [kc[n].group(1) if kc[n] else None for n in ("K_SH", "K_OS_EXEC", "K_PATH_OK")]
    nums_b = [kb[n].group(1) if kb[n] else None for n in ("K$SH", "K$OS.EXEC", "K$PATH.OK")]
    ck("K1 the C and BASIC headers give K_SH, K_OS_EXEC and K_PATH_OK the same numbers, 93 to 95",
       nums_c == ["93", "94", "95"] and nums_b == nums_c, "C %s, BASIC %s" % (nums_c, nums_b))
    allkeys = re.findall(r"#define (K_[A-Z_0-9]+)\s+(\d+)", t["keys_h"])
    dup = [n for n, v in allkeys if v in ("93", "94", "95") and n not in ("K_SH", "K_OS_EXEC", "K_PATH_OK")]
    ck("K2 no other key uses 93, 94 or 95", not dup, "also: %s" % dup)
    bits = dict(re.findall(r"#define (USR_[A-Z_]+)\s+(0x[0-9A-Fa-f]+)", t["sysseg_h"]))
    vals = [int(v, 16) for v in bits.values()]
    ck("K3 USR_SH is 0x2000 and USR_OS_EXEC 0x0200, and no user-table flag shares a value",
       bits.get("USR_SH") == "0x2000" and bits.get("USR_OS_EXEC") == "0x0200" and len(vals) == len(set(vals)), "bits %s" % bits)
    ck("K4 K$SH and K$OS.EXEC are set only from a $internal program",
       all(has(between(t["op_kernel"], "case %s:" % c, "break;"), "HDR_INTERNAL") for c in ("K_SH", "K_OS_EXEC")))
    ck("K5 K$PATH.OK asks os_path_ok_for_account, for whoever is asking",
       has(between(t["op_kernel"], "case K_PATH_OK:", "} break;"), "os_path_ok_for_account")
       and "HDR_INTERNAL" not in between(t["op_kernel"], "case K_PATH_OK:", "} break;"))

    # ---- G ----
    gate = between(t["op_sh"], "bool os_gate_open(void) {", "\n}")
    ck("G1 os_gate_open is the administrator or an account given OS (USR_ADMIN | USR_OS_EXEC), and does not look at the program",
       has(gate, "USR_ADMIN", "USR_OS_EXEC") and "HDR_INTERNAL" not in gate)
    ck("G2 os_user_permitted, which OS.EXECUTE, SH and the Python gate ask, answers os_gate_open() and no longer TRUE",
       re.search(r"return os_gate_open\(\);", between(t["op_sh"], "Private bool os_user_permitted(PRIV_WHY* why) {", "\n}"))
       is not None)
    pok = between(t["op_dio2"], "bool os_path_ok_for_account(const char* name) {", "\n}\n")
    ck("G3 os_path_ok_for_account: the gate first, then the name folded (fullpath, net_normalise), refused with a surviving .., and inside the account",
       pok.find("os_gate_open()") >= 0 and pok.find("fullpath(") > pok.find("os_gate_open()")
       and pok.find("has_parent_ref(") > pok.find("net_normalise(") > pok.find("fullpath(")
       and has(pok, "SYSCOM_ACCOUNT_PATH", "path_within(cand, root)") and "return FALSE;" in pok)
    pop = between(t["op_dio2"], "bool os_path_open_ok(const char* name) {", "\n}\n")
    ck("G4 os_path_open_ok trusts a $internal program and otherwise asks the account",
       has(pop, "HDR_INTERNAL", "return TRUE;", "return os_path_ok_for_account(name);"))
    raw = between(t["op_dio2"], "Private bool net_raw_permitted(char* path, bool for_write) {", "if (connection_type != CN_SOCKET)")
    ck("G5 the OSPATH keys, CHOWN and OSRENAME (net_raw_permitted) ask the account's question first, for every connection",
       "os_path_open_ok(path)" in raw)

    # ---- S ----
    seq = t["op_seqio"]
    ck("S1 OPENSEQ by pathname asks os_path_open_ok before the port test",
       "if (!os_path_open_ok(file_name)) {" in between(seq, "ProfEvent(PROF_OPENSEQ, file_name, file_name_len);", "if (is_port(file_name))"))
    dele = between(seq, "void op_delseq() {", "exit_op_delseq:")
    ck("S2 DELETESEQ of a pathname (no record name) asks os_path_open_ok", "} else {" in dele and "os_path_open_ok(file_name)" in dele)
    ck("S3 OPENPATH asks os_path_open_ok for the resolved path, ahead of the network gate",
       0 <= t["op_dio1"].find("!map_name && !os_path_open_ok(pathname)") < t["op_dio1"].find("net_may_write = net_path_permitted"))
    d = between(t["op_dio4"], "void op_dir() {", "opendir(pathname)")
    ck("S4 DIR() asks os_path_open_ok before it opens the directory", "os_path_open_ok(pathname)" in d)
    ck("S5 DIGEST of a file asks os_path_open_ok, an $internal program excepted first",
       0 <= between(t["op_xfun"], "Private bool digest_path_ok(char* name) {", "}\n").find("os_path_open_ok(name)"))
    sf = t["to_file"]
    ck("S6 a print file's pathname asks os_path_ok_for_account in start_file, before the open_file label, and raises 12185 for the user",
       0 <= sf.find("if (!os_path_ok_for_account(fn)) {") < sf.find("  open_file:") and has(sf, "sysmsg(12185)", "process.username"))

    # ---- B ----
    for prog, label in (("login", "B1 LOGIN"), ("apisrvr", "B2 APISRVR")):
        ck("%s loads K$SH and K$OS.EXEC from ACC$SH and ACC$OS.EXEC, off unless the record says yes" % label,
           has(t[prog], "ACC$SH", "ACC$OS.EXEC", "kernel(K$SH,", "kernel(K$OS.EXEC,") and "'YES'" in t[prog])
    a = t["apisrvr"]
    ck("B3 APISRVR loads them before MASTER.LOGIN runs, and both start off",
       0 <= a.find("api.sh.grant = @false") < a.find("void kernel(K$SH,      api.sh.grant)") < a.find("if not(master.login.done) then"))
    ck("B4 CPROC's SH verb and \"!\" are the account's SH switch (sh.listed = kernel(K$SH, -1)), refused with 10053",
       "sh.listed = kernel(K$SH, -1)" in t["cproc"] and "sysmsg(10053, @logname)" in t["cproc"])
    ck("B5 EDIT needs the administrator or K$OS.EXEC and says what to ask for",
       has(t["edit"], "kernel(K$ADMINISTRATOR, -1) or kernel(K$OS.EXEC, -1)", "set.os.access os on"))
    ck("B6 SETPTR AS PATHNAME and QPROC's CSV TO pathname ask K$PATH.OK with message 12185",
       all(has(t[p], "kernel(K$PATH.OK,", "12185") for p in ("setptr", "qproc")))
    ck("B7 _voc_ref holds a VOC pointer to the OS gate (K$PATH.OK, ER$PERM) for everybody but the administrator and an account that holds OS",
       has(t["voc_ref"], "vr.free = vr.admin or kernel(K$OS.EXEC, -1)", "kernel(K$PATH.OK,", "set.status ER$PERM"))

    # ---- V ----
    s = t["setosacc"]
    ck("V1 SET.OS.ACCESS is an administrator verb, and a refusal changes nothing",
       0 <= s.find("if not(kernel(K$ADMINISTRATOR, -1)) then") < s.find("write acc.new to acc.f"))
    ck("V2 it names the one account sduser and writes ACC$SH / ACC$OS.EXEC under a lock (readu ... write ... release)",
       has(s, "acc.name = 'sduser'", "readu acc.rec from acc.f, acc.name", "write acc.new to acc.f, acc.name", "release acc.f, acc.name",
           "os.field = ACC$SH", "os.field = ACC$OS.EXEC"))
    ck("V3 one action per command: a third word, or neither SH nor OS, or neither ON nor OFF, is the syntax message 12931 and changes nothing",
       has(s, "if os.field = 0 or word.3 # '' then", "sysmsg(12931)"))
    ck("V4 only 'yes' is on, the audit line is lower case, and the answer is the state of BOTH switches (10102)",
       has(s, "os.was = (upcase(trim(acc.rec<os.field>)) = 'YES')", "downcase(word.1)", "K$AUDIT", "sysmsg(10102, acc.name, os.sh.now, os.ex.now)")
       and s.count("= 'YES'") >= 5)
    ck("V5 the verb is in newvoc and voc_template, catalogued as $setosacc",
       t["newvoc"] == t["voctemplate"] == "V\nCA\n$setosacc\n")
    fields = dict(re.findall(r"\$define (ACC\$[A-Z.]+)\s+(\d+)", t["syscom_keys"]))
    ck("V6 the register fields are 7 and 8 (ACC$SH, ACC$OS.EXEC), after SUSPENDED at 5 and with 6 left deleted",
       fields.get("ACC$SH") == "7" and fields.get("ACC$OS.EXEC") == "8" and fields.get("ACC$SUSPENDED") == "5" and "ACC$PRIOR.TIER" not in fields,
       "fields %s" % fields)
    ck("V7 messages: 12185 names the user (%1) and the remedy, 12931 is the syntax line, 10102 is the Solo wording",
       has(t["m12185"], "%1 has no OS access", "set.os.access os on") and t["m12931"].startswith("Syntax: set.os.access")
       and t["m10102"].strip() == "Account %1 has SH %2, OS.EXECUTE %3")

    # ---- I ----
    i = t["iss"]
    ck("I1 the control file's os-access is read, and only none, sh, os or both is an answer",
       has(i, "GetIniString('install', 'os-access'", "'none'", "'sh'", "'os'", "'both'"))
    ck("I2 the question is a page of two boxes, both unticked, shown on a new install AND an upgrade (skipped only for a control file's answer)",
       has(i, "OsAccessPage := CreateInputOptionPage(", "OsAccessPage.Values[0] := False;", "OsAccessPage.Values[1] := False;")
       and "Result := UseControl and (CfOsAccess <> '')" in between(i, "PageID = OsAccessPage.ID", "else if PageID = wpSelectTasks")
       and "DataTreeWasAbsent" not in between(i, "PageID = OsAccessPage.ID", "else if PageID = wpSelectTasks"))
    ck("I3 the answer reaches solo-setup.ps1 for a new tree and an upgrade alike (set before the new-tree branch, cleared after the run)",
       0 <= i.find("SetEnvironmentVariable('SD_SOLO_OS_ACCESS', OsAccessWord);") < i.find("if DataTreeWasAbsent then\n  begin\n    Params := Params + ' -Passwords';")
       and "SetEnvironmentVariable('SD_SOLO_OS_ACCESS', '');" in i)
    st = t["setup"]
    ck("I4 solo-setup.ps1 reads the answer, refuses anything but none, sh, os or both, and clears it before any child starts",
       has(st, "SD_SOLO_OS_ACCESS", "'^(none|sh|os|both)$'") and st.find("SetEnvironmentVariable('SD_SOLO_OS_ACCESS', $null") < st.find("function Invoke-Sd"))
    ck("I5 it turns on what was named with SET.OS.ACCESS SH ON / OS ON, and always reads both switches back, judged on the verb's own line",
       has(st, "Invoke-Sd '-internal SET.OS.ACCESS SH ON' ''", "Invoke-Sd '-internal SET.OS.ACCESS OS ON' ''", "Invoke-Sd '-internal SET.OS.ACCESS' ''",
           "Account sduser has SH (yes|no), OS\\.EXECUTE (yes|no)"))
    ck("I6 the sample control file documents os-access", has(t["sample"], "# os-access", "os-access="))
    return res


def mutate(t, key, old, new):
    if old not in t[key]:
        return None
    u = dict(t)
    u[key] = t[key].replace(old, new, 1)
    return u


MUTANTS = [
    ("K_OS_EXEC renumbered in the BASIC header", "int_keys", "$define K$OS.EXEC           94", "$define K$OS.EXEC           96", "K1"),
    ("USR_SH takes USR_GLOBAL's value", "sysseg_h", "#define USR_SH          0x2000", "#define USR_SH          0x0100", "K3"),
    ("K$SH settable by anyone", "op_kernel", "      if (n >= 0) {\n        if (process.program.flags & HDR_INTERNAL) {\n          if (n > 0)\n            my_uptr->flags |= USR_SH;",
     "      if (n >= 0) {\n        if (1) {\n          if (n > 0)\n            my_uptr->flags |= USR_SH;", "K4"),
    ("K$PATH.OK trusts an internal program", "op_kernel", "result.data.value = os_path_ok_for_account(path_ok_name) ? 1 : 0;",
     "result.data.value = (process.program.flags & HDR_INTERNAL) ? 1 : (os_path_ok_for_account(path_ok_name) ? 1 : 0);", "K5"),
    ("the gate forgets the administrator", "op_sh", "return (my_uptr->flags & (USR_ADMIN | USR_OS_EXEC)) != 0;", "return (my_uptr->flags & USR_OS_EXEC) != 0;", "G1"),
    ("OS.EXECUTE is open again", "op_sh", "  return os_gate_open();\n}\n\n/* ======================================================================\n   os_gate_open()",
     "  return TRUE;\n}\n\n/* ======================================================================\n   os_gate_open()", "G2"),
    ("containment does not refuse ..", "op_dio2", "  if (has_parent_ref(cand))\n    return FALSE;\n\n  if (process.syscom != NULL) {\n    descr = Element(process.syscom, SYSCOM_ACCOUNT_PATH);\n    if (k_get_c_string(descr, item, MAX_PATHNAME_LEN) > 0) {\n      if (net_normalise(item, root) && path_within(cand, root))\n        return TRUE;\n    }\n  }\n\n  return FALSE;\n}\n\nbool os_path_open_ok",
     "  if (process.syscom != NULL) {\n    descr = Element(process.syscom, SYSCOM_ACCOUNT_PATH);\n    if (k_get_c_string(descr, item, MAX_PATHNAME_LEN) > 0) {\n      if (net_normalise(item, root) && path_within(cand, root))\n        return TRUE;\n    }\n  }\n\n  return FALSE;\n}\n\nbool os_path_open_ok", "G3"),
    ("os_path_open_ok no longer trusts an internal program", "op_dio2", "  if (process.program.flags & HDR_INTERNAL)\n    return TRUE;\n  return os_path_ok_for_account(name);",
     "  return os_path_ok_for_account(name);", "G4"),
    ("OSPATH keys skip the account's question", "op_dio2", "  if (!os_path_open_ok(path))\n    return FALSE;\n\n  if (connection_type != CN_SOCKET)",
     "  if (connection_type != CN_SOCKET)", "G5"),
    ("OPENSEQ by pathname is open", "op_seqio", "    if (!os_path_open_ok(file_name)) {\n      process.status = ER_PERM;\n      goto exit_op_openseq;\n    }\n\n    /* Check if looks like a port name */",
     "    /* Check if looks like a port name */", "S1"),
    ("DELETESEQ of a path is open", "op_seqio", "  } else {\n    /* 20 Oct 26 SD Core Solo - RELEASE_1.1 165, THE OS SWITCH (Linux Solo 7c6bbfc).  With no record name",
     "  } else if (0) {\n    /* 20 Oct 26 SD Core Solo - RELEASE_1.1 165, THE OS SWITCH (Linux Solo 7c6bbfc).  With no record name", "S2"),
    ("OPENPATH is open", "op_dio1", "!map_name && !os_path_open_ok(pathname)", "0 && !os_path_open_ok(pathname)", "S3"),
    ("DIR() is open", "op_dio4", "if (!os_path_open_ok(pathname)) {\n      process.status = ER_PERM;\n    } else if", "if (0) {\n      process.status = ER_PERM;\n    } else if", "S4"),
    ("DIGEST of a file is open", "op_xfun", "  if (!os_path_open_ok(name))\n    return FALSE;\n  if (connection_type != CN_SOCKET)", "  if (connection_type != CN_SOCKET)", "S5"),
    ("a print file path is open", "to_file", "    if (!os_path_ok_for_account(fn)) {\n      os_access_refused();\n    }\n", "", "S6"),
    ("LOGIN does not load the switches", "login", "   void kernel(K$SH,      upcase(trim(acc.rec<ACC$SH>)) = 'YES')\n", "", "B1"),
    ("APISRVR does not load the switches", "apisrvr", "void kernel(K$OS.EXEC, api.os.grant)\n", "", "B2"),
    ("APISRVR loads them after MASTER.LOGIN", "apisrvr", "void kernel(K$SH,      api.sh.grant)\nvoid kernel(K$OS.EXEC, api.os.grant)\n\n* 19 Oct 26 Windows port - from Linux d6a86a7 (sheet 170): the MASTER.LOGIN paragraph",
     "* 19 Oct 26 Windows port - from Linux d6a86a7 (sheet 170): the MASTER.LOGIN paragraph", "B3"),
    ("the shell is open again", "cproc", "sh.listed = kernel(K$SH, -1)", "sh.listed = @true", "B4"),
    ("EDIT is open again", "edit", "if kernel(K$ADMINISTRATOR, -1) or kernel(K$OS.EXEC, -1) then", "if @true then", "B5"),
    ("QPROC writes anywhere", "qproc", "      if not(kernel(K$PATH.OK, csv.pathname)) then", "      if 0 then", "B6"),
    ("a VOC pointer is not held to the gate", "voc_ref", "vr.free = vr.admin or kernel(K$OS.EXEC, -1)", "vr.free = @true", "B7"),
    ("the verb is open to everyone", "setosacc", "if not(kernel(K$ADMINISTRATOR, -1)) then", "if 0 then", "V1"),
    ("the verb takes two actions", "setosacc", "if os.field = 0 or word.3 # '' then", "if os.field = 0 then", "V3"),
    ("anything but yes is on", "setosacc", "os.was = (upcase(trim(acc.rec<os.field>)) = 'YES')", "os.was = (trim(acc.rec<os.field>) # '')", "V4"),
    ("the register field moves", "syscom_keys", "$define ACC$SH           7 ", "$define ACC$SH           9 ", "V6"),
    ("message 12185 loses the remedy", "m12185", "set.os.access os on", "ask somebody", "V7"),
    ("the control file key is ignored", "iss", "GetIniString('install', 'os-access'", "GetIniString('install', 'os-acces'", "I1"),
    ("the question starts ticked", "iss", "OsAccessPage.Values[0] := False;", "OsAccessPage.Values[0] := True;", "I2"),
    ("the question is skipped on an upgrade", "iss", "    Result := UseControl and (CfOsAccess <> '')\n  else if PageID = wpSelectTasks",
     "    Result := (not DataTreeWasAbsent) or (UseControl and (CfOsAccess <> ''))\n  else if PageID = wpSelectTasks", "I2"),
    ("the answer is only passed for a new tree", "iss", "  SetEnvironmentVariable('SD_SOLO_OS_ACCESS', OsAccessWord);\n  if DataTreeWasAbsent then\n  begin\n    Params := Params + ' -Passwords';",
     "  if DataTreeWasAbsent then\n  begin\n    SetEnvironmentVariable('SD_SOLO_OS_ACCESS', OsAccessWord);\n    Params := Params + ' -Passwords';", "I3"),
    ("solo-setup accepts any word", "setup", "-notmatch '^(none|sh|os|both)$'", "-notmatch '^.*$'", "I4"),
    ("solo-setup never turns the shell on", "setup", "Invoke-Sd '-internal SET.OS.ACCESS SH ON' ''", "Invoke-Sd '-internal SET.OS.ACCESS SH OFF' ''", "I5"),
    ("the sample forgets os-access", "sample", "# os-access", "# something", "I6"),
]


def selftest():
    t = load()
    base = checks(t)
    bad = [n for n, ok, _ in base if not ok]
    if bad:
        print("selftest: the real files already fail: %s" % [b.split()[0] for b in bad])
        return False
    ok = True
    for name, key, old, new, want in MUTANTS:
        u = mutate(t, key, old, new)
        if u is None:
            print("  [FAIL] selftest: %s (the text to break was not found in %s)" % (name, FILES[key]))
            ok = False
            continue
        failed = [n.split()[0] for n, passed, _ in checks(u) if not passed]
        caught = want in failed
        print("  [%s] selftest: %s%s" % ("PASS" if caught else "FAIL", name, "" if caught else " (NOT CAUGHT; failed: %s)" % failed))
        ok = ok and caught
    return ok


def main():
    for k, v in FILES.items():
        if not os.path.isfile(os.path.join(SD64, v)):
            print("test-osswitch-units: CANNOT RUN - %s missing" % v)
            return 2
    print("test-osswitch-units: reading %d files under %s" % (len(FILES), SD64))
    if "--selftest" in sys.argv:
        return 0 if selftest() else 1
    res = checks(load())
    failed = 0
    for name, ok, detail in res:
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "   <- " + detail))
        failed += 0 if ok else 1
    print("\ntest-osswitch-units: %d passed, %d failed" % (len(res) - failed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
