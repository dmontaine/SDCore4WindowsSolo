#!/usr/bin/env python3
"""test-fileadmin-solo-units.py - SDNet file administration on SD Core Solo (SD Core's S.73 item 3, ef9d5946, and its D1, 7fd83ad3, carried on 11 Nov 2026), BOTH SIDES,
as invariants read off the source.

  python test-fileadmin-solo-units.py
  python test-fileadmin-solo-units.py --selftest

16 Nov 2026, Windows Solo (SOLO 56, P-32): taken from Linux Solo HEAD.  The gate's message is 15964 here (Linux 15964 + 1000, the agreed renumbering of
Linux's second block), and Linux's 11501, 11510 and 11532 are 12506, 12515 and 12537 (Linux id + 1005); everything else it reads is
the same source in both trees.

No sudo, no install, no sd.  Exit 0 every check passed, 1 a check failed, 2 it could not run.

THE OWNER'S RULE (11 Nov 2026): "the whole purpose of the global admin password is that a server can administer solo".  So a Solo SERVER serves the administration set - requests 68 and 69
(WRITE ... CREATING.SEQKEY), 70 (a verb run on the server: analyse, configure, the index verbs, create and delete a file) and 71 (FCONTROL) - ONLY to a session that signed in with the GLOBAL
password (K$GLOBAL.SESSION, set by vb.scram.final when the proof matched $global's StoredKey); every other session is refused with message 15964 and an audit line.  A Solo with no global password
(the delivered state) has no such session.  This takes the place of SD Core's test-fileswrite-units.py and the item 3 rows of its test-net-units.py: SD Core's gate is a Linux group read by
!apifilesok for a files-only login, and Solo has neither the group nor the route.

***WHAT THIS IS, AND WHAT IT IS NOT.***  It reads the C and BASIC source as text, comments removed.  It DOES NOT RUN ANYTHING, SO IT CANNOT SAY THAT THE GATE REFUSES ANYBODY: that is
sandbox-fileadmin-solo.py (a real `sd -n -q` server, the account password and the global password, the disk as evidence) and sandbox-netindex-solo.py (the index queries).  What a text check is
for: the ORDER that makes the gate a gate (the test is before the dispatch, the audit before the reply), the PRESENCE of each piece on both sides, and the numbers both sides must agree on.

--selftest breaks each invariant the way an edit plausibly would and requires the NAMED check to notice; a mutant nothing catches fails the self-test.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SD64 = os.path.abspath(os.path.join(HERE, os.pardir))
SDSYS = os.path.join(SD64, "sdsys")
GPL = os.path.join(SDSYS, "gpl.bp")

# Requests 50 to 67 of apisrvr's dispatch: the client library carry (SD Core's numbers of 15 Oct 26), merged with this carry on 11 Nov 2026.
CLIENT_50_67 = ["vb.getvar", "vb.system", "vb.trans", "vb.rtrans", "vb.txn", "vb.evaluate", "vb.evalconv", "vb.iconv", "vb.oconv",
                "vb.iconvs", "vb.oconvs", "vb.openseq", "vb.readseq", "vb.readblk", "vb.writeseq", "vb.writeblk", "vb.seek", "vb.weofseq"]
SRC = os.path.join(SD64, "gplsrc")

FILES = {
    "apisrvr": os.path.join(GPL, "apisrvr"),
    "netfile": os.path.join(GPL, "netfile"),
    "netfile.h": os.path.join(GPL, "netfile.h"),
    "netadmin": os.path.join(GPL, "netadmin"),
    "sdclient": os.path.join(GPL, "sdclient"),
    "createf": os.path.join(GPL, "createf"),
    "deletef": os.path.join(GPL, "deletef"),
    "analyse": os.path.join(GPL, "analyse"),
    "configf": os.path.join(GPL, "configf"),
    "createi": os.path.join(GPL, "createi"),
    "buildi": os.path.join(GPL, "buildi"),
    "deletei": os.path.join(GPL, "deletei"),
    "disablei": os.path.join(GPL, "disablei"),
    "netfiles.c": os.path.join(SRC, "netfiles.c"),
    "dh_ak.c": os.path.join(SRC, "dh_ak.c"),
    "dh_misc.c": os.path.join(SRC, "dh_misc.c"),
    "op_dio3.c": os.path.join(SRC, "op_dio3.c"),
    "op_kernel.c": os.path.join(SRC, "op_kernel.c"),
    "sd.h": os.path.join(SRC, "sd.h"),
    "msg15964": os.path.join(SDSYS, "messages", "15964"),
}
C_FILES = ("netfiles.c", "dh_ak.c", "dh_misc.c", "op_dio3.c", "op_kernel.c", "sd.h")
RAW = ("netfile.h", "msg15964")
VERB_OPS = {"analyse": ("file", 1), "configf": ("old.fu", 2), "createi": ("data.f", 3), "buildi": ("data.f", 4), "deletei": ("fu", 5), "disablei": ("fu", 6)}


def strip_bas(src):
    out = []
    for line in src.split("\n"):
        s = line.lstrip()
        if s.startswith("*") or s.startswith("!"):
            out.append("")
            continue
        cut = line.find(";*")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def strip_c(src):
    src = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def code(name, src):
    if name in RAW:
        return src
    if name in C_FILES:
        return strip_c(src)
    return strip_bas(src)


def at(text, needle, start=0):
    return text.find(needle, start)


def block(text, label, end_label=None, length=6000):
    """The text from LABEL to END_LABEL (or LENGTH characters)."""
    i = text.find(label)
    if i < 0:
        return ""
    if end_label:
        j = text.find(end_label, i + len(label))
        return text[i:j] if j > 0 else text[i:i + length]
    return text[i:i + length]


def cfunc(text, head):
    """The body of a C function whose definition begins with HEAD, to its closing brace at column 0."""
    i = text.find(head)
    if i < 0:
        return ""
    j = text.find("\n}\n", i)
    return text[i:j + 3] if j > 0 else ""


def dispatch(api):
    """The labels of apisrvr's `on action + 1 gosub` list, in order (index = request number + 1)."""
    m = re.search(r"on action \+ 1 gosub (.*?)\n\s*st = status\(\)", api, re.S)
    if not m:
        return []
    return [x.strip() for x in m.group(1).replace("\n", " ").split(",") if x.strip()]


def checks(srcs):
    rows = []

    def ck(i, ok, detail=""):
        rows.append((i, bool(ok), detail))

    c = {name: code(name, text) for name, text in srcs.items()}
    api = c["apisrvr"]

    # ---- S. the SERVER: Solo's gate -----------------------------------------------------------------------------------------------------------------------------------------------
    i_disp = at(api, "on action + 1 gosub")
    gate = api[at(api, "if action >= 68 and action <= 71 then"):i_disp]
    ck("S1 the gate stands BEFORE the dispatch and after the not-logged-in test: requests 68 to 71 (exactly that range) are tested for K$GLOBAL.SESSION",
       0 < at(api, "if not(logged.in) then") < at(api, "if action >= 68 and action <= 71 then") < i_disp and "if not(kernel(K$GLOBAL.SESSION, -1)) then" in gate, gate[:120])
    i_aud, i_err, i_msg, i_go = (at(gate, s) for s in ("void kernel(K$AUDIT, 'api refused request=' : action : ' global=off user=' : @logname)", "server.error = SV$ON.ERROR",
                                                       "abort.message = sysmsg(15964, action)", "goto return.status.set"))
    ck("S2 a refusal is audited FIRST ('api refused request=N global=off user=...'), then answered ON ERROR with message 15964 naming the request, and nothing is dispatched (goto return.status.set)",
       0 < i_aud < i_err < i_go and 0 < i_msg < i_go, (i_aud, i_err, i_msg, i_go))
    d = dispatch(api)
    # 11 Nov 2026: 50 to 67 are the client library carry's handlers (SD Core's numbers), merged with this carry the same day.
    # 11 Nov 2026 (owner, "Go with option 1"): 49 is SD Core's vb.revision and the ssh key is 72, Solo's own, after SD Core's 71.
    ck("S3 the dispatch list: 49 is vb.revision (SD Core's), 50 to 67 are the client library's handlers in SD Core's order, 68 vb.writeseqkey, 69 vb.writeuseqkey, 70 vb.fileadmin, 71 vb.fcontrol, 72 vb.sshkey (Solo's own), and nothing after them but the default",
       len(d) == 74 and d[49] == "vb.revision" and d[50:68] == CLIENT_50_67 and d[68:72] == ["vb.writeseqkey", "vb.writeuseqkey", "vb.fileadmin", "vb.fcontrol"]
       and d[72] == "vb.sshkey" and d[73] == "vb.illegal.action" and d.count("vb.sshkey") == 1, "%d entries; %r" % (len(d), d[48:]))
    sf = block(api, "vb.scram.final:", "scram.check.proof - does")
    ck("S4 K$GLOBAL.SESSION is set ONCE in apisrvr, in vb.scram.final, only when the proof matched $global (scram.via = 'global') and only after K$ADMINISTRATOR took",
       api.count("kernel(K$GLOBAL.SESSION, 1)") == 1 and 0 < at(sf, "if scram.via = 'global' then") < at(sf, "if kernel(K$ADMINISTRATOR, 1) then") < at(sf, "void kernel(K$GLOBAL.SESSION, 1)"),
       sf[at(sf, "if scram.via = 'global' then"):][:160])
    kg = block(c["op_kernel.c"], "case K_GLOBAL_SESSION:", "break;")
    ck("S5 the kernel sets the flag only for a $internal program and only on a session that holds USR_ADMIN (op_kernel.c K_GLOBAL_SESSION)",
       "process.program.flags & HDR_INTERNAL" in kg and "(n > 0) && (my_uptr->flags & USR_ADMIN)" in kg and "my_uptr->flags |= USR_GLOBAL" in kg, kg[:200])
    fa = block(api, "vb.fileadmin:", "fa.check.words:")
    # 11 Nov 26: operation 1 is analyze.file - the verb the VOC still has (analyse.file is in sdsys/voc_removed since S.87; SD Core's apisrvr still says analyse.file, a defect there)
    ck("S6 vb.fileadmin chooses the verb by the OPERATION NUMBER from a fixed list (1 analyze.file, the spelling the VOC holds; 7 empty) and names the file by file.names, never by the text it was sent",
       "field('analyze.file,configure.file,create.index,build.index,delete.index,disable.index,,create.file,delete.file', ',', fa.op)" in fa and "fa.name = file.names<fno>" in fa
       and "fa.cmd = fa.verb" in fa, fa[:120])
    o = [at(fa, s) for s in ("gosub check.file", "gosub check.voc.edit", "gosub fa.check.words", "void kernel(K$AUDIT, 'api admin request=70 op='", "close files(fno)", "execute fa.cmd capturing response")]
    ck("S7 vb.fileadmin's order: check.file, check.voc.edit (every operation but 1), fa.check.words, the audit line, the file closed, and only then the execute; no.query for 8 and 9; refused under SDCLIENT/SDNet",
       all(x > 0 for x in o) and o == sorted(o) and "if fa.op # 1 then" in fa and "if fa.op = 8 or fa.op = 9 then fa.cmd := ' no.query'" in fa
       and at(fa, "if config(\"SDCLIENT\") # 0 or kernel(K$SDNET, -1) then") < o[0], o)
    fw = block(api, "fa.check.words:", "vb.fcontrol:")
    ck("S8 fa.check.words: 200 characters at most, letters digits . _ - only, PATHNAME LPTR FORCE NO.QUERY refused, DIRECTORY only as the last word",
       "if len(fa.text) > 200 then" in fw and "fa.allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'" in fw
       and "',PATHNAME,LPTR,FORCE,NO.QUERY,'" in fw and "if upcase(fa.tok) = 'DIRECTORY' and fa.w # fa.n.words then fa.tok.ok = @false" in fw, fw[:100])
    fc = block(api, "vb.fcontrol:", "check.file:")
    wk = block(api, "writeseqkey.common:", "vb.fileadmin:")
    ck("S9 vb.fcontrol asks check.file, then check.voc.edit for every key but FC$VALID.ID; writeseqkey.common asks check.file, check.voc.edit and the hashed-file test before it writes",
       0 < at(fc, "gosub check.file") < at(fc, "if fc.key # FC$VALID.ID then") < at(fc, "gosub check.voc.edit") < at(fc, "response = fcontrol(")
       and 0 < at(wk, "gosub check.file") < at(wk, "gosub check.voc.edit") < at(wk, "# FL$TYPE.DH then") < at(wk, "creating.seqkey wk.id"), (fc[:60], wk[:60]))
    vo = block(api, "vb.open:", "vb.read:")
    ck("S10 file.names: vb.open keeps the name only when the open was OK, vb.close forgets it, the first-time block starts it empty, and it is in the common block",
       "if server.error = SV$OK then file.names<i> = cmnd" in vo and "file.names<fno> = ''" in vo and "   file.names = ''" in api
       and re.search(r"common /\$APISRVR/[^\n]*\n[^\n]*\nfile\.names,", api) is not None, vo[-200:])
    sl, sr = block(api, "vb.selectleft:", "vb.selectright:"), block(api, "vb.selectright:", "vb.mark.mapping:")
    ck("S11 D1: vb.selectleft and vb.selectright ask check.list before the scan, and vb.selectright RETURNs (it fell into vb.mark.mapping)",
       0 < at(sl, "gosub check.list") < at(sl, "selectleft cmnd") and 0 < at(sr, "gosub check.list") < at(sr, "selectright cmnd")
       and "selectright cmnd[5,999] from files(fno) setting response to listno ; return" in sr, sr[-160:])
    m = srcs.get("msg15964", "")
    ck("S12 message 15964 exists, takes the request number (%1) and names the global password; no other program of Solo's gpl.bp cites it",
       "%1" in m and "global password" in m and m.endswith("\n") and m.count("\n") == 1, repr(m))

    # ---- C. the CLIENT --------------------------------------------------------------------------------------------------------------------------------------------------------------
    nfc = c["netfiles.c"]
    g = cfunc(nfc, "int net_gate(FILE_VAR* fvar")
    ck("C1 net_gate no longer refuses CREATING.SEQKEY (the counter is the server's) and still refuses a read-mode handle first and a transaction after",
       "P_SEQKEY" not in g and 0 < at(g, "MSG_READ_ONLY") < at(g, "process.txn_id != 0"), g[:120])
    mdef = dict(re.findall(r"#define\s+(NF_[A-Z]+)\s+(\d+)", nfc))
    bdef = dict(re.findall(r"\$define\s+NF\$([A-Z]+)\s+(\d+)", srcs["netfile.h"]))
    pairs = [("NF_ADMIN", "ADMIN", "20"), ("NF_CREATEFILE", "CREATEFILE", "21"), ("NF_FCONTROL", "FCONTROL", "22"), ("NF_SEQKEY", "SEQKEY", "23"), ("NF_INDEXQ", "INDEXQ", "24")]
    ck("C2 the handler's five operations have the same numbers in netfiles.c and netfile.h: ADMIN 20, CREATEFILE 21, FCONTROL 22, SEQKEY 23, INDEXQ 24",
       all(mdef.get(a) == n and bdef.get(b) == n for a, b, n in pairs), repr([(a, mdef.get(a), bdef.get(b)) for a, b, n in pairs]))
    na, nf_, nq = cfunc(nfc, "int net_admin("), cfunc(nfc, "int net_fcontrol("), cfunc(nfc, "int net_index_query(")
    ck("C3 net_admin asks net_gate (PEEK for analyse.file, ADMIN otherwise) before it sends; net_fcontrol the same (PEEK for key 6); net_index_query asks no change gate",
       0 < at(na, "net_gate(fvar, (op == 1) ? NETG_PEEK : NETG_ADMIN") < at(na, "net_change_result(") and 0 < at(nf_, "net_gate(fvar, (key == 6) ? NETG_PEEK : NETG_ADMIN") < at(nf_, "net_change_result(")
       and "net_gate" not in nq and "NF_INDEXQ" in nq, (na[:80], nf_[:80]))
    ck("C4 NETG_ADMIN is 6 in sd.h and every new entry point is declared there", re.search(r"#define\s+NETG_ADMIN\s+6\b", c["sd.h"]) is not None
       and all(("int %s(" % f) in c["sd.h"] for f in ("net_admin", "net_create_file", "net_fcontrol", "net_write_seqkey", "net_index_query", "net_last_reply_status")))
    dk = c["dh_ak.c"]
    still = all(('net_refuse(%s, "%s")' % (v, w)) in dk or ('net_refuse(descr->data.fvar, "%s")' % w) in dk for v, w in (("fvar", "CLEAR.AK"), ("fvar", "AKENABLE"), ("fvar", "AKMAP"), ("x", "AKREAD"), ("x", "AKWRITE"), ("x", "AKDELETE")))
    gone = not any(('"%s"' % w) in dk for w in ("SELECTINDEX", "SETRIGHT", "SETLEFT", "SELECTRIGHT/SELECTLEFT"))
    ck("C5 D1: INDICES, SELECTINDEX, SETLEFT/RIGHT, SELECTLEFT/RIGHT no longer refuse a remote file (net_selindex, net_akscan, net_index_query), and AKREAD, AKWRITE, AKDELETE, CLEAR.AK, "
       "AKENABLE, AKMAP still do", still and gone and dk.count("net_index_query(") >= 5, (still, gone))
    dm = c["dh_misc.c"]
    of, pf = cfunc(dm, "void op_fcontrol()"), cfunc(dm, "void pub_fcontrol()")
    ck("C6 FCONTROL: the public function sends a remote file's key to the server (net_fcontrol) instead of refusing it; the internal FC_NET_ADMIN needs a remote file and FC_NET_CREATE a local one",
       "net_fcontrol(fvar, action" in pf and 'net_refuse(fvar, "FCONTROL")' not in pf
       and "((action == FC_NET_ADMIN) && (fvar->type != NET_FILE)) || ((action == FC_NET_CREATE) && (fvar->type == NET_FILE))" in of, pf[:80])
    od = c["op_dio3.c"]
    ck("C7 WRITE ... CREATING.SEQKEY of a remote file goes to net_write_seqkey inside the NET_FILE branch, after refuse_net_file has asked net_gate",
       0 < at(od, "refuse_net_file(fvar, op_flags, keep_lock ? \"WRITEU\" : \"WRITE\", NETG_WRITE)") < at(od, "net_write_seqkey(fvar, src_descr->data.str.saddr, keep_lock, &net_id)"))
    nf = c["netfile"]
    ops = all(("case op = NF$%s" % o) in nf for o in ("ADMIN ", "CREATEFILE", "FCONTROL", "SEQKEY", "INDEXQ"))
    ap = block(nf, "admin.prepare:", "admin.outcome:")
    ck("C8 the handler: the five operations are dispatched; admin.prepare refuses a read-mode handle (12506) before it takes the connection, and a transaction (12515) for a change",
       ops and 0 < at(ap, "if nf.h.mode(hx) # 'write' then") < at(ap, "need.conn = @true") and "fail.num = 12515" in ap, ap[:80])
    cf = block(nf, "act.createfile:", "act.fcontrol:")
    ck("C9 act.createfile asks check.server (the gate, the server, the list, the mode, the login, the limits) and the write mode before it connects or sends",
       0 < at(cf, "gosub check.server") < at(cf, "if fmode # 'write' then") < at(cf, "gosub connect.new") < at(cf, "obj->fileadmin(8, 0, c)"), cf[:80])
    sc = c["sdclient"]
    nums = dict(re.findall(r"\$define\s+(Srvr(?:WriteSeqKey|WriteuSeqKey|Fileadmin|Fcontrol))\s+(\d+)", sc))
    tr = block(sc, "local function text.request(", "\nend\n")
    ck("C10 the class: requests 68 to 71 numbered as SD Core numbers them, fileadmin / fcontrol / writeseqkey / writeuseqkey / indices / selectindexv / selectindexk through text.request, "
       "which aborts only when quiet is not set",
       nums == {"SrvrWriteSeqKey": "68", "SrvrWriteuSeqKey": "69", "SrvrFileadmin": "70", "SrvrFcontrol": "71"}
       and all(("public function %s(" % f) in sc for f in ("fileadmin", "fcontrol", "writeseqkey", "writeuseqkey", "indices", "selectindexv", "selectindexk"))
       and "if not(quiet) then abort abort.text" in tr, repr(nums))
    ck("C11 selectleft, selectright, setleft and setright of the class honour quiet (the $netfile handler is quiet)",
       "if not(quiet) then abort 'SELECTLEFT generated an abort event'" in sc and "if not(quiet) then abort 'SELECTRIGHT generated an abort event'" in sc
       and sc.count("if server.error = SV$ON.ERROR and not(quiet) then\n            abort 'SET") == 2)
    bad = []
    for prog, (var, op) in VERB_OPS.items():
        t = c[prog]
        i = t.find("if fileinfo(%s, FL$TYPE) = FL$TYPE.NET then" % var)
        j = t.find("call !netadmin(%s, %d, " % (var, op), i)
        if i < 0 or j < 0 or j - i > 200 or "stop" not in t[j:j + 160]:
            bad.append(prog)
    ck("C12 each verb hands a remote file to !netadmin with its own operation number: analyse 1, configure 2, create.index 3, build.index 4, delete.index 5, disable.index 6", not bad, repr(bad))
    cr = block(c["createf"], "create.remote.file:", "\nend\n")
    ck("C13 create.file ... SERVER writes the N pointer ONLY after the server's create.file returned 0, and refuses a name already in the VOC before anything is sent",
       0 < at(cr, "read voc.rec from voc.f, file.name then") < at(cr, "call !netadmin(voc.f, 8,") < at(cr, "if net.rc # 0 then") < at(cr, "write voc.rec to voc.f, file.name"), cr[:80])
    dr = block(c["deletef"], "delete.remote.file:", "check.sdsys.file:")
    ck("C14 delete.file of an N pointer removes the pointer only after the server's delete.file returned 0 (a refusal keeps it)",
       0 < at(dr, "call !netadmin(remote.f, 9, '', net.rc, @false)") < at(dr, "if net.rc # 0 then") < at(dr, "delete voc.f, file.name\n   @system.return.code = 0\n   display sysmsg(12537"), dr[-200:])
    nad = c["netadmin"]
    ck("C15 !netadmin: operation 8 is FCI$NET.CREATE (no file yet), every other FCI$NET.ADMIN with 'op<FM>words'; the return code is STATUS()",
       "shown = fcontrol.int(fu, FCI$NET.CREATE, words)" in nad and "shown = fcontrol.int(fu, FCI$NET.ADMIN, op : @fm : words)" in nad and at(nad, "rc = status()") > at(nad, "FCI$NET.ADMIN"))
    return rows


def sub(name, old, new):
    def f(srcs):
        s = dict(srcs)
        if old not in s[name]:
            raise KeyError("%s: %r is not in the file, so the mutant cannot be made" % (name, old[:60]))
        s[name] = s[name].replace(old, new, 1)
        return s
    return f


MUTANTS = [
    ("the gate tests the administrator instead of the global session", "S1", sub("apisrvr", "      if not(kernel(K$GLOBAL.SESSION, -1)) then\n         void kernel(K$AUDIT, 'api refused request='",
                                                                                 "      if not(kernel(K$ADMINISTRATOR, -1)) then\n         void kernel(K$AUDIT, 'api refused request='")),
    ("the gate leaves 71 out", "S1", sub("apisrvr", "if action >= 68 and action <= 71 then", "if action >= 68 and action <= 70 then")),
    ("the refusal is not audited", "S2", sub("apisrvr", "void kernel(K$AUDIT, 'api refused request=' : action : ' global=off user=' : @logname)", "null")),
    ("the refusal answers OK", "S2", sub("apisrvr", "         server.error = SV$ON.ERROR\n         abort.message = sysmsg(15964, action)", "         abort.message = sysmsg(15964, action)")),
    ("a dispatch slot is lost (70 lands on 69's handler)", "S3", sub("apisrvr", "   vb.weofseq,        ;*  67   Truncate at the position (QMWeofSeq)\n", "")),
    ("the global flag is set for any proof", "S4", sub("apisrvr", "               if scram.via = 'global' then\n                  if kernel(K$ADMINISTRATOR, 1) then",
                                                       "               if 1 then\n                  if kernel(K$ADMINISTRATOR, 1) then")),
    ("the kernel sets the flag without the administrator", "S5", sub("op_kernel.c", "if ((n > 0) && (my_uptr->flags & USR_ADMIN))\n          my_uptr->flags |= USR_GLOBAL;",
                                                                     "if (n > 0)\n          my_uptr->flags |= USR_GLOBAL;")),
    ("request 70 names its file by the text it was sent", "S6", sub("apisrvr", "   fa.name = file.names<fno>\n", "   fa.name = field(fa.text, ' ', 1)\n")),
    ("request 70 runs the command before it checks the words", "S7", sub("apisrvr", "gosub fa.check.words\nif fa.bad # '' then", "if 0 then")),
    ("request 70 does not close the file first", "S7", sub("apisrvr", "if fa.names.file then close files(fno)\n", "")),
    ("PATHNAME is let through", "S8", sub("apisrvr", "',PATHNAME,LPTR,FORCE,NO.QUERY,'", "',LPTR,FORCE,NO.QUERY,'")),
    ("FCONTROL changes the file with no VOC rule", "S9", sub("apisrvr", "if fc.key # FC$VALID.ID then\n   gosub check.voc.edit", "if 0 then\n   gosub check.voc.edit")),
    ("vb.open keeps the name of a failed open", "S10", sub("apisrvr", "if server.error = SV$OK then file.names<i> = cmnd", "file.names<i> = cmnd")),
    ("vb.selectright falls into vb.mark.mapping again", "S11", sub("apisrvr", "setting response to listno ; return   ;* 21 Oct 26 dm, S.73 item 3 (D1): it had no RETURN",
                                                                  "setting response to listno   ;* 21 Oct 26 dm, S.73 item 3 (D1): it had no RETURN")),
    ("the message loses the request number", "S12", sub("msg15964", "(request %1)", "(request)")),
    ("net_gate refuses CREATING.SEQKEY again", "C1", sub("netfiles.c", "  if (process.txn_id != 0) {\n    st = net_refuse_with(fvar, what, MSG_TXN, -ER_TXN);",
                                                          "  if ((kind == NETG_WRITE) && (op_flags & P_SEQKEY))\n    return -1;\n  if (process.txn_id != 0) {\n    st = net_refuse_with(fvar, what, MSG_TXN, -ER_TXN);")),
    ("a handler number differs between C and BASIC", "C2", sub("netfile.h", "$define NF$INDEXQ         24", "$define NF$INDEXQ         25")),
    ("net_admin sends without asking the gate", "C3", sub("netfiles.c", "  st = net_gate(fvar, (op == 1) ? NETG_PEEK : NETG_ADMIN, 0, verb);\n  if (st != 0)\n    return st;", "  st = 0;")),
    ("NETG_ADMIN takes another number", "C4", sub("sd.h", "#define NETG_ADMIN 6", "#define NETG_ADMIN 7")),
    ("AKREAD stops refusing a remote file", "C5", sub("dh_ak.c", 'net_refuse(descr->data.fvar, "AKREAD");', ";")),
    ("SETLEFT refuses a remote file again", "C5", sub("dh_ak.c", "  if (fvar->type == NET_FILE) { /* 21 Oct 26 S.73 item 3, D1 (carried 11 Nov 26): the position is the server's",
                                                       "  if (fvar->type == NET_FILE) net_refuse(fvar, \"SETLEFT\");\n  if (fvar->type == NET_FILE) { /* 21 Oct 26 S.73 item 3, D1 (carried 11 Nov 26): the position is the server's")),
    ("FC_NET_CREATE is taken on a remote file", "C6", sub("dh_misc.c", "((action == FC_NET_CREATE) && (fvar->type == NET_FILE))", "0")),
    ("CREATING.SEQKEY of a remote file skips the gate", "C7", sub("op_dio3.c", 'if (refuse_net_file(fvar, op_flags, keep_lock ? "WRITEU" : "WRITE", NETG_WRITE))', "if (0)")),
    ("admin.prepare connects before it looks at the mode", "C8", sub("netfile", "admin.prepare:\n   need.gate = @false ; need.conn = @false ; any.acct = @false ; allow.lost = @true\n"
                                                                      "   gosub get.handle\n   if failed then return\n   if nf.h.mode(hx) # 'write' then\n      gosub act.refuse\n      return\n   end\n",
                                                                      "admin.prepare:\n   need.gate = @false ; need.conn = @false ; any.acct = @false ; allow.lost = @true\n"
                                                                      "   gosub get.handle\n   if failed then return\n")),
    ("act.createfile connects before the server checks", "C9", sub("netfile", "   changing = @true\n   gosub check.server\n   if failed then return\n   if fmode # 'write' then",
                                                                     "   changing = @true\n   if fmode # 'write' then")),
    ("text.request aborts a quiet caller", "C10", sub("sdclient", "if not(quiet) then abort abort.text", "abort abort.text")),
    ("SELECTRIGHT aborts a quiet caller", "C11", sub("sdclient", "if not(quiet) then abort 'SELECTRIGHT generated an abort event'", "abort 'SELECTRIGHT generated an abort event'")),
    ("build.index sends the wrong operation", "C12", sub("buildi", "call !netadmin(data.f, 4, ", "call !netadmin(data.f, 3, ")),
    ("create.file writes the pointer before the server answered", "C13", sub("createf", "   call !netadmin(voc.f, 8, net.server : @fm : remote.words, net.rc, @false)\n",
                                                                             "   write voc.rec to voc.f, file.name\n   call !netadmin(voc.f, 8, net.server : @fm : remote.words, net.rc, @false)\n")),
    ("delete.file removes the pointer whatever the server said", "C14", sub("deletef", "   call !netadmin(remote.f, 9, '', net.rc, @false)\n   if net.rc # 0 then",
                                                                             "   call !netadmin(remote.f, 9, '', net.rc, @false)\n   if 0 then")),
    ("!netadmin sends create.file as an operation on a file", "C15", sub("netadmin", "shown = fcontrol.int(fu, FCI$NET.CREATE, words)", "shown = fcontrol.int(fu, FCI$NET.ADMIN, words)")),
]


def load():
    srcs, missing = {}, []
    for name, path in FILES.items():
        try:
            with open(path, encoding="latin-1") as f:
                srcs[name] = f.read()
        except OSError:
            srcs[name] = ""
            missing.append(name)
    return srcs, missing


def run_selftest(srcs):
    base_fail = {r[0].split()[0] for r in checks(srcs) if not r[1]}
    print("selftest: the unchanged tree fails %d check(s): %s" % (len(base_fail), " ".join(sorted(base_fail)) or "none"))
    if base_fail:
        print("selftest: the tree is not whole, so a mutant's own failure cannot be told from the tree's; run the plain check first")
        return False
    ok_all, missed = True, 0
    for name, want, mut in MUTANTS:
        try:
            mutated = mut(srcs)
        except KeyError as exc:
            print("  [FAIL] selftest: %s  <- %s" % (name, exc))
            ok_all = False
            continue
        failed = sorted({r[0].split()[0] for r in checks(mutated) if not r[1]})
        hit = want in failed
        missed += 0 if hit else 1
        print("  [%s] selftest: %s is caught by %s (failed: %s)" % ("PASS" if hit else "FAIL", name, want, " ".join(failed) or "none"))
        ok_all = ok_all and hit
    print("selftest: %d mutants, %d missed" % (len(MUTANTS), missed))
    return ok_all


def main(argv):
    srcs, missing = load()
    print("test-fileadmin-solo-units: tree %s" % SD64)
    if "apisrvr" in missing or "netfiles.c" in missing:
        print("test-fileadmin-solo-units: CANNOT RUN - gpl.bp/apisrvr or gplsrc/netfiles.c is not there")
        return 2
    if missing:
        print("test-fileadmin-solo-units: not there (their checks fail): %s" % ", ".join(missing))
    rows = checks(srcs)
    if not rows:
        print("test-fileadmin-solo-units: CANNOT RUN - no check ran")
        return 2
    # S12's second half: no other program of Solo's gpl.bp cites 15964 (read here, not in checks(), because it walks the directory)
    others = []
    for fn in sorted(os.listdir(GPL)):
        if fn == "apisrvr":
            continue
        try:
            with open(os.path.join(GPL, fn), encoding="latin-1") as f:
                if re.search(r"sysmsg\(15964\b", f.read()):
                    others.append(fn)
        except (OSError, IsADirectoryError):
            pass
    rows.append(("S12b no program but apisrvr cites message 15964 (it is the gate's own text)", not others, repr(others)))
    failed = 0
    for i, ok, detail in rows:
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", i, "" if ok or not detail else "   <- " + str(detail)[:220]))
        failed += 0 if ok else 1
    print("\ntest-fileadmin-solo-units: %d passed, %d failed" % (len(rows) - failed, failed))
    ok = failed == 0
    if "--selftest" in argv:
        ok = run_selftest(srcs) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
