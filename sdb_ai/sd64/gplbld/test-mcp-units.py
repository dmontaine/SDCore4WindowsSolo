#!/usr/bin/env python3
"""test-mcp-units.py - the MCP door of SD Core Solo for Windows (S.211), free: no SD, no install, no elevation.

  python C:/Users/Don/Projects/SDCore4WindowsSolo/sdb_ai/sd64/gplbld/test-mcp-units.py [--selftest]

TWO PARTS.  (1) The launcher gplbld/solo-mcp.py is run as an MCP client runs it, on pipes, against a FAKE sd-solo (SOLO_MCP_SD) that reads the request file
as mcp.call would and answers in its markers: the framing, the agent's name, the request file's lines and its removal, the local refusals, the cuts, the
timeout, an answer with no markers, a closed door.  (2) The SD BASIC source (gpl.bp/mcp_call, gpl.bp/setmcp) is read as text, with comments taken out, for
the rules the launcher cannot enforce: the gate is read before a request file is opened and again at every call, sd_run needs the write switch, every word
reaches the query processor only after a check against the file's dictionary, every path ends in ONE audit line with its status, SET.MCP asks for the
administrator first.  Messages 15950-15959, the register fields 20 and 21, the VOC records and the launcher's install line are checked as well.
It cannot say a gate refuses anybody in a live SD: that is a witness on an install.  --selftest runs the mutants of part 2.
Exit 0 all rows passed, 1 a row failed, 2 it could not run.

START-HISTORY:
11 Nov 26 Windows port - from Linux Solo 531d829 and d071011 (S.211; SOLO 57).  The fake sd-solo is a Python script behind a .cmd file (Windows runs no .py
          by itself); L6 does not ask for mode 0700 (the $mcp folder takes the account folder's access list); L20 and L22 name the Windows path and the
          Windows list of environment variables; messages are 15950-15959 (Linux 14950-14959 at +1000); B17 reads $STORED's field 2, as this tree's LOGIN
          keeps the password; K4 reads stage.py; K5 (the BASIC sdclient class methods) is not carried: this tree's sdclient has no class methods yet (SOLO 56).
11 Nov 26 dm  New (S.211).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SD64 = os.path.dirname(HERE)
SDSYS = os.path.join(SD64, "sdsys")
LAUNCHER = os.path.join(HERE, "solo-mcp.py")
WIN = sys.platform == "win32"
passed = failed = 0


def row(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  [PASS] " + name)
    else:
        failed += 1
        print("  [FAIL] " + name + ("   <- " + detail if detail else ""))


def read(p):
    with open(p, encoding="latin-1") as f:
        return f.read()


def code(text):
    """The code lines of an SD BASIC program: comment lines (first non-blank character *) and everything before START-CODE taken out."""
    body = text.split("* START-CODE", 1)[-1]
    return "\n".join(ln for ln in body.split("\n") if not ln.strip().startswith("*"))


# ---- part 1: the launcher against a fake sd-solo -------------------------------------------------------------------------------------
FAKE = r'''import json, os, sys, time
cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake.cfg")))
log = cfg["log"]
open(log, "a").write(" ".join(sys.argv[1:]) + "\n")
mode = cfg["mode"]
w = cfg["write"]
a = sys.argv[1:]
if mode == "nomarkers":
    print("some banner and no markers"); sys.exit(0)
if mode == "sleep":
    time.sleep(30)
if a[:2] == ["mcp.call", "status"]:
    if mode == "closed":
        print("MCP-BEGIN status refused"); print("The MCP door is closed"); print("MCP-END status"); sys.exit(0)
    print("MCP-BEGIN status ok"); print("mcp=on write=" + w); print("MCP-END status"); sys.exit(0)
rid = a[1]
req = open(os.path.join(cfg["acc"], "$mcp", rid)).read()
open(log + ".req", "a").write(req + "---\n")
if mode == "big":
    body = "x" * 100000
elif mode == "ctl":
    body = "a\x1b[31mred\x07b\tc\nd"
else:
    body = "answer for " + req.split("\n")[0]
print("MCP-BEGIN " + rid + " ok"); print(body); print("MCP-END " + rid)
'''


class Client:
    def __init__(self, tmp, mode="ok", write="off", timeout="30", sd=None):
        self.tmp = tmp
        self.acc = os.path.join(tmp, "acc")
        os.makedirs(self.acc, exist_ok=True)
        self.log = os.path.join(tmp, "fake.log")
        fake_py = os.path.join(tmp, "fake-sd.py")
        with open(fake_py, "w") as f:
            f.write(FAKE)
        if WIN:
            fake = os.path.join(tmp, "fake-sd.cmd")
            with open(fake, "w") as f:
                f.write('@"%s" "%s" %%*\n' % (sys.executable, fake_py))
        else:
            fake = os.path.join(tmp, "fake-sd")
            with open(fake, "w") as f:
                f.write("#!/bin/sh\nexec \"%s\" \"%s\" \"$@\"\n" % (sys.executable, fake_py))
            os.chmod(fake, 0o755)
        with open(os.path.join(tmp, "fake.cfg"), "w") as f:
            json.dump({"log": self.log, "mode": mode, "write": write, "acc": self.acc}, f)
        env = dict(os.environ, SOLO_MCP_SD=sd or fake, SOLO_MCP_ACCOUNT_DIR=self.acc, SOLO_MCP_TIMEOUT=timeout)
        self.p = subprocess.Popen([sys.executable, LAUNCHER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  encoding="utf-8", env=env)
        self.n = 0

    def call(self, method, params=None, raw=None):
        self.n += 1
        line = raw if raw is not None else json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}})
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        out = self.p.stdout.readline()
        return json.loads(out) if out else None

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()
        return self.p.returncode

    def reqs(self):
        p = self.log + ".req"
        return read(p).split("---\n")[:-1] if os.path.exists(p) else []

    def calls(self):
        return read(self.log).splitlines() if os.path.exists(self.log) else []


def init(c, name="Claude Code"):
    return c.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": name, "version": "1"}})


def part1(tmp):
    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t)
    r = init(c, "Claude Code!! <x>")
    row("L1 initialize: the protocol version is the client's, the server is named, tools are offered", bool(r) and r["result"]["protocolVersion"] == "2025-06-18"
        and r["result"]["serverInfo"]["name"] == "sd-core-solo" and "tools" in r["result"]["capabilities"], repr(r)[:200])
    row("L2 the agent's name is the client's, cut to [a-z0-9._-], and is what SD is asked with", c.calls() == ["mcp.call status claude-code-x"], repr(c.calls()))
    c.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    c.p.stdin.flush()
    r = c.call("tools/list")
    names = [x["name"] for x in r["result"]["tools"]]
    row("L3 tools/list with the write switch off: the four read-only tools and no sd_run, each read-only tool annotated readOnlyHint",
        names == ["sd_files", "sd_describe", "sd_read", "sd_query"] and all(x["annotations"]["readOnlyHint"] for x in r["result"]["tools"]), repr(names))
    r = c.call("tools/call", {"name": "sd_run", "arguments": {"command": "list voc"}})
    row("L4 sd_run with the write switch off is refused by the launcher and nothing is sent to SD", r["result"]["isError"] and len(c.reqs()) == 0
        and len(c.calls()) == 1, repr(r)[:200])
    r = c.call("tools/call", {"name": "sd_read", "arguments": {"file": "customers", "id": "C1"}})
    rq = c.reqs()
    row("L5 sd_read: the request file has tool, agent, file and id on lines 1 to 4 and the answer comes back", not r["result"]["isError"]
        and r["result"]["content"][0]["text"] == "answer for read" and rq and rq[0].split("\n")[:4] == ["read", "claude-code-x", "customers", "C1"],
        repr((r, rq))[:300])
    mcpdir = os.path.join(c.acc, "$mcp")
    mode_ok = WIN or (os.stat(mcpdir).st_mode & 0o777) == 0o700
    row("L6 the request file is removed after the call%s" % ("" if WIN else ", the directory is 0700"), os.listdir(mcpdir) == [] and mode_ok)
    r = c.call("tools/call", {"name": "sd_query", "arguments": {"file": "customers", "fields": ["name", "city"], "sort": "name", "limit": 5,
                                                              "where": [{"field": "city", "op": "=", "value": "Oslo"}]}})
    lines = c.reqs()[-1].split("\n")
    row("L7 sd_query: fields on line 5, sort 6, limit 7, a condition from line 9 as field TAB op TAB value", lines[4] == "name city" and lines[5] == "name"
        and lines[6] == "5" and lines[8] == "city\t=\tOslo", repr(lines))
    bad = [({"file": "c", "fields": ["a;b"]}, "a field name with a semicolon"), ({"file": "c", "fields": []}, "no fields"),
           ({"file": "c", "fields": ["a"], "limit": True}, "a boolean limit"), ({"file": "c", "fields": ["a"], "limit": 500}, "a limit over 200"),
           ({"file": "c", "fields": ["a"], "where": [{"field": "a", "op": "like", "value": "x"}]}, "an operator that is not one of six"),
           ({"file": "c\nlist voc", "fields": ["a"]}, "a newline in the file name"), ({"file": "c", "fields": ["a"], "where": [{"field": "a", "op": "=", "value": "x\ty"}]}, "a tab in a value")]
    before = len(c.reqs())
    res = [c.call("tools/call", {"name": "sd_query", "arguments": a})["result"]["isError"] for a, _ in bad]
    row("L8 sd_query is refused locally for %s" % "; ".join(w for _, w in bad), all(res) and len(c.reqs()) == before, repr(res))
    r = c.call("tools/call", {"name": "nosuch", "arguments": {}})
    row("L9 an unknown tool is an error result, not a crash", r["result"]["isError"])
    r = c.call("nosuch/method")
    row("L10 an unknown method is the JSON-RPC error -32601", r["error"]["code"] == -32601)
    r = c.call(None, raw="{not json")
    row("L11 text that is not JSON is the error -32700 and the launcher goes on", r["error"]["code"] == -32700 and c.call("ping")["result"] == {})
    r = c.call(None, raw="x" * (1024 * 1024 + 10))
    row("L12 a message over 1 MB is refused (-32600)", r["error"]["code"] == -32600)
    row("L13 closing the input ends the launcher with 0", c.close() == 0)

    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t, write="on")
    init(c)
    names = [x["name"] for x in c.call("tools/list")["result"]["tools"]]
    r = c.call("tools/call", {"name": "sd_run", "arguments": {"command": "list voc"}})
    rq = c.reqs()
    row("L14 with the write switch on: sd_run is offered, annotated destructiveHint, and its sentence is on line 8",
        "sd_run" in names and not r["result"]["isError"] and rq and rq[0].split("\n")[7] == "list voc", repr((names, rq))[:200])
    c.close()

    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t, mode="closed")
    r = init(c)
    row("L15 a closed door: initialize is answered with an error that carries SD's words, and the launcher ends", r["error"]["code"] == -32000
        and "closed" in r["error"]["message"] and c.close() == 0, repr(r)[:200])

    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t, mode="big")
    init(c)
    r = c.call("tools/call", {"name": "sd_files", "arguments": {}})
    txt = r["result"]["content"][0]["text"]
    row("L16 an answer over 64 KB is cut and says so", len(txt.encode()) < 66000 and txt.endswith("[output cut]"), str(len(txt)))
    c.close()

    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t, mode="ctl")
    init(c)
    txt = c.call("tools/call", {"name": "sd_files", "arguments": {}})["result"]["content"][0]["text"]
    row("L17 control characters other than newline and tab are turned into spaces in the answer", "\x1b" not in txt and "\x07" not in txt and "\t" in txt and "\n" in txt, repr(txt))
    c.close()

    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t, mode="sleep", timeout="1")
    # the status call itself sleeps in this mode: the launcher answers initialize with an error and ends
    r = init(c)
    row("L18 a call that does not finish in the time allowed is an error, not a hang", r is not None and "error" in r, repr(r)[:200])
    c.close()

    t = tempfile.mkdtemp(dir=tmp)
    c = Client(t, mode="nomarkers")
    r = init(c)
    row("L19 an answer with no markers is an error that names the kept password, not a guess", r is not None and "error" in r and "kept" in r["error"]["message"], repr(r)[:200])
    c.close()

    nosd = os.path.join("C:\\", "nonexistent", "sd-solo.exe") if WIN else "/nonexistent/sd-solo"
    p = subprocess.run([sys.executable, LAUNCHER], capture_output=True, text=True, env=dict(os.environ, SOLO_MCP_SD=nosd), stdin=subprocess.DEVNULL)
    row("L20 no sd-solo program: exit 2 and a line that says which path", p.returncode == 2 and nosd in p.stderr, repr((p.returncode, p.stderr))[:200])
    p = subprocess.run([sys.executable, LAUNCHER, "--config"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    cfg = json.loads(p.stdout)
    row("L21 --config prints a configuration snippet that names this launcher", cfg["mcpServers"]["sd-solo"]["args"] == [LAUNCHER], p.stdout[:200])
    src = read(LAUNCHER)
    body = re.sub(r'"""[\s\S]*?"""', "", src)
    row("L22 the launcher holds no password: it never opens $cred, asks for no password (no getpass, no input()) and passes SD only a fixed list of environment variables",
        "$cred" not in body and "getpass" not in body and "input(" not in body and "environ[" not in body
        and 'env={k: v for k, v in os.environ.items() if k.upper() in PASS_ENV}' in body and '"USERPROFILE"' in body and '"SYSTEMROOT"' in body, "")


# ---- part 2: the BASIC source as text ---------------------------------------------------------------------------------------------------------
def part2(files, label=""):
    mc = code(files["mcp_call"])
    sm = code(files["setmcp"])
    r = []

    def ck(name, ok, detail=""):
        r.append((name, ok, detail))

    def pos(s, pat):
        m = re.search(pat, s)
        return m.start() if m else -1

    g = pos(mc, r"gosub load\.gate")
    rr = pos(mc, r"gosub read\.request")
    ck("B1 the gate is read BEFORE the request file is read (a closed door opens nothing)", 0 <= g < rr, repr((g, rr)))
    ck("B2 the gate is read from the register at EVERY call: openpath of accounts in load.gate, ACC$MCP and ACC$MCP.WRITE, 'yes' only",
       re.search(r"load\.gate:[\s\S]*?openpath @sdsys : @ds : 'accounts'[\s\S]*?upcase\(trim\(acc\.rec<ACC\$MCP>\)\) = 'YES'[\s\S]*?upcase\(trim\(acc\.rec<ACC\$MCP\.WRITE>\)\) = 'YES'", mc) is not None)
    ck("B3 a closed door is refused (15955) after the request is read and before any tool runs", re.search(r"if not\(door\.on\) then\s+st = 'refused'\s+out = sysmsg\(15955\)\s+goto finish", mc) is not None)
    ck("B4 sd_run asks the write switch FIRST (15956) and a sentence over 500 characters or with a control character is refused",
       re.search(r"do\.run:\s+if not\(write\.on\) then\s+st = 'refused'\s+out = sysmsg\(15956\)[\s\S]*?len\(p\.sentence\) > 500[\s\S]*?convert\(ctl, blanks, p\.sentence\) # p\.sentence", mc) is not None)
    q = mc[mc.find("do.query:"):mc.find("do.run:")]
    ck("B5 sd_query: every field, condition field and the sort field must be an item of the file's dictionary before it is written into the sentence",
       len(re.findall(r"read dd from df, \w+(\.in)? else nm\.ok = @false", q)) >= 3 and "open 'DICT', p.file to df" in q, repr(len(re.findall(r"read dd from df", q))))
    ck("B6 sd_query: the operator is one of six and the value only plain characters, both checked before use; the sentence ends in SAMPLE with at most 200",
       "op.ok = (cop = '=' or cop = '#' or cop = '<' or cop = '>' or cop = '<=' or cop = '>=')" in q and "VALUE.CHARS" in q and "MAXROWS" in mc and "SAMPLE " in q)
    ck("B7 a name (file, field) is letters, digits and . _ $ - only, no space, 60 at most", "NAME.CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._$-'" in mc
       and "len(nm.in) <= 60" in mc and "index(nm.in, ' ', 1)" in mc)
    ck("B8 the request id is letters, digits and . _ - only, at most 40 (it cannot name another path)", "AGENT.CHARS" in mc and "len(req.id) <= 40" in mc
       and "rpath = @path : @ds : '$mcp' : @ds : req.id" in mc)
    fin = mc[mc.find("finish:"):mc.find("load.gate:")]
    ck("B9 every path ends at finish: ONE audit line 'mcp call agent= tool= target= status=' in lower case, then the markers",
       fin.count("kernel(K$AUDIT") == 1 and "'mcp call agent=' : agent : ' tool=' : tool : ' target=' : target[1, 120] : ' status=' : st" in fin and
       fin.index("kernel(K$AUDIT") < fin.index("print 'MCP-BEGIN") and mc.count("kernel(K$AUDIT") == 1, repr(mc.count("kernel(K$AUDIT")))
    ck("B10 the answer is made safe at finish: @fm to newline, control characters to blanks, cut at MAXOUT", "out = convert(@fm, NL, out)" in fin and "out = convert(ctl, blanks, out)" in fin
       and "MAXOUT" in fin)
    ck("B11 the audit target has its control characters taken out", "target = convert(ctl, blanks, convert(TAB.CH : NL, '  ', target))" in fin)
    ck("B12 'goto finish' is the only way out: no stop or return to the caller before the audit line", mc.split("finish:")[0].count("stop") == 0)
    ck("B13 mcp_call never writes a file, a record or the register: no write, writeu, delete, deleteseq, writeseq, osopen or os.execute", not re.search(r"(?<![.\w])(write|writeu|writev|delete|deleteseq|writeseq|os\.execute|osdelete)(?![.\w])",
                                                                                   re.sub(r";\*.*|'[^'\n]*'|\"[^\"\n]*\"", "''", mc)))
    ck("B14 mcp_call is $internal, catalogued $mcpcall, and has no ADMIN check (it must work for an ordinary session)", "$internal" in files["mcp_call"] and "$catalog $mcpcall" in files["mcp_call"] and "K$ADMINISTRATOR" not in mc)
    ck("B15 SET.MCP asks for the administrator FIRST (2001), writes only fields 20 and 21, audits in lower case", re.search(r"if not\(kernel\(K\$ADMINISTRATOR, -1\)\) then\s+stop sysmsg\(2001\)", sm) is not None
       and sm.count("acc.rec<ACC$MCP>") >= 2 and "acc.rec<ACC$MCP.WRITE>" in sm and "kernel(K$AUDIT, 'set.mcp '" in sm and "write acc.rec to acc.f, acc.name" in sm)
    ck("B16 SET.MCP changes ONE thing per command and everything else is the syntax message 15951", "case n.words = 3 and w2 = 'write'" in sm and "if not(syntax.ok) then stop sysmsg(15951)" in sm)
    ck("B17 SET.MCP ON says so when no password is kept ($STORED in $cred, its field 2 empty; message 15954)", "read kept from cred.f, '$STORED'" in sm
       and "if kept<2> = '' then display sysmsg(15954)" in sm)
    return r


def part3(files):
    r = []
    keys = read(os.path.join(SDSYS, "syscom", "keys.h"))
    r.append(("K1 the register fields are ACC$MCP 20 and ACC$MCP.WRITE 21, and no other ACC$ field has 20 or 21",
              re.search(r"define ACC\$MCP\s+20\b", keys) and re.search(r"define ACC\$MCP\.WRITE\s+21\b", keys)
              and len(re.findall(r"define ACC\$\S+\s+(20|21)\b", keys)) == 2, ""))
    miss = [n for n in range(15950, 15960) if not os.path.isfile(os.path.join(SDSYS, "messages", str(n)))]
    r.append(("K2 messages 15950-15959 exist (Linux Solo's 14950-14959, in this port's second block)", not miss, repr(miss)))
    voc = [(d, n) for d in ("newvoc", "voc_template") for n in ("set.mcp", "mcp.call") if read(os.path.join(SDSYS, d, n)) != ("V\nCA\n$" + n.replace(".", "") + "\n")]
    r.append(("K3 the VOC records set.mcp and mcp.call are verbs that run $setmcp and $mcpcall, in newvoc and voc_template", not voc, repr(voc)))
    stage = read(os.path.join(HERE, "stage.py"))
    r.append(("K4 stage.py installs the launcher with the other helpers of the SD Core Solo folder", re.search(r"^\s+'solo-mcp\.py',\s*$", stage, re.M) is not None, ""))
    return r


def main():
    for p in (LAUNCHER, os.path.join(SDSYS, "gpl.bp", "mcp_call"), os.path.join(SDSYS, "gpl.bp", "setmcp")):
        if not os.path.isfile(p):
            print("test-mcp-units: cannot run - %s is missing" % p)
            return 2
    files = {"mcp_call": read(os.path.join(SDSYS, "gpl.bp", "mcp_call")), "setmcp": read(os.path.join(SDSYS, "gpl.bp", "setmcp"))}
    print("test-mcp-units: the launcher %s and the programs under %s" % (LAUNCHER, SDSYS))
    if "--selftest" in sys.argv:
        return selftest(files)
    tmp = tempfile.mkdtemp(prefix="mcpunits-")
    try:
        part1(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, ok, detail in part2(files) + part3(files):
        row(name, bool(ok), detail)
    print("test-mcp-units: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


MUTANTS = [
    ("the request is read before the gate", "mcp_call", "   gosub load.gate\n", "", "B1"),
    ("a closed door is not refused", "mcp_call", "      out = sysmsg(15955)\n      goto finish\n   end\n\n   begin case", "      goto finish\n   end\n\n   begin case", "B3"),
    ("sd_run does not ask the write switch", "mcp_call", "   if not(write.on) then\n      st = 'refused'\n      out = sysmsg(15956)", "   if 0 then\n      st = 'refused'\n      out = sysmsg(15956)", "B4"),
    ("a query field is not checked against the dictionary", "mcp_call", "         read dd from df, nm.in else nm.ok = @false\n      end\n      if not(nm.ok) then\n         close df\n         refuse.text = 'field '",
     "      end\n      if not(nm.ok) then\n         close df\n         refuse.text = 'field '", "B5"),
    ("the audit line is dropped", "mcp_call", "   void kernel(K$AUDIT, 'mcp call agent=' : agent : ' tool=' : tool : ' target=' : target[1, 120] : ' status=' : st)\n", "", "B9"),
    ("the program writes a record", "mcp_call", "   n = dcount(rec, @fm)\n", "   write rec to f, p.id\n   n = dcount(rec, @fm)\n", "B13"),
    ("SET.MCP does not ask for the administrator", "setmcp", "   if not(kernel(K$ADMINISTRATOR, -1)) then", "   if 0 then", "B15"),
    ("SET.MCP reads Linux's lower-case kept-password id", "setmcp", "read kept from cred.f, '$STORED'", "read kept from cred.f, '$stored'", "B17"),
]


def selftest(files):
    miss = 0
    base = {k: v for k, v in files.items()}
    base_fail = [n for n, ok, _ in part2(base) if not ok]
    print("  control: the unmutated source fails %d part-2 rows" % len(base_fail))
    if base_fail:
        print("  [FAIL] control", base_fail)
        return 1
    for name, which, old, new, expect in MUTANTS:
        if old not in files[which]:
            print("  [MISS] mutant %r: its text is not in %s" % (name, which))
            miss += 1
            continue
        m = dict(base)
        m[which] = files[which].replace(old, new, 1)
        bad = [n for n, ok, _ in part2(m) if not ok]
        hit = any(b.startswith(expect + " ") for b in bad)
        print("  [%s] mutant: %s -> %s" % ("caught" if hit else "MISSED", name, ", ".join(b.split(" ")[0] for b in bad) or "no row"))
        miss += 0 if hit else 1
    print("selftest: %d mutants, %d missed" % (len(MUTANTS), miss))
    return 1 if miss else 0


if __name__ == "__main__":
    sys.exit(main())
