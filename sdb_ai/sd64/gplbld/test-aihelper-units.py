#!/usr/bin/env python3
"""test-aihelper-units.py - the AI helper sd-ai.exe of SD Core Solo (gplsrc/sdai, native C), BUILT AND RUN.  RELEASE_1.1 246.

  python C:\\Users\\Don\\SDCoreProject\\SDCore4WindowsSolo\\sdb_ai\\sd64\\gplbld\\test-aihelper-units.py [--selftest [--from=N]]

From SD Core's guard of the same name (13 Nov 2026), 16 Nov 2026 for Solo's same-user helper (Linux Solo gplbld/sd-ai, owner 23 Oct 2026): there
is no service and no named pipe, the SD session starts "sd-ai.exe --one" per request on anonymous pipes, the caller is the helper's OWN token,
the gate is gate=yes in ai.conf, and any caller may change the settings and the keys.

Free: no sd, no install, no elevation, no network but the loopback (files in a temporary directory, a fake provider on 127.0.0.1).  It BUILDS the
helper from gplsrc/sdai with MSYS2's UCRT64 gcc and the static OpenSSL, as the Makefile's sd-ai target does, plus -DSDAI_TESTS (the test build's
one hook: --test-key writes and reads a key on its own), into a temporary tree laid out as Solo's (<root>\\usr\\bin\\sd-ai.exe with ai-providers
and ai-context beside it, so the program's own defaults put the state in <root>\\sdsys\\ai).  Exit 0 every row passed, 1 a row failed, 2 it
could not run (not Windows, no UCRT64 gcc or OpenSSL).

WHAT IS HELD.  THE KEY - DPAPI round trip, not in clear, the file private (this account and SYSTEM), a blob made for one provider not readable as
another's, a key file Everyone may read refused; THE CALLER - the helper's own token, read and logged; standard input that is not a pipe (a file
holding a valid request, the NUL device) is refused with Linux Solo's words before anything is read, and nothing is changed; THE GATE - absent,
and any word but exactly "yes" (on, YES), is off: an ask is nogate in Linux Solo's words and the status says gate false; set what=gate yes writes
gate=yes, no REMOVES the line, anything else is badreq "the gate is yes or no"; THE ADMINISTRATOR - a setting and a key from the caller are taken;
THE MODES - --service and --listen are refused with a usage line naming --one only; THE DEFAULTS - the state is <root>\\sdsys\\ai, the providers
file beside the program; THE WIRE - the status, badreq and ok lines are the bytes the Python helper wrote (json.dumps with ", " and ": "); THE
CLIENT - every line on standard output, its own --one child reached with no pipe name, gate on|off, Linux Solo's show lines, --handover reading
and REMOVING the file; THE CALL - a round trip to a fake provider over TLS with the administrator's CA file (the key sent only as the bearer header
to that URL), hygiene, one retry on 429, a redirect refused, an answer over the reply limit refused, and the certificate refused without the CA
file and for another host name.
NOT HELD: a caller that is LocalSystem, LocalService or NetworkService (refused by caller_self; unreachable from an unelevated test), a token that
cannot be read, the kernel's spawn (op_ai.c / its Solo transport, not built yet), a real provider with the Windows store.

--selftest  each MUTANT (a copy of gplsrc/sdai in a scratch directory with one rule taken out, BUILT) must turn a row red; the live sources are
hashed before and after and must be unchanged.  --from=N runs the mutants from number N.
"""

import ctypes
import ctypes.wintypes as wt
import glob
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SD64 = os.path.dirname(HERE)
AIDIR = os.path.join(SD64, "gplsrc", "sdai")
PROVIDERS = os.path.join(HERE, "ai-providers")
CONTEXT = os.path.join(HERE, "ai-context")
UCRT_BIN = os.path.join("C:" + os.sep, "msys64", "ucrt64", "bin")
GCC = os.path.join(UCRT_BIN, "gcc.exe")
KEY = "test-key-0123456789"
NO_WINDOW = 0x08000000
USAGE = "usage: sd-ai --one [--state DIR] [--providers FILE]"
passed = failed = 0


def say(s=""):
    print(s, flush=True)


def row(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        say("  [PASS] " + name)
    else:
        failed += 1
        say("  [FAIL] " + name + ("   <- " + str(detail)[:400] if detail else ""))


# ---------------------------------------------------------------------------------------------------- Windows reads of our own (not the helper's code)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.LocalFree.argtypes = [ctypes.c_void_p]
k32.GetCurrentProcess.restype = wt.HANDLE
adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
adv.GetNamedSecurityInfoW.restype = wt.DWORD
adv.GetNamedSecurityInfoW.argtypes = [wt.LPCWSTR, ctypes.c_int, wt.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
adv.GetAce.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]


def sid_text(psid):
    out = wt.LPWSTR()
    if not psid or not adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        return None
    try:
        return out.value
    finally:
        k32.LocalFree(out)


def own_sid():
    tok = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
        return None
    try:
        need = wt.DWORD()
        adv.GetTokenInformation(tok, 1, None, 0, ctypes.byref(need))
        buf = ctypes.create_string_buffer(need.value)
        if not adv.GetTokenInformation(tok, 1, buf, need, ctypes.byref(need)):
            return None
        return sid_text(ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0])
    finally:
        k32.CloseHandle(tok)


def aces_of(dacl):
    aces = []
    count = ctypes.c_ushort.from_address(dacl + 4).value          # ACL: revision, sbz1, size, AceCount
    for i in range(count):
        ace = ctypes.c_void_p()
        if not adv.GetAce(dacl, i, ctypes.byref(ace)):
            break
        typ = ctypes.c_ubyte.from_address(ace.value).value
        mask = wt.DWORD.from_address(ace.value + 4).value
        aces.append((typ, sid_text(ace.value + 8), mask))
    return aces


def file_security(path):
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    if adv.GetNamedSecurityInfoW(path, 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd)) != 0:
        return None, None
    try:
        return sid_text(owner.value), (aces_of(dacl.value) if dacl.value else None)
    finally:
        k32.LocalFree(sd)


# ---------------------------------------------------------------------------------------------------- the build, one request, the client

def build(src, out):
    """The test build of the helper from the C files in src, into out\\usr\\bin with the providers file and the standing text beside it, as
    Solo's tree has them; (exe path or None, compiler output)."""
    bindir = os.path.join(out, "usr", "bin")
    os.makedirs(bindir, exist_ok=True)
    os.makedirs(os.path.join(out, "sdsys"), exist_ok=True)
    shutil.copyfile(PROVIDERS, os.path.join(bindir, "ai-providers"))
    shutil.copyfile(CONTEXT, os.path.join(bindir, "ai-context"))
    exe = os.path.join(bindir, "sd-ai.exe")
    env = dict(os.environ)
    env["PATH"] = UCRT_BIN + os.pathsep + env.get("PATH", "")
    cmd = [GCC, "-std=gnu17", "-Wall", "-Wformat=2", "-O2", "-municode", "-DSDAI_TESTS"] + sorted(glob.glob(os.path.join(src, "*.c"))) + \
          ["-o", exe, "-Wl,-Bstatic", "-lssl", "-lcrypto", "-Wl,-Bdynamic", "-lcrypt32", "-lws2_32", "-ladvapi32"]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
    return (exe if p.returncode == 0 and os.path.isfile(exe) else None), p.stdout + p.stderr


def one(exe, line, state=None, stdin_file=None):
    """One request as the SD session makes it: sd-ai.exe --one, the request line on an anonymous pipe (or, with stdin_file, a file or device
    as standard input); the reply line, bytes, without its newline.  state None: the program's own default."""
    args = [exe, "--one"] + (["--state", state, "--providers", PROVIDERS] if state else [])
    if stdin_file is None:
        p = subprocess.run(args, input=line + b"\n", capture_output=True, timeout=120, creationflags=NO_WINDOW)
    else:
        with open(stdin_file, "rb") as f:
            p = subprocess.run(args, stdin=f, capture_output=True, timeout=120, creationflags=NO_WINDOW)
    return p.stdout.split(b"\n", 1)[0]


def ctl(exe, *words):
    p = subprocess.run([exe] + list(words), capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
    return p.returncode, p.stdout, p.stderr


def jline(b):
    try:
        return json.loads(b.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"unreadable": repr(b[:200])}


def ask_line(prompt):
    return json.dumps({"v": 1, "op": "ask", "system": "", "prompt": prompt, "maxtokens": 100}, separators=(",", ":")).encode("ascii")


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def load_fake():
    spec = importlib.util.spec_from_file_location("sdai_fakemodel", os.path.join(HERE, "test-fakemodel.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------------------------------- the rows

def run(exe, tmp, fake):
    me = own_sid()
    root = os.path.dirname(os.path.dirname(os.path.dirname(exe)))
    state = os.path.join(root, "sdsys", "ai")             # the program's own default: <root>\sdsys\ai
    conf = os.path.join(state, "ai.conf")
    say("  built: %s" % exe)
    say("  the tree: %s (state by default %s)" % (root, state))
    say("  caller: this process's child, SID %s, unelevated test run" % me)
    row("this process's own account is read (the null case: every row below compares against it)", bool(me) and me.startswith("S-1-5-"), me)

    say("\n--- the key: DPAPI in this account's scope, a private file")
    kst = os.path.join(tmp, "keystate")
    for sub in ("", "keys", "state"):
        os.makedirs(os.path.join(kst, sub), exist_ok=True)
    w = ctl(exe, "--test-key", "write", kst, "openai", "sk-test-0123456789abcdef")
    r = ctl(exe, "--test-key", "read", kst, "openai")
    row("the key is written and read back (--test-key: write_key, then read_key)", w[1].strip() == "ok" and r[1].strip() == "key: sk-test-0123456789abcdef", (w, r))
    kp = os.path.join(kst, "keys", "openai")
    blob = open(kp, "rb").read() if os.path.exists(kp) else b""
    row("the key file does not hold the key in clear text (a DPAPI blob)", b"sk-test-0123456789abcdef" not in blob and len(blob) > 40, len(blob))
    owner, aces = file_security(kp)
    allow = {s for (t, s, m) in (aces or []) if t == 0}
    row("the key file's access list allows this account and SYSTEM and nobody else, and it is protected (nothing inherited)", allow == {me, "S-1-5-18"} and owner == me, (owner, aces))
    if os.path.exists(kp):
        shutil.copyfile(kp, os.path.join(kst, "keys", "anthropic"))
        subprocess.run(["icacls", os.path.join(kst, "keys", "anthropic"), "/inheritance:r", "/grant:r", "*%s:F" % me, "*S-1-5-18:F"], capture_output=True)
    r = ctl(exe, "--test-key", "read", kst, "anthropic")
    row("a blob made for one provider is not read as another's (the entropy names the provider): nokey", r[1].startswith("refused: nokey: the key file cannot be opened"), r)
    subprocess.run(["icacls", kp, "/grant", "*S-1-1-0:R"], capture_output=True)
    r = ctl(exe, "--test-key", "read", kst, "openai")
    row("a key file that Everyone may read is refused, not repaired (nokey, not private)", r[1].strip() == "refused: nokey: the key file is not private", r)

    say("\n--- the caller: the helper's own token; standard input must be a pipe")
    raw = one(exe, b'{"v":1,"op":"status"}')
    row("THE DEFAULTS: --one with no --state made its state at <root>\\sdsys\\ai (keys and state inside)",
        os.path.isdir(os.path.join(state, "keys")) and os.path.isdir(os.path.join(state, "state")), os.listdir(root))
    row("THE WIRE: the caller's status, gate absent, begins with the Python helper's bytes and says gate false",
        raw.startswith(b'{"t": "status", "provider": "", "model": "", "gate": false, "key": false, "context": "'), raw[:200])
    r = jline(raw)
    row("the caller is this user's own, so the status carries the connection details (the five providers, the limits) and the shipped standing text",
        sorted((r.get("providers") or {}).keys()) == sorted(["anthropic", "openai", "google", "deepseek", "custom"]) and "limits" in r and r.get("context-from") == "default", r)
    raw = one(exe, ask_line("hello"))
    row("THE GATE: an ask with no gate line is refused in Linux Solo's words, in the Python helper's bytes",
        raw == b'{"t": "err", "code": "nogate", "msg": "the AI is not turned on for this account"}', raw)
    req = os.path.join(tmp, "request-in-a-file")
    with open(req, "wb") as f:
        f.write(b'{"v":1,"op":"set","what":"provider","value":"openai"}\n')
    raw = one(exe, None, stdin_file=req)
    row("standard input that is a FILE (holding a valid setting) is no caller: Linux Solo's refusal, and nothing is written",
        raw == b'{"t": "err", "code": "nogate", "msg": "this connection may not use the AI"}' and not os.path.exists(conf), raw)
    raw = one(exe, None, stdin_file=os.devnull)
    row("standard input that is the NUL device is no caller: the same refusal", raw == b'{"t": "err", "code": "nogate", "msg": "this connection may not use the AI"}', raw)
    raw = one(exe, b"not a request")
    row("THE WIRE: a line that is not a request is badreq, in the Python helper's bytes",
        raw == b'{"t": "err", "code": "badreq", "msg": "not a request this helper understands"}', raw)
    log = read(os.path.join(state, "sd-ai.log"))
    row("each request left one log line in <state>\\sd-ai.log with this caller's SID (None for the file), the status, and no text",
        ("sid=%s provider=- status=nogate in=- out=-" % me) in log and "sid=None provider=- status=nogate" in log and "hello" not in log, log[-400:])

    say("\n--- the gate: exactly gate=yes in ai.conf")
    for word in ("on", "YES", "yes "):
        with open(conf, "w", newline="\n") as f:
            f.write("provider=\ngate=%s\n" % word)
        r = jline(one(exe, b'{"v":1,"op":"status"}'))
        a = jline(one(exe, ask_line("hello")))
        expect = word.strip() == "yes"        # the value is stripped as Python's split stripped it: "yes " is yes
        row("gate=%r reads as %s: status gate %s, an ask %s" % (word, "on" if expect else "off", expect, "past the gate" if expect else "nogate"),
            r.get("gate") is expect and ((a.get("code") != "nogate") if expect else (a.get("code") == "nogate")), (r.get("gate"), a))
    os.remove(conf)
    r = jline(one(exe, b'{"v":1,"op":"set","what":"gate","value":"yes"}'))
    text = read(conf)
    row("set what=gate value=yes: ok, and ai.conf holds the line gate=yes", r == {"t": "ok"} and "\ngate=yes\n" in "\n" + text, (r, text))
    r = jline(one(exe, b'{"v":1,"op":"status"}'))
    row("the status then says gate true", r.get("gate") is True, r.get("gate"))
    r = jline(one(exe, b'{"v":1,"op":"set","what":"gate","value":"maybe"}'))
    row("set what=gate with any other value: badreq 'the gate is yes or no', and gate=yes is still there",
        r == {"t": "err", "code": "badreq", "msg": "the gate is yes or no"} and "gate=yes" in read(conf), (r, read(conf)))
    r = jline(one(exe, b'{"v":1,"op":"set","what":"gate","value":"no"}'))
    text = read(conf)
    row("set what=gate value=no: ok, and the gate line is GONE (off is the absence, as Linux Solo)", r == {"t": "ok"} and "gate" not in text, (r, text))
    r = jline(one(exe, b'{"v":1,"op":"set","what":"martian","value":"x"}'))
    row("an unknown what names gate among the settings (Linux Solo's words)",
        r.get("msg") == "what is one of provider, model, custom, custom-clear, ca, limit, gate, context", r)

    say("\n--- the administrator: any caller (Linux Solo's same-user rule)")
    r = jline(one(exe, b'{"v":1,"op":"set","what":"provider","value":"openai"}'))
    row("a setting from the caller is taken: ok, and ai.conf says provider=openai", r == {"t": "ok"} and "provider=openai" in read(conf), (r, read(conf)))
    r = jline(one(exe, b'{"v":1,"op":"keyset","provider":"openai","key":"sk-kept-0123456789"}'))
    kp2 = os.path.join(state, "keys", "openai")
    row("a key from the caller is taken: ok, and a private key file appears", r == {"t": "ok", "key": "set"} and os.path.isfile(kp2), r)
    r = jline(one(exe, b'{"v":1,"op":"keyclear","provider":"openai"}'))
    row("keyclear from the caller: the key file is gone", r == {"t": "ok", "key": "clear"} and not os.path.exists(kp2), r)
    one(exe, b'{"v":1,"op":"set","what":"provider","value":""}')

    say("\n--- the modes: --one only")
    for mode in (["--service"], ["--listen", r"\\.\pipe\sd-ai-test"]):
        p = subprocess.run([exe] + mode, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        row("%s is refused: exit 2, the usage names --one only, nothing on standard output" % mode[0],
            p.returncode == 2 and p.stderr.strip() == USAGE and p.stdout == "", (p.returncode, p.stdout, p.stderr))

    say("\n--- the client (sd-ai.exe show ...), each command through its own --one child")
    rc, out, err = ctl(exe, "show")
    row("show: exit 0, Linux Solo's first lines on standard output, nothing on standard error",
        rc == 0 and out.startswith("AI provider in use: none (the AI is off)\n  gate: off\n") and err == "", (rc, out, err))
    rc, out, err = ctl(exe, "gate", "on")
    row("gate on: ok, and ai.conf holds gate=yes", rc == 0 and out == "ok\n" and "gate=yes" in read(conf), (rc, out, err, read(conf)))
    rc, out, err = ctl(exe, "show")
    row("show then says gate: on", rc == 0 and "\n  gate: on\n" in out, out[:200])
    rc, out, err = ctl(exe, "gate", "off")
    row("gate off: ok, and the gate line is gone", rc == 0 and out == "ok\n" and "gate" not in read(conf), (rc, out, read(conf)))
    rc, out, err = ctl(exe, "gate", "maybe")
    row("gate with another word: the usage, exit 2", rc == 2 and out.startswith("usage: sd-ai-ctl show [--json] | gate on|off"), (rc, out, err))
    rc, out, err = ctl(exe, "provider", "martian")
    row("provider martian: the helper's refusal printed as error: badreq: ..., exit 1, standard error empty",
        rc == 1 and out.startswith("error: badreq: provider must be one of") and err == "", (rc, out, err))
    hf = os.path.join(tmp, "handover-key")
    with open(hf, "w") as f:
        f.write("sk-handover-0123456789\n")
    rc, out, err = ctl(exe, "key", "openai", "--handover", hf)
    row("key --handover: the key is set (nothing printed, exit 0) and the file is removed", rc == 0 and out == "" and not os.path.exists(hf)
        and os.path.isfile(os.path.join(state, "keys", "openai")), (rc, out, err))
    with open(hf, "w") as f:
        f.write("sk-handover-0123456789\n")
    rc, out, err = ctl(exe, "key", "martian", "--handover", hf)
    row("key --handover with a provider that is none of the five: refused, exit 2, and the file removed all the same", rc == 2 and not os.path.exists(hf), (rc, out, err))
    rc, out, err = ctl(exe, "key-clear", "openai")
    row("key-clear: its line, exit 0", rc == 0 and out == "The key for openai is cleared.\n", (rc, out, err))
    rc, out, err = ctl(exe, "--pipe", r"\\.\pipe\sd-ai", "show")
    row("--pipe is not Solo's: the usage, exit 2", rc == 2 and out.startswith("usage: sd-ai-ctl"), (rc, out, err))
    p = subprocess.run([exe], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
    row("no command: the usage, on standard output, exit 2", p.returncode == 2 and p.stdout.startswith("usage: sd-ai-ctl") and p.stderr == "", (p.returncode, p.stdout, p.stderr))

    say("\n--- the call: a fake provider on 127.0.0.1 over TLS, gate=yes")
    if fake is None:
        row("the fake provider could be loaded (test-fakemodel.py) and the openssl command line found", False, "see above")
        return
    pki = os.path.join(tmp, "pki")
    os.makedirs(pki)
    try:
        fake.make_pki(pki)
    except RuntimeError as e:
        row("the test certificates are made", False, e)
        return
    fm = fake.FakeModel(pki, key=KEY).start()
    fw = fake.FakeModel(pki, key=KEY, cert="wrongname").start()
    st3 = os.path.join(tmp, "state3")
    for sub in ("", "keys", "state"):
        os.makedirs(os.path.join(st3, sub), exist_ok=True)
    ca = os.path.join(pki, "ca.crt").replace("\\", "/")

    def setconf(port, with_ca=True, gate=True):
        lines = ["provider=custom", "custom.name=Fake", "custom.url=https://localhost:%d/v1/chat/completions" % port, "custom.format=openai", "custom.auth=bearer",
                 "custom.version=", "custom.maxparam=max_tokens", "model.custom=fake-large"]
        if with_ca:
            lines.append("ca-file=" + ca)
        if gate:
            lines.append("gate=yes")
        with open(os.path.join(st3, "ai.conf"), "w", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    try:
        setconf(fm.port, gate=False)
        w = ctl(exe, "--test-key", "write", st3, "custom", KEY)
        row("the key is set for the call", w[1].strip() == "ok", w)
        n0 = len(fm.log)
        r = jline(one(exe, ask_line("hello"), state=st3))
        row("with a provider, a model and a key but NO gate line, the ask is nogate and nothing reaches the provider", r.get("code") == "nogate" and len(fm.log) == n0, r)
        setconf(fm.port)
        raw = one(exe, ask_line("hello"), state=st3)
        row("THE WIRE: an answer is exactly the Python helper's bytes: text, tokens, provider, truncated, replaced",
            raw == b'{"t": "ok", "text": "The answer is forty-two.", "in": 11, "out": 7, "provider": "custom", "truncated": false, "replaced": 0}', raw)
        last = fm.log[-1] if fm.log else {}
        sent = jline(last.get("body", b""))
        row("the request went to the provider's path with the key as the bearer header and nowhere else in it, with the model and the person's text",
            last.get("path") == "/v1/chat/completions" and last.get("headers", {}).get("authorization") == "Bearer " + KEY and KEY.encode() not in last.get("body", b"")
            and sent.get("model") == "fake-large" and sent.get("max_tokens") == 100 and sent.get("messages", [{}])[-1] == {"role": "user", "content": "hello"}, last)
        r = jline(one(exe, ask_line("[[ctrl]]"), state=st3))
        t = r.get("text", "")
        row("hygiene: no escape, no BEL, no carriage return, no byte above 126 comes back; curly quotes and the dash are plain; the rest is counted as replaced",
            r.get("t") == "ok" and all(ord(ch) < 127 and (ch in "\n\t" or ord(ch) >= 32) for ch in t) and '"quoted" - dash' in t and r.get("replaced", 0) >= 5, r)
        before = fm.count.get("err429", 0)
        r = jline(one(exe, ask_line("[[err429]]"), state=st3))
        row("ONE retry on 429: the second answer is taken", r.get("t") == "ok" and fm.count.get("err429", 0) - before == 2, (r, fm.count))
        r = jline(one(exe, ask_line("[[redirect]]"), state=st3))
        row("a redirect is refused, never followed", r.get("code") == "refused" and "redirect, which is not followed" in r.get("msg", ""), r)
        r = jline(one(exe, ask_line("[[big]]"), state=st3))
        row("an answer over the reply limit (300,000 characters against 65536) is refused, not cut", r.get("code") == "toobig" and r.get("msg") == "the reply is over 65536 bytes", r)
        r = jline(one(exe, ask_line("[[shape]]"), state=st3))
        row("an answer of a shape the helper does not know is badreply", r.get("code") == "badreply", r)
        setconf(fm.port, with_ca=False)
        n0 = len(fm.log)
        r = jline(one(exe, ask_line("hello"), state=st3))
        row("WITHOUT the administrator's CA file the certificate is refused (the Windows store does not hold the test CA), and no request reached the provider",
            r.get("code") == "net" and r.get("msg") == "the provider's certificate was not accepted" and len(fm.log) == n0, r)
        setconf(fw.port)
        r = jline(one(exe, ask_line("hello"), state=st3))
        row("a certificate the CA signed for ANOTHER host name is refused", r.get("code") == "net" and r.get("msg") == "the provider's certificate was not accepted" and not fw.log, r)
    finally:
        fm.stop()
        fw.stop()


# ---------------------------------------------------------------------------------------------------- the mutants

# (file, what it takes out, old text, new text).  The old text must be in the file exactly once.
MUTANTS = [
    ("sdai_win.c", "private_file accepts any access list", "    if (!EqualSid(s, me) && !EqualSid(s, (PSID)system))\n      ok = 0;\n", ""),
    ("sdai_main.c", "the key is written in clear", "  if (!dpapi((const BYTE*)key, (DWORD)strlen(key), entropy, 1, &blob, &bn))",
     "  blob = (BYTE*)_strdup(key);\n  bn = (DWORD)strlen(key);\n  if (0)"),
    ("sdai_main.c", "the entropy does not name the provider", '{ snprintf(out, n, "sd-ai key %s", name); }', '{ (void)name; snprintf(out, n, "sd-ai key"); }'),
    ("sdai_ctl.c", "the client writes its lines to standard error", "  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);\n  DWORD w;\n  size_t n = strlen(s);",
     "  HANDLE h = GetStdHandle(STD_ERROR_HANDLE);\n  DWORD w;\n  size_t n = strlen(s);"),
    ("sdai_ctl.c", "--handover leaves the file", "  DeleteFileW(w);\n  free(w);\n  return k.p;", "  free(w);\n  return k.p;"),
    ("sdai_https.c", "the certificate is not verified", "SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);", "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);"),
    ("sdai_https.c", "Windows' policy verdict is ignored (15 Nov 26)", "if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps) && ps.dwError == 0)",
     "if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps))"),
    ("sdai_https.c", "the Windows check accepts whatever it found (15 Nov 26)", "  X509_STORE_CTX_set_error(xs, ok ? X509_V_OK : X509_V_ERR_CERT_UNTRUSTED);\n  return ok;",
     "  X509_STORE_CTX_set_error(xs, X509_V_OK);\n  return 1;"),
    ("sdai_https.c", "the host name is not checked", "if (!SSL_set1_host(ssl, host) || !SSL_set_tlsext_host_name(ssl, host)) {", "if (!SSL_set_tlsext_host_name(ssl, host)) {"),
    ("sdai_main.c", "the answer is not cleaned", "    hygiene(text.p, text.n, &clean, &replaced);\n", "    clean = text;\n    replaced = 0;\n"),
    ("sdai_main.c", "no retry", "for (attempt = 1; attempt <= 2; attempt++) {", "for (attempt = 1; attempt <= 1; attempt++) {"),
    ("sdai_main.c", "the status line is written with other separators", '  sb_key(out, &first, "t");\n  sb_jstrz(out, "status");', '  sb_puts(out, "\\"t\\":\\"status\\"");\n  first = 0;'),
    # 16 Nov 26 SD Core Solo: the Solo rules (12 above are Core's, carried; --from=13 runs these alone)
    ("sdai_win.c", "SOLO: standard input that is not a pipe is a caller", "  if (in == NULL || in == INVALID_HANDLE_VALUE || GetFileType(in) != FILE_TYPE_PIPE)",
     "  if (in == NULL || in == INVALID_HANDLE_VALUE)"),
    ("sdai_main.c", "SOLO: the gate is open whatever ai.conf says", 'return c != NULL && strcmp(kv_str(conf, "gate", ""), "yes") == 0;', "return c != NULL;"),
    ("sdai_main.c", "SOLO: the gate is on for any word", 'return c != NULL && strcmp(kv_str(conf, "gate", ""), "yes") == 0;', 'return c != NULL && kv_str(conf, "gate", "")[0] != \'\\0\';'),
    ("sdai_main.c", "SOLO: gate no writes gate=no instead of removing the line", '      kv_del(&nw, "gate");', '      kv_set(&nw, "gate", "no");'),
    ("sdai_main.c", "SOLO: the gate takes any value", '    if (!jeq(v, "yes") && !jeq(v, "no"))\n      return refuse("badreq", "the gate is yes or no");\n', ""),
    ("sdai_main.c", "SOLO: a mode other than --one serves a request", '  if (mode != NULL && wcscmp(mode, L"--one") == 0) {', "  if (1) {"),
]


def digest(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def one_run(src, fake):
    global passed, failed
    passed = failed = 0
    # not mkdtemp: its names may hold _, and the ca-file setting takes letters, digits and . / + - only (the helper's plain_path)
    tmp = os.path.join(tempfile.gettempdir(), "sdai-solo-units-%d-%d" % (os.getpid(), int(time.time() * 1000) % 10 ** 9))
    os.makedirs(tmp)
    try:
        exe, out = build(src, os.path.join(tmp, "root"))
        if exe is None:
            row("the test build of the helper compiles", False, out[-600:])
            return failed
        run(exe, tmp, fake)
    finally:
        subprocess.run(["icacls", tmp, "/reset", "/T", "/Q"], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
    return failed


def selftest(fake, first):
    files = sorted(glob.glob(os.path.join(AIDIR, "*")))
    before = {p: digest(p) for p in files}
    missed = 0
    for n, (name, what, old, new) in enumerate(MUTANTS, 1):
        if n < first:
            continue
        with open(os.path.join(AIDIR, name), encoding="ascii") as f:
            text = f.read()
        if text.count(old) != 1:
            say("MUTANT %d (%s): its text is in %s %d times, not once - the self-test is stale" % (n, what, name, text.count(old)))
            missed += 1
            continue
        d = tempfile.mkdtemp(prefix="sdai_mutant_")
        try:
            for p in files:
                shutil.copyfile(p, os.path.join(d, os.path.basename(p)))
            with open(os.path.join(d, name), "w", encoding="ascii", newline="") as f:
                f.write(text.replace(old, new))
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                red = one_run(d, fake)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        say("MUTANT %d (%s): %s" % (n, what, "caught (%d red)" % red if red else "MISSED"))
        missed += 0 if red else 1
    after = {p: digest(p) for p in files}
    if before != after:
        say("THE LIVE SOURCES CHANGED DURING THE SELF-TEST")
        return 1
    say("selftest: %d mutants, %d missed; the live sources are unchanged (SHA-256)" % (len(MUTANTS), missed))
    return 1 if missed else 0


def main():
    if os.name != "nt":
        say("test-aihelper-units: Windows only")
        return 2
    if not os.path.isfile(GCC) or not glob.glob(os.path.join(UCRT_BIN, "..", "lib", "libssl.a")):
        say("test-aihelper-units: no UCRT64 gcc or static OpenSSL at %s - it builds the helper the way the Makefile does" % UCRT_BIN)
        return 2
    for p in (AIDIR, PROVIDERS, CONTEXT):
        if not os.path.exists(p):
            say("test-aihelper-units: %s is missing" % p)
            return 2
    try:
        fake = load_fake()
        if fake.openssl_path() is None:
            say("  (no openssl command line: the call rows will fail)")
    except (OSError, ImportError, SyntaxError) as e:
        say("  test-fakemodel.py could not be loaded: %s" % e)
        fake = None
    if "--selftest" in sys.argv:
        first = 1
        for a in sys.argv:
            if a.startswith("--from="):
                first = int(a[len("--from="):])
        return selftest(fake, first)
    say("test-aihelper-units: building %s with %s (-DSDAI_TESTS), running it unelevated" % (AIDIR, GCC))
    bad = one_run(AIDIR, fake)
    say("\n%d passed, %d failed" % (passed, bad))
    if passed == 0:
        say("NOTHING WAS MEASURED")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
