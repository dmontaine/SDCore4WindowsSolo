#!/usr/bin/env python3
"""solo-mcp.py - the MCP launcher of SD Core Solo for Windows (S.211): a Model Context Protocol server on standard input and output.

An AI agent's MCP client starts this program as a child process (it is printed by `solo-mcp.py --config`).  It speaks JSON-RPC 2.0, one
message to a line, and does NOT decide anything itself: every call is one one-shot `sd-solo mcp.call <id>` on the account's KEPT password,
and the gate (SET.MCP), the checks of every word, the work and the audit line are in the SD BASIC program mcp.call (gpl.bp/mcp_call).  A
launcher that is replaced by someone else's meets the same gate.  It holds, reads and passes NO password.

  py -3 <SD Core Solo folder>\\solo-mcp.py            serve (an MCP client does this)
  py -3 <SD Core Solo folder>\\solo-mcp.py --config   print the snippet for an MCP client's configuration and stop
  py -3 <SD Core Solo folder>\\solo-mcp.py --version  print the version and stop

TOOLS.  Read-only (readOnlyHint): sd_files, sd_describe, sd_read, sd_query.  With SET.MCP WRITE ON also sd_run (destructiveHint).
LIMITS.  One call at a time, 30 seconds, a message of at most 1 MB, an answer of at most 64 KB; control characters other than newline and
tab are turned into spaces here as well as in SD.  THE PERSON'S YES is the MCP client's: a stdio server cannot reach the person.

TEST HOOKS (the test suites use them; nothing else should): SOLO_MCP_SD names the sd-solo program, SOLO_MCP_ACCOUNT_DIR the account's
directory (where the request files go, in $mcp), SOLO_MCP_TIMEOUT the seconds a call may take.

Exit 0 when the client closed the input; 2 when it could not start.
START-HISTORY:
11 Nov 26 Windows port - from Linux Solo 531d829 (S.211; SOLO 57, the owner, 11 Nov 26: "Yes, carry it").  It lives in the SD Core Solo folder beside
          the other helpers, so HOME is its own folder: sd-solo.exe is usr\\bin\\sd-solo.exe and the account is user_accounts\\sduser.  Each one-shot runs with
          no console window (an MCP client may have none to share), on the environment a Windows program needs (Linux passes eight Unix names), and its
          output is read with CRLF taken as a line end.  The protocol, the tools and every check are Linux's unchanged.  The $mcp folder takes the account
          folder's access list, so there is no chmod; stdin and stdout are UTF-8 with \\n line ends, so a client reads one JSON message to a line.
11 Nov 26 dm  New (S.211).
"""
import json
import os
import re
import secrets
import subprocess
import sys

VERSION = "1.0"
SERVER_NAME = "sd-core-solo"
SUPPORTED = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_MESSAGE = 1024 * 1024
MAX_ANSWER = 64 * 1024
HOME = os.path.dirname(os.path.abspath(__file__))
SD = os.environ.get("SOLO_MCP_SD") or os.path.join(HOME, "usr", "bin", "sd-solo.exe")
ACCOUNT_DIR = os.environ.get("SOLO_MCP_ACCOUNT_DIR") or os.path.join(HOME, "user_accounts", "sduser")
TIMEOUT = float(os.environ.get("SOLO_MCP_TIMEOUT") or "30")
CTL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
NAME = re.compile(r"^[A-Za-z0-9._$-]{1,60}$")
# What a one-shot sd-solo is given of the environment: what a Windows program needs to start and to reach the user's profile (the kept password is
# protected for this user), and nothing the MCP client may have added.
PASS_ENV = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN",
            "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "HOMEDRIVE", "HOMEPATH", "COMPUTERNAME", "SD_CONFIG")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

agent = "unknown"
write_on = False

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
TOOLS = [
    {"name": "sd_files", "description": "List the files of the SD account.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": READ_ONLY},
    {"name": "sd_describe", "description": "List the dictionary items (the fields) of a file of the SD account.",
     "inputSchema": {"type": "object", "properties": {"file": {"type": "string"}}, "required": ["file"], "additionalProperties": False},
     "annotations": READ_ONLY},
    {"name": "sd_read", "description": "Read one record of a file of the SD account: one field to a line, value marks shown as ].",
     "inputSchema": {"type": "object", "properties": {"file": {"type": "string"}, "id": {"type": "string"}}, "required": ["file", "id"],
                     "additionalProperties": False}, "annotations": READ_ONLY},
    {"name": "sd_query", "description": "List records of a file: the fields to show (names of the file's dictionary), conditions (field, operator = # < > <= >=, "
                                       "a plain-text value), one sort field and a limit of at most 200 rows.",
     "inputSchema": {"type": "object", "properties": {
         "file": {"type": "string"}, "fields": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20},
         "where": {"type": "array", "items": {"type": "object", "properties": {
             "field": {"type": "string"}, "op": {"type": "string", "enum": ["=", "#", "<", ">", "<=", ">="]}, "value": {"type": "string"}},
             "required": ["field", "op", "value"], "additionalProperties": False}},
         "sort": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}},
         "required": ["file", "fields"], "additionalProperties": False}, "annotations": READ_ONLY},
]
RUN_TOOL = {"name": "sd_run", "description": "Run ONE sentence in the SD account as the person could type it (the account's own switches apply). "
                                             "Needs the administrator to have run set.mcp write on.",
            "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"], "additionalProperties": False},
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False}}


def clean(text):
    return CTL.sub(" ", text)


def send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    send(out)


def run_sd(sentence_words):
    """One one-shot sd-solo command.  Returns (status, text) from the lines between MCP-BEGIN and MCP-END, or ('error', why)."""
    try:
        p = subprocess.run([SD] + sentence_words, capture_output=True, text=True, errors="replace", timeout=TIMEOUT, stdin=subprocess.DEVNULL,
                           env={k: v for k, v in os.environ.items() if k.upper() in PASS_ENV}, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "error", "the call did not finish in %d seconds" % int(TIMEOUT)
    except OSError as e:
        return "error", "cannot start sd-solo (%s)" % e.strerror
    body = p.stdout.replace("\r\n", "\n").replace("\r", "\n")
    m = re.search(r"^MCP-BEGIN (\S+) (ok|refused|error)[ \t]*\n(.*?)^MCP-END \1[ \t]*$", body, re.S | re.M)
    if not m:
        return "error", "SD gave no answer (is a password kept for one-shot commands? see the documentation): " + clean(body.strip())[:300]
    return m.group(2), m.group(3).rstrip("\n")


def check_door():
    """Ask SD whether the door is open; sets write_on.  Returns (ok, text)."""
    global write_on
    st, text = run_sd(["mcp.call", "status", agent])
    if st != "ok":
        return False, text
    write_on = "write=on" in text
    return True, text


def request_file(lines):
    d = os.path.join(ACCOUNT_DIR, "$mcp")
    os.makedirs(d, exist_ok=True)
    rid = "r" + secrets.token_hex(8)
    path = os.path.join(d, rid)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="latin-1", errors="replace", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return rid, path


def call_tool(name, args):
    """Returns (text, is_error)."""
    if not isinstance(args, dict):
        return "the arguments must be an object", True
    lines = [""] * 8
    conds = []

    def text_arg(key, required=True):
        v = args.get(key, "")
        if not isinstance(v, str) or (required and v == ""):
            raise ValueError("%s must be a non-empty string" % key)
        if re.search(r"[\x00-\x1f\x7f]", v):
            raise ValueError("%s has a control character" % key)
        return v

    try:
        if name == "sd_files":
            lines[0] = "files"
        elif name == "sd_describe":
            lines[0], lines[2] = "describe", text_arg("file")
        elif name == "sd_read":
            lines[0], lines[2], lines[3] = "read", text_arg("file"), text_arg("id")
        elif name == "sd_query":
            lines[0], lines[2] = "query", text_arg("file")
            fields = args.get("fields")
            if not isinstance(fields, list) or not fields or len(fields) > 20 or not all(isinstance(x, str) and NAME.match(x) for x in fields):
                raise ValueError("fields must be 1 to 20 names")
            lines[4] = " ".join(fields)
            if args.get("sort"):
                lines[5] = text_arg("sort")
            if "limit" in args:
                lim = args["limit"]
                if not isinstance(lim, int) or isinstance(lim, bool) or lim < 1 or lim > 200:
                    raise ValueError("limit must be 1 to 200")
                lines[6] = str(lim)
            for c in args.get("where", []) or []:
                if not isinstance(c, dict) or set(c) != {"field", "op", "value"} or not all(isinstance(c[k], str) for k in c):
                    raise ValueError("a condition is {field, op, value}")
                if re.search(r"[\x00-\x1f\x7f]", c["field"] + c["op"] + c["value"]):
                    raise ValueError("a condition has a control character")
                if c["op"] not in ("=", "#", "<", ">", "<=", ">="):
                    raise ValueError("an operator is one of = # < > <= >=")
                conds.append("%s\t%s\t%s" % (c["field"], c["op"], c["value"]))
        elif name == "sd_run":
            if not write_on:
                return "The write tool is closed: the administrator has not turned it on (set.mcp write on)", True
            lines[0], lines[7] = "run", text_arg("command")
        else:
            return "no such tool: " + name[:40], True
    except ValueError as e:
        return str(e), True
    lines[1] = agent
    try:
        rid, path = request_file(lines + conds)
    except OSError as e:
        return "cannot write the request (%s)" % e.strerror, True
    try:
        st, text = run_sd(["mcp.call", rid])
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    text = clean(text)
    if len(text.encode("utf-8", "replace")) > MAX_ANSWER:
        text = text.encode("utf-8", "replace")[:MAX_ANSWER].decode("utf-8", "ignore") + "\n[output cut]"
    return text, st != "ok"


def handle(msg):
    global agent
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if method is None:
        return                                           # a response from the client: nothing to do
    if mid is None:                                      # a notification
        return
    if method == "initialize":
        info = params.get("clientInfo") or {}
        raw = str(info.get("name", "")).lower() if isinstance(info, dict) else ""
        name = re.sub(r"[^a-z0-9._-]+", "-", raw)[:32].strip("-")
        agent = name or "unknown"
        ok, text = check_door()
        if not ok:
            reply(mid, error={"code": -32000, "message": text or "the MCP door is closed"})
            sys.exit(0)
        want = params.get("protocolVersion")
        reply(mid, {"protocolVersion": want if want in SUPPORTED else SUPPORTED[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": VERSION},
                    "instructions": "Tools for the SD Core Solo for Windows database of the person who started this server. The administrator controls the door "
                                    "(set.mcp). Every call is written to SD's audit trail with your name."})
    elif method == "ping":
        reply(mid, {})
    elif method == "tools/list":
        reply(mid, {"tools": TOOLS + ([RUN_TOOL] if write_on else [])})
    elif method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str):
            reply(mid, error={"code": -32602, "message": "a tool name is needed"})
            return
        text, is_err = call_tool(name, params.get("arguments") or {})
        reply(mid, {"content": [{"type": "text", "text": text}], "isError": is_err})
    else:
        reply(mid, error={"code": -32601, "message": "method not found"})


def serve():
    for raw in sys.stdin:
        if len(raw) > MAX_MESSAGE:
            reply(None, error={"code": -32600, "message": "message too large"})
            continue
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            reply(None, error={"code": -32700, "message": "parse error"})
            continue
        if not isinstance(msg, dict):
            reply(None, error={"code": -32600, "message": "invalid request"})
            continue
        handle(msg)
    return 0


def main():
    # One JSON message to a line, in UTF-8: Windows' default text streams would write CRLF in the console's code page.
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", newline="\n") if stream is sys.stdout else stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if "--version" in sys.argv[1:]:
        print("solo-mcp %s" % VERSION)
        return 0
    if "--config" in sys.argv[1:]:
        me = os.path.abspath(__file__)
        print(json.dumps({"mcpServers": {"sd-solo": {"command": sys.executable or "py", "args": [me]}}}, indent=2))
        return 0
    if not os.path.isfile(SD):
        sys.stderr.write("solo-mcp: cannot find the SD program %s\n" % SD)
        return 2
    return serve()


if __name__ == "__main__":
    sys.exit(main())
