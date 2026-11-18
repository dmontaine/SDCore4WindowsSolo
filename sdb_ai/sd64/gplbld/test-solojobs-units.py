#!/usr/bin/env python3
"""test-solojobs-units.py - Solo's scheduled jobs (S.247): SET.JOB, RUN.JOB, SET.JOBS.ACCESS, the TOOL.JOBS page, login's run.job route, the doors
helper's job requests and the installer's parts, as invariants.

    python C:\\Users\\Don\\Projects\\SDCore4WindowsSolo\\sdb_ai\\sd64\\gplbld\\test-solojobs-units.py [--selftest]

16 Nov 2026, Windows port of Linux Solo's guard (2d3db81, 72c2457): the checks that are portable are Linux's, word for word where the code is;
the systemd checks are replaced by their Windows equivalents (the owner's decisions of 16 Nov 2026): the task's action is FIXED to sd-solo.exe
run.job <name> and its principal is S4U, the doors helper reads only checked words from a request and never a command, and login's Windows
identity route admits run.job and nothing else.
FREE: no install, no elevation, no SD, and NEVER Task Scheduler (it reads files).  Exit 0 every check passed, 1 a check failed, 2 it could not run.

WHAT IT HOLDS:
  J1  the switch is field 23 (ACC$JOBS), and only 'yes' is on; SET.JOBS.ACCESS asks for the administrator first and writes that field alone
  J2  SET.JOB: ADD, CHANGE and RUN ask the switch before anything is changed; DELETE and the list do not need it
  J3  ADD and CHANGE ask for the account password (typed at a terminal, or from the page's hand-over) BEFORE the definition is written; a one-shot
      or a session with no terminal is refused (15941); one try
  J4  the name rule and the five schedules are SD Core's, in SET.JOB, in the helper's request check and in the Task Scheduler trigger (SD Core's
      sd-jobs.ps1 Get-JobSchedule)
  J5  a command is printable ASCII, at most 500 characters, not RUN.JOB or SET.JOB; it is field 3 of the definition and never in a request or a task
  J6  the task: principal the Solo user by SID, LogonType S4U, the least privilege; ONE action, the fixed sd-solo.exe "run.job <name>"; no missed run
      made up, no run doubled; the folder SYSTEM and Administrators only; a task of the name deleted first, and read back after
  J7  the hand-over file is read and REMOVED before anything is decided; a first line other than add or change is refused; a file or folder that
      is not this Windows user's alone is refused
  J8  RUN.JOB runs only as the one-shot "run.job <name>", asks the switch at every run, audits the start and the end, and EXECUTEs the definition's
      command with the return code zeroed first
  J9  no SET.JOB RESTORE: the installer's elevated step gives a reload's definitions their tasks (Restore-JobTasks on Install and Upgrade) and
      takes every job task away FIRST on Remove
  J10 the page runs SET.JOB and nothing else, through $tk_run after a box answered Run; N and C have a masked password field; D asks for the name
  J11 the uninstaller's Keep keeps $jobs, and the installer's reload copies it back
  J12 the messages the programs cite exist, and the VOC records name the programs
  J13 the doors helper's job request: kind=job, op set|delete|run, a checked name, a checked schedule (set), the proof over the ACCOUNT's StoredKey
      for set; the keys SET.JOB writes are the ones the helper reads; the proof's message is built the same way on both sides; only checked words
      reach solo-machine.ps1's command line
  J14 login's Windows identity route: only a one-shot that is exactly "run.job <name>", only when $stored is there and DPAPI would not open it, only
      when $cred is this Windows user's own (SD_FILE_PRIVATE); it never sets the administrator or global flags; it sits after the kept password
      and before the terminal refusal
It cannot say Task Scheduler runs a job, that SYSTEM may register an S4U task, or that a signed-out run signs in: that is a real Solo install.
--selftest breaks each invariant the way an edit plausibly would and requires the check aimed at it to notice.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SD64 = os.path.normpath(os.path.join(HERE, ".."))
SDSYS = os.path.join(SD64, "sdsys")
GPL = os.path.join(SDSYS, "gpl.bp")
FILES = {
    "job": os.path.join(GPL, "solojob"),
    "run": os.path.join(GPL, "runjob"),
    "acc": os.path.join(GPL, "setjobsacc"),
    "page": os.path.join(GPL, "tool_solojobs"),
    "login": os.path.join(GPL, "login"),
    "keys": os.path.join(SDSYS, "syscom", "keys.h"),
    "doors": os.path.join(HERE, "solo-doors.ps1"),
    "machine": os.path.join(HERE, "solo-machine.ps1"),
    "setup": os.path.join(HERE, "solo-setup.ps1"),
    "iss": os.path.join(HERE, "sd-solo.iss"),
}
VOCS = {"set.job": "$solojob", "run.job": "$runjob", "set.jobs.access": "$setjobsacc", "tool.jobs": "$tool_solojobs"}


def load():
    raw = {}
    for k, p in FILES.items():
        try:
            with open(p, encoding="latin-1", newline="") as f:
                raw[k] = f.read().replace("\r\n", "\n")
        except OSError:
            raw[k] = None
    for v in VOCS:
        for d in ("newvoc", "voc_template"):
            p = os.path.join(SDSYS, d, v)
            try:
                with open(p, encoding="latin-1") as f:
                    raw[d + "/" + v] = f.read()
            except OSError:
                raw[d + "/" + v] = None
    return raw


def code(src):
    """BASIC with comment lines and ;* tails removed."""
    out = []
    for ln in (src or "").split("\n"):
        if re.match(r"^\s*\*", ln):
            continue
        out.append(re.sub(r"\s*;\*.*$", "", ln))
    return "\n".join(out)


def ps_code(src):
    """PowerShell with whole-line # comments removed."""
    return "\n".join(ln for ln in (src or "").split("\n") if not re.match(r"^\s*#", ln))


def block(text, label):
    """A BASIC routine: from its label to the next label (an inner return does not end it)."""
    m = re.search(r"^" + re.escape(label) + r":\s*$(.*?)(?=^[a-z][a-z0-9.]*:\s*$|\Z)", text, re.M | re.S)
    return m.group(1) if m else ""


def ps_func(text, name):
    """A PowerShell function, from 'function Name' to the first line that is a lone closing brace."""
    m = re.search(r"^function " + re.escape(name) + r"\b.*?^\}\s*$", text, re.M | re.S)
    return m.group(0) if m else ""


def between(text, begin, end):
    i = text.find(begin)
    j = text.find(end, i + 1) if i >= 0 else -1
    return text[i:j] if 0 <= i < j else ""


def checks(raw):
    rows = []

    def ck(i, what, ok, detail=""):
        rows.append((i, what, bool(ok), detail))

    missing = [k for k, v in raw.items() if v is None and not k.startswith("newvoc/") and not k.startswith("voc_template/")]
    if missing:
        ck("J0", "every file this check reads exists", False, ", ".join(missing))
        return rows
    jb, rn, ac, pg, lg = code(raw["job"]), code(raw["run"]), code(raw["acc"]), code(raw["page"]), code(raw["login"])
    dr, mc = ps_code(raw["doors"]), ps_code(raw["machine"])

    # J1
    ck("J1", "the switch is field 23 (ACC$JOBS) and only 'yes' is on; SET.JOBS.ACCESS asks for the administrator before it opens the register, writes ACC$JOBS alone, under a lock",
       re.search(r"\$define ACC\$JOBS\s+23\b", raw["keys"]) and ac.find("if not(kernel(K$ADMINISTRATOR, -1)) then") >= 0
       and ac.find("if not(kernel(K$ADMINISTRATOR, -1)) then") < ac.find("openpath")
       and "if jb.want then acc.new<ACC$JOBS> = 'yes' else acc.new<ACC$JOBS> = 'no'" in ac and len(re.findall(r"acc\.new<ACC\$[A-Z.]+>\s*=", ac)) == 2
       and "readu acc.rec from acc.f, acc.name else" in ac
       and "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true" in jb and "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true" in rn)

    # J2
    main = jb.split("* ------------------------------------------------------------------------------------------------- the actions")[0]
    if main == jb:
        main = raw["job"].split("* ------------------------------------------------------------------------------------------------- the actions")[0]
        main = code(main)
    i_sw = main.find("if action # 'delete' then\n      gosub switch.on")
    i_open = main.find("gosub open.jobs\n   if not(ok)")
    ck("J2", "ADD, CHANGE and RUN ask the switch before the definitions are opened, DELETE does not, the list says it",
       i_sw > 0 and i_open > i_sw and "stop sysmsg(15948)" in main[i_sw:i_open] and "gosub switch.on" in block(jb, "list.jobs"))

    # J3
    ds = block(jb, "do.set")
    ap = block(jb, "ask.password")
    ck("J3", "ADD and CHANGE ask for the password before the definition is written; it is the account's (CRED_VERIFY of sduser), one try, the page's from the hand-over, refused with no terminal or in a one-shot",
       0 < ds.find("gosub ask.password") < ds.find("write new.rec to jobs.f, jname")
       and "if kernel(K$TTY, 0) = '' or trim(system(1026)) # '' then" in ap and "pw.text = ho.pw" in ap
       and "call !CRED_VERIFY(acc.name, pw.text, pw.match)" in ap and "acc.name = 'sduser'" in jb and "for pw." not in ap)

    # J4
    so = block(jb, "sched.ok")
    gt = ps_func(mc, "Get-JobTrigger")
    ck("J4", "the name rule and the five schedules: SET.JOB's checks, the helper's request pattern and the Task Scheduler trigger (SD Core's Get-JobSchedule) agree",
       "if convert('abcdefghijklmnopqrstuvwxyz0123456789-', '', jname) # '' then return" in block(jb, "name.ok") and "if len(jname) < 1 or len(jname) > 32 then return" in block(jb, "name.ok")
       and "(s2 = '5' or s2 = '10' or s2 = '15' or s2 = '20' or s2 = '30')" in so and "dd >= 1 and dd <= 28" in so and "if hh > 23 or mm > 59 then return" in block(jb, "time.ok")
       and "$shapes = '^(every (5|10|15|20|30) minutes|hourly|daily ' + $hm + '|weekly (mon|tue|wed|thu|fri|sat|sun) ' + $hm + '|monthly ([1-9]|1[0-9]|2[0-8]) ' + $hm + ')$'" in dr
       and "$hm = '([01][0-9]|2[0-3]):[0-5][0-9]'" in dr and "$jname -cnotmatch '^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$'" in dr
       and "($w[1] -cnotmatch '^(5|10|15|20|30)$')" in gt and "<Interval>PT$($w[1])M</Interval>" in gt and "<Interval>PT1H</Interval>" in gt
       and "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>" in gt and "($w[1] -cnotmatch '^([1-9]|1[0-9]|2[0-8])$')" in gt
       and "return ($t -cmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$')" in mc and "return ($n -cmatch '^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$')" in mc)

    # J5
    co = block(jb, "cmd.ok")
    hr = block(jb, "helper.req")
    tx = ps_func(mc, "Get-JobTaskXml")
    ck("J5", "a command is printable ASCII (32-126), at most 500, not run.job or set.job; it is field 3 of the definition, RUN.JOB reads it there, and it is in neither the request nor the task",
       "if cc < 32 or cc > 126 then return" in co and "$define MAX.CMD    500" in raw["job"] and "if cw = 'run.job' or cw = 'set.job' then return" in co
       and re.search(r"new\.rec = sched : @fm : [^\n]* : @fm : jcmd : @fm", ds) is not None and "jcmd" not in hr and "rec<3>" in rn
       and tx != "" and not re.search(r"\$\w*(cmd|command)\b", tx, re.I) and re.search(r"function Get-JobTaskXml\(\[string\]\$n, \[string\]\$sched, \[string\]\$trigger, \[string\]\$userSid\)", tx))

    # J6
    rj = ps_func(mc, "Register-JobTask")
    ck("J6", "the task: the user by SID, S4U, least privilege; one action, the fixed sd-solo.exe 'run.job NAME'; no missed run made up, no run doubled; the folder SYSTEM and Administrators only; deleted first, read back after",
       "<LogonType>S4U</LogonType>" in tx and "<RunLevel>LeastPrivilege</RunLevel>" in tx and "<UserId>$(& $e $userSid)</UserId>" in tx
       and tx.count("<Exec>") == 1 and "<Arguments>run.job $n</Arguments>" in tx and "<Command>$(& $e $sdexe)</Command>" in tx
       and "<StartWhenAvailable>false</StartWhenAvailable>" in tx and "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>" in tx
       and "$sdexe = Join-Path $AppDir 'usr\\bin\\sd-solo.exe'" in mc
       and "$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'" in mc
       and 0 < rj.find("$f.DeleteTask($JobPrefix + $n, 0)") < rj.find("Register-ScheduledTask") < rj.find("[string]$t.Principal.LogonType -ne 'S4U'")
       and "$sid = Get-ForUserSid" in rj and "(A;;GR;;;' + $sid + ')" in rj)

    # J7
    rh = block(jb, "read.handover")
    i_rm = rh.rfind("deleteseq ho.file else null")
    ck("J7", "the hand-over file is read, then removed, before its action is judged; only add or change is taken; one that is not this Windows user's alone is refused and removed",
       "ho.file = @sdsys : @ds : '$jobsho' : @ds : 'req'" in rh and 0 < rh.find("readseq") < i_rm < rh.find("ho.action = downcase(trim(ho.lines<1>))")
       and "if ho.action # 'add' and ho.action # 'change' then return" in rh and "if SDEXT(ho.file : @FM : 'FILE', @TRUE, SD_FILE_PRIVATE) # '1' then" in rh
       and "if SDEXT(hdir : @FM : 'DIR', @TRUE, SD_FILE_PRIVATE) # '1' then" in block(pg, "hand.over"))

    # J8
    i_one = rn.find("if not(ok.call) then")
    i_swr = rn.find("if not(sw.on) then")
    i_ex = rn.find("execute jcmd")
    ck("J8", "RUN.JOB: only as the one-shot 'run.job NAME' (system(1026)), then the name rule, then the switch, then the definition; the start and the end are audited around the EXECUTE",
       0 < i_one < i_swr < rn.find("if jcmd = '' then") < i_ex and "one = trim(system(1026))" in rn
       and rn.find("'run.job start name='") < i_ex < rn.find("'run.job end name='") and rn.count("execute ") == 1
       and re.search(r"@system\.return\.code = 0\s*\n\s*execute jcmd", rn) is not None)

    # J9
    i_rm_all = mc.find("try { Remove-AllJobTasks }")
    i_rm_task = mc.find("Note '--- startup task'\n        Remove-SoloTask")
    i_doors = mc.find("if ($Action -eq 'Remove') { Remove-DoorsTask } else { Register-DoorsTask }")
    i_rest = mc.find("        Restore-JobTasks")
    ck("J9", "no SET.JOB RESTORE: the installer's elevated step gives $jobs its tasks on Install and Upgrade, after the doors helper, and removes every job task first on Remove",
       "action = 'restore'" not in jb and "'restore'" not in jb
       and 0 < i_rm_all < i_rm_task and 0 < i_doors < i_rest and "if ($Action -ne 'Remove') {\n        Note ''\n        Note '--- scheduled jobs (a task for each definition in $jobs)'\n        Restore-JobTasks" in mc)

    # J10
    ck("J10", "the page runs set.job alone, through $tk_run after a confirm box answered Run; the password field is masked (kind 1); D asks for the name typed",
       "allow = 'set.job'" in pg and pg.count("allow = ") == 1 and pg.count("call $tk_run(") == 2 and "call $tk_run(allow, 'set.job', jout, jst, jrerr)" in pg
       and "spec<-1> = 'pw' : @vm : 'Account password' : @vm : 34 : @vm : 64 : @vm : 1" in pg
       and "call $tk_confirm(sent, el, fname, res, cmsg)" in block(pg, "job.delete")
       and block(pg, "job.confirm").find("call $tk_confirm(sent, el, '', res, cmsg)") < block(pg, "job.confirm").find("gosub hand.over")
       and not re.search(r"^\s*(?:execute|perform|chain|os\.execute|write[uv]?|delete[uv]?)\b", pg, re.M))

    # J11
    keep = raw["iss"]
    ck("J11", "the uninstaller's Keep keeps $jobs in sdsys, and the reload copies it back (solo-setup.ps1 RELOAD-KEPT)",
       re.search(r"RemoveFolderContents\(Root \+ '\\sdsys', '\|[^']*\|\$jobs\|", keep) is not None
       and "@{ Rel = 'sdsys\\$jobs';" in between(raw["setup"], "# RELOAD-KEPT-BEGIN", "foreach ($k in $keptItems)"))

    # J12
    cited = set(re.findall(r"sysmsg\((\d+)", jb + rn + ac + pg))
    gone = sorted(n for n in cited if not os.path.exists(os.path.join(SDSYS, "messages", n)))
    vocbad = [d + "/" + v for v, prog in VOCS.items() for d in ("newvoc", "voc_template")
              if raw.get(d + "/" + v) is None or raw[d + "/" + v].split("\n")[1:3] != ["CA", prog]]
    ck("J12", "every message the four programs cite exists (%d), and each verb's VOC record in newvoc and voc_template is CA of its program" % len(cited), cited and not gone and not vocbad, repr((gone, vocbad)))

    # J13
    wrote = set(re.findall(r"q : '([a-z]+)=", hr))
    read = set(re.findall(r"req\['([a-z]+)'\]", dr)) - {"door", "mode", "cred"}
    m_bb = re.search(r"^\s*authmsg\s*=\s*('sd-solo-jobs[^']*'(?:\s*:\s*(?:[\w.]+|'[^']*'))*)", hr, re.M)
    m_ps = re.search(r"\$authmsg\s*=\s*('sd-solo-jobs[^']*'(?:\s*\+\s*(?:\$\w+|'[^']*'))*)", dr)
    names = {"jname": "name", "h.sched": "sched", "nonce": "nonce", "now": "time"}
    psn = {"jname": "name", "sched": "sched", "nonce": "nonce", "time": "time"}
    bb = [t if t.startswith("'") else names.get(t, "?" + t) for t in re.findall(r"'[^']*'|[\w.]+", m_bb.group(1))] if m_bb else None
    ps = [t if t.startswith("'") else psn.get(t[1:], "?" + t) for t in re.findall(r"'[^']*'|\$\w+", m_ps.group(1))] if m_ps else None
    jcall = re.search(r"\$jargs = @\('-Action', 'Job', '-JobOp', \$op, '-JobName', \$jname\)\s*\n\s*if \(\$op -eq 'set'\) \{ \$jargs \+= @\('-JobSchedule', \$sched\) \}", dr)
    ck("J13", "the job request: SET.JOB writes the keys the helper reads; op, name and schedule are checked words; the set proof is over the account's StoredKey, its message the same on both sides; only checked words reach solo-machine.ps1",
       wrote == {"version", "kind", "op", "name", "sched", "proof", "nonce", "time"} and wrote == read and bb is not None and bb == ps
       and "if (@('set', 'delete', 'run') -cnotcontains $op)" in dr and "$cred = 'sduser'" in dr
       and "h.stored = cred.rec<CRED$STOREDKEY>" in ap and "read cred.rec from cred.f, acc.name else" in ap
       and jcall is not None and "@jargs -ForUser $ForUser -AppDir $AppDir -Result $res" in dr
       and "if ($op -eq 'set' -and $sched -cnotmatch $shapes)" in dr and "if ($have -cne $JobSchedule)" in mc,
       repr((sorted(wrote), sorted(read), bb, ps)))

    # J14
    rjb = between(lg, "RUN-JOB-IDENTITY-BEGIN", "RUN-JOB-IDENTITY-END")
    rjb_raw = between(raw["login"], "RUN-JOB-IDENTITY-BEGIN", "RUN-JOB-IDENTITY-END")
    rjb = code(rjb_raw)
    i_stored = lg.find("if pw.via # '' then\n         void kernel(K$AUDIT, 'login password account=' : initial.account : ' via=stored')")
    i_id = lg.find("if not(pw.interactive) and pw.dpapi.fail then")
    i_tty = lg.find("if not(pw.interactive) and pw.on.tty then")
    ck("J14", "login admits by Windows identity only 'run.job NAME' exactly, only when the kept copy is there and DPAPI would not open it, only when $cred is this Windows user's own; no admin flag; after $stored, before the terminal refusal",
       rjb != "" and "if dcount(rj.cmd, ' ') = 2 and downcase(field(rj.cmd, ' ', 1)) = 'run.job' then" in rjb
       # 18 Nov 26 (audit round 3, P-4430): the one-shot's command is read with system(1026); login's batch.command is gone
       and "convert('abcdefghijklmnopqrstuvwxyz0123456789-', '', rj.name) = ''" in rjb and "rj.cmd = trim(system(1026))" in rjb
       and "if SDEXT(@sdsys : @ds : '$cred' : @FM : 'DIR', @TRUE, SD_FILE_PRIVATE) = '1' then" in rjb
       and "K$ADMINISTRATOR" not in rjb and "K$GLOBAL.SESSION" not in rjb and rjb.count("pw.ok = @true") == 1
       and "if pw.text = '' then pw.dpapi.fail = @true" in lg and lg.count("pw.dpapi.fail = @true") == 1
       and 0 < i_stored < i_id < i_tty, repr((i_stored, i_id, i_tty)))
    return rows


def sub(key, old, new):
    def f(raw):
        if raw.get(key) is None or old not in raw[key]:
            return None
        r = dict(raw)
        r[key] = raw[key].replace(old, new, 1)
        return r
    return f


MUTANTS = [
    ("the switch is another field", "J1", sub("keys", "$define ACC$JOBS         23", "$define ACC$JOBS         22")),
    ("set.jobs.access skips the administrator", "J1", sub("acc", "   if not(kernel(K$ADMINISTRATOR, -1)) then\n      stop sysmsg(2001)", "   if 0 then\n      stop sysmsg(2001)")),
    ("run.job takes any switch value", "J1", sub("run", "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true", "sw.on = @true")),
    ("add does not ask the switch", "J2", sub("job", "   if action # 'delete' then\n      gosub switch.on", "   if action = 'none' then\n      gosub switch.on")),
    ("the definition is written before the password", "J3", sub("job", "   gosub ask.password\n   if not(pw.ok) then", "   write new.rec to jobs.f, jname on error null\n   gosub ask.password\n   if not(pw.ok) then")),
    ("a one-shot may set a job", "J3", sub("job", "if kernel(K$TTY, 0) = '' or trim(system(1026)) # '' then", "if kernel(K$TTY, 0) = '' then")),
    ("every 7 minutes is taken by set.job", "J4", sub("job", "(s2 = '5' or s2 = '10'", "(s2 = '5' or s2 = '7' or s2 = '10'")),
    ("monthly takes day 31 in the trigger", "J4", sub("machine", "($w[1] -cnotmatch '^([1-9]|1[0-9]|2[0-8])$')", "($w[1] -cnotmatch '^([1-9]|[12][0-9]|3[01])$')")),
    ("the helper takes any schedule", "J4", sub("doors", "|monthly ([1-9]|1[0-9]|2[0-8]) ' + $hm + ')$'", "|monthly ([1-9]|1[0-9]|2[0-8]) ' + $hm + '|.*)$'")),
    ("a command may hold a control character", "J5", sub("job", "if cc < 32 or cc > 126 then return", "if cc < 9 then return")),
    ("the command goes into the request", "J5", sub("job", "'name=' : jname : q", "'name=' : jname : q : ', ' : q : 'cmd=' : jcmd : q")),
    ("the task runs another program", "J6", sub("machine", "<Arguments>run.job $n</Arguments>", "<Arguments>$n</Arguments>")),
    ("the task stores a password", "J6", sub("machine", "<LogonType>S4U</LogonType>", "<LogonType>Password</LogonType>")),
    ("a missed run is made up", "J6", sub("machine", "<StartWhenAvailable>false</StartWhenAvailable>", "<StartWhenAvailable>true</StartWhenAvailable>")),
    ("the task folder lets users in", "J6", sub("machine", "$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'", "$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;AU)'")),
    ("the hand-over file is judged before it is removed", "J7", sub("job", "   ho.action = downcase(trim(ho.lines<1>))\n   if ho.action # 'add' and ho.action # 'change' then return", "   ho.action = downcase(trim(ho.lines<1>))\n   if ho.action # 'add' and ho.action # 'change' then return\n   deleteseq ho.file else null")),
    ("run.job runs from any session", "J8", sub("run", "   if not(ok.call) then", "   if @false then")),
    ("run.job leaves its own -1 as a command's status", "J8", sub("run", "   @system.return.code = 0\n   execute jcmd", "   execute jcmd")),
    ("the uninstaller leaves the job tasks", "J9", sub("machine", "        try { Remove-AllJobTasks } catch", "        try { $null = 0 } catch")),
    ("a reload does not give the tasks back", "J9", sub("machine", "        Note '--- scheduled jobs (a task for each definition in $jobs)'\n        Restore-JobTasks", "        Note '--- scheduled jobs (a task for each definition in $jobs)'")),
    ("the page may run another command", "J10", sub("page", "allow = 'set.job'", "allow = 'set.job sh'")),
    ("the password is shown as typed", "J10", sub("page", "@vm : 'Account password' : @vm : 34 : @vm : 64 : @vm : 1", "@vm : 'Account password' : @vm : 34 : @vm : 64 : @vm : ''")),
    ("Keep drops $jobs", "J11", sub("iss", "voc_removed.saved|$jobs|'", "voc_removed.saved|'")),
    ("the reload does not copy $jobs", "J11", sub("setup", "@{ Rel = 'sdsys\\$jobs';", "@{ Rel = 'sdsys\\$jobz';")),
    ("a cited message is missing", "J12", sub("job", "stop sysmsg(15945)", "stop sysmsg(15929)")),
    ("the helper's job proof is built in another order", "J13", sub("doors", "'sd-solo-jobs|v1|set|' + $jname + '|' + $sched + '|' + $nonce + '|' + $time", "'sd-solo-jobs|v1|set|' + $jname + '|' + $nonce + '|' + $sched + '|' + $time")),
    ("the job proof is checked against the administrator", "J13", sub("doors", "$cred = 'sduser'", "$cred = '$admin'")),
    ("the helper takes any operation", "J13", sub("doors", "if (@('set', 'delete', 'run') -cnotcontains $op)", "if (@('set', 'delete', 'run', 'exec') -cnotcontains $op)")),
    ("the identity route takes any one-shot", "J14", sub("login", "if dcount(rj.cmd, ' ') = 2 and downcase(field(rj.cmd, ' ', 1)) = 'run.job' then", "if dcount(rj.cmd, ' ') >= 1 then")),
    ("the identity route skips the owner check", "J14", sub("login", "if SDEXT(@sdsys : @ds : '$cred' : @FM : 'DIR', @TRUE, SD_FILE_PRIVATE) = '1' then", "if @true then")),
    ("the identity route makes an administrator", "J14", sub("login", "            pw.via = 'windows-user'\n", "            pw.via = 'windows-user'\n            void kernel(K$ADMINISTRATOR, 1)\n")),
    ("the identity route fires when $stored opened", "J14", sub("login", "if pw.text = '' then pw.dpapi.fail = @true", "pw.dpapi.fail = @true")),
]


def report(rows):
    bad = 0
    for i, what, ok, detail in rows:
        print("  [%s] %s %s%s" % ("PASS" if ok else "FAIL", i, what, "" if ok or not detail else "   <- " + str(detail)[:400]))
        bad += 0 if ok else 1
    return bad


def main(argv):
    raw = load()
    print("test-solojobs-units: " + ", ".join(sorted(os.path.relpath(p, SD64) for p in FILES.values())))
    if "--selftest" in argv:
        base = checks(raw)
        if any(not ok for _, _, ok, _ in base):
            print("REFUSING - the unmutated source already fails: " + ", ".join(i for i, _, ok, _ in base if not ok))
            return 1
        missed = 0
        for name, tag, f in MUTANTS:
            m = f(raw)
            if m is None:
                print("  [MISSED] %s: the mutation changed nothing" % name)
                missed += 1
                continue
            failed = [i for i, _, ok, _ in checks(m) if not ok]
            if tag in failed:
                print("  [pass] %s: caught by %s" % (name, tag))
            else:
                print("  [MISSED] %s: %s did not fail (failed: %s)" % (name, tag, failed))
                missed += 1
        print("self-test: %d mutants, %d not caught" % (len(MUTANTS), missed))
        return 1 if missed else 0
    rows = checks(raw)
    if not rows:
        print("test-solojobs-units: VOID - no check ran")
        return 2
    bad = report(rows)
    print("test-solojobs-units: %d checks, %d failed" % (len(rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
