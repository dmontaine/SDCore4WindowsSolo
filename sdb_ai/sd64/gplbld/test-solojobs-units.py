#!/usr/bin/env python3
"""test-solojobs-units.py - Solo's scheduled jobs (S.247; SOLO 74): SET.JOB, RUN.JOB, RUN.JOBS.DUE, SET.JOBS.ACCESS, the TOOL.JOBS page, login's
run.job and job-clock routes, the job clock task and the installer's parts, as invariants.

    python C:\\Users\\Don\\Projects\\SDCore4WindowsSolo\\sdb_ai\\sd64\\gplbld\\test-solojobs-units.py [--selftest]

16 Nov 2026, Windows port of Linux Solo's guard (2d3db81, 72c2457): the checks that are portable are Linux's, word for word where the code is.
20 Nov 2026, SOLO 74 (sit8): a job no longer has a Task Scheduler task of its own.  The VM showed that the doors helper (SYSTEM) may not register
the user's S4U task ("Access is denied"), so ONE task, the job clock, registered by the installer's elevated step as the user, runs
sd-solo.exe run.jobs.due every minute, and RUN.JOBS.DUE runs what is due (the owner's "option 1").  J4, J5, J6, J9, J13 and J14 follow it; J15 is new.
FREE: no install, no elevation, no SD, and NEVER Task Scheduler (it reads files).  Exit 0 every check passed, 1 a check failed, 2 it could not run.

WHAT IT HOLDS:
  J1  the switch is field 23 (ACC$JOBS), and only 'yes' is on; SET.JOBS.ACCESS asks for the administrator first and writes that field alone
  J2  SET.JOB: ADD, CHANGE and RUN ask the switch before anything is changed; DELETE and the list do not need it
  J3  ADD and CHANGE ask for the account password (typed at a terminal, or from the page's hand-over) BEFORE the definition is written; a one-shot
      or a session with no terminal is refused (15941); one try
  J4  the name rule and the five schedules are SD Core's, in SET.JOB and in !SOLO_JOB_TIMES, which the clock and the list read
  J5  a command is printable ASCII, at most 500 characters, not RUN.JOB, SET.JOB or RUN.JOBS.DUE; it is field 3 of the definition and never in a task
  J6  the job clock: principal the Solo user by SID, LogonType S4U, the least privilege; ONE action, the fixed sd-solo.exe "run.jobs.due"; every
      minute; no missed run made up; overlapping ticks allowed; the folder SYSTEM and Administrators only; the user may read and start it, not
      change it; deleted first, read back after
  J7  the hand-over file is read and REMOVED before anything is decided; a first line other than add or change is refused; a file or folder that
      is not this Windows user's alone is refused
  J8  RUN.JOB runs only as the one-shot "run.job <name>" or from the clock's one-shot, asks the switch at every run, audits the start and the end,
      and EXECUTEs the definition's command with the return code zeroed first
  J9  the installer's elevated step registers the clock on Install and Upgrade (an older install's per-job tasks removed first), after the doors
      helper, and takes every job task away FIRST on Remove; SET.JOB writes only the definition (no task, no helper)
  J10 the page runs SET.JOB and nothing else, through $tk_run after a box answered Run; N and C have a masked password field; D asks for the name
  J11 the uninstaller's Keep keeps $jobs, and the installer's reload copies it back
  J12 the messages the programs cite exist, and the VOC records name the programs
  J13 the doors helper takes no job request (SYSTEM cannot make a job's task), and solo-machine.ps1 has no -Action Job
  J14 login: the Windows identity route admits only "run.job <name>" or exactly "run.jobs.due", only when $stored is there and DPAPI would not open
      it, only when $cred is this Windows user's own; never an administrator; after $stored, before the terminal refusal.  With jobs off the
      clock's one-shot leaves before any password, quietly
  J15 RUN.JOBS.DUE: only as the clock's one-shot; nothing with jobs off; a job is due when its schedule's latest time is after its last run and
      its setting and not more than five minutes ago, or when SET.JOB RUN marked it; every due job is stamped under its lock BEFORE any runs;
      each runs through RUN.JOB, never its command directly
It cannot say Task Scheduler runs the clock, that a signed-out tick signs in, or that the times are right on a real clock: that is a real Solo install.
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
    "due": os.path.join(GPL, "runjobsdue"),
    "times": os.path.join(GPL, "solo_job_times"),
    "acc": os.path.join(GPL, "setjobsacc"),
    "page": os.path.join(GPL, "tool_solojobs"),
    "login": os.path.join(GPL, "login"),
    "keys": os.path.join(SDSYS, "syscom", "keys.h"),
    "doors": os.path.join(HERE, "solo-doors.ps1"),
    "machine": os.path.join(HERE, "solo-machine.ps1"),
    "setup": os.path.join(HERE, "solo-setup.ps1"),
    "iss": os.path.join(HERE, "sd-solo.iss"),
}
VOCS = {"set.job": "$solojob", "run.job": "$runjob", "run.jobs.due": "$runjobsdue", "set.jobs.access": "$setjobsacc", "tool.jobs": "$tool_solojobs"}


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


_carry_cache = {}


def carry_behaviour(block):
    """20 Nov 26 (RELEASE_1.1 367): run solo-setup.ps1's Invoke-RegisterCarry, lifted from its REGISTER-CARRY block, on scratch records.
    'ok', or what was wrong.  Cached by the block's text, so a mutant elsewhere costs no PowerShell."""
    if block in _carry_cache:
        return _carry_cache[block]
    import shutil, subprocess, tempfile
    fn = between(block, "function Invoke-RegisterCarry", "        $carried = ")
    if not fn:
        _carry_cache[block] = "the function was not found in the block"
        return _carry_cache[block]
    ps = shutil.which("powershell") or shutil.which("powershell.exe")
    if ps is None:
        _carry_cache[block] = "no PowerShell to run it"
        return _carry_cache[block]
    d = tempfile.mkdtemp(prefix="solocarry-")
    try:
        def rec(fields, end=True):
            return ("\r\n".join(fields) + ("\r\n" if end else "")).encode("latin-1")
        new = ["@USRDIR/sduser", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "no"]
        kept = list(new); kept[6] = "yes"; kept[22] = "YES"; kept[16] = "ai pdf"; kept[14] = "no"; kept[0] = "C:/old/path"
        want = list(new); want[6] = "yes"; want[22] = "yes"; want[16] = "ai pdf"
        new2 = list(new); new2[22] = "yes"; new2[16] = "x"           # this install's own tile list stays
        kept2 = list(new); kept2[22] = "no"; kept2[16] = "ai pdf"
        files = {"k1": rec(kept), "n1": rec(new), "k2": rec(kept2), "n2": rec(new2, end=False), "n3": rec(new)}
        for n, b in files.items():
            with open(os.path.join(d, n), "wb") as f:
                f.write(b)
        drv = os.path.join(d, "drive.ps1")
        with open(drv, "w", encoding="ascii", newline="\r\n") as f:
            f.write(fn.replace("\r\n", "\n") + "\n")
            f.write("$d = $args[0]\n")
            f.write("'R1=' + (Invoke-RegisterCarry (Join-Path $d 'k1') (Join-Path $d 'n1'))\n")
            f.write("'R2=' + (Invoke-RegisterCarry (Join-Path $d 'k2') (Join-Path $d 'n2'))\n")
            f.write("'R3=' + (Invoke-RegisterCarry (Join-Path $d 'absent') (Join-Path $d 'n3'))\n")
        p = subprocess.run([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", drv, d], capture_output=True, text=True, timeout=60)
        out = dict(l.split("=", 1) for l in p.stdout.splitlines() if l[:3] in ("R1=", "R2=", "R3="))
        got = {n: open(os.path.join(d, n), "rb").read() for n in ("n1", "n2", "n3")}
        bad = []
        if out.get("R1") != "3 switch(es) carried from the kept record": bad.append("R1 said %r" % out.get("R1"))
        if got["n1"] != rec(want): bad.append("n1 is %r" % got["n1"])
        if out.get("R2") != "0 switch(es) carried from the kept record": bad.append("R2 said %r" % out.get("R2"))
        if got["n2"] != rec(new2, end=False): bad.append("n2 changed: %r" % got["n2"])
        if out.get("R3") != "none was saved": bad.append("R3 said %r" % out.get("R3"))
        if got["n3"] != rec(new): bad.append("n3 changed")
        if not out: bad.append("no output; stderr: " + p.stderr.strip()[:300])
        _carry_cache[block] = "ok" if not bad else "; ".join(bad)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return _carry_cache[block]


def checks(raw):
    rows = []

    def ck(i, what, ok, detail=""):
        rows.append((i, what, bool(ok), detail))

    missing = [k for k, v in raw.items() if v is None and not k.startswith("newvoc/") and not k.startswith("voc_template/")]
    if missing:
        ck("J0", "every file this check reads exists", False, ", ".join(missing))
        return rows
    jb, rn, ac, pg, lg = code(raw["job"]), code(raw["run"]), code(raw["acc"]), code(raw["page"]), code(raw["login"])
    du, tm = code(raw["due"]), code(raw["times"])
    dr, mc = ps_code(raw["doors"]), ps_code(raw["machine"])

    # J1
    ck("J1", "the switch is field 23 (ACC$JOBS) and only 'yes' is on; SET.JOBS.ACCESS asks for the administrator before it opens the register, writes ACC$JOBS alone, under a lock",
       re.search(r"\$define ACC\$JOBS\s+23\b", raw["keys"]) and ac.find("if not(kernel(K$ADMINISTRATOR, -1)) then") >= 0
       and ac.find("if not(kernel(K$ADMINISTRATOR, -1)) then") < ac.find("openpath")
       and "if jb.want then acc.new<ACC$JOBS> = 'yes' else acc.new<ACC$JOBS> = 'no'" in ac and len(re.findall(r"acc\.new<ACC\$[A-Z.]+>\s*=", ac)) == 2
       and "readu acc.rec from acc.f, acc.name else" in ac
       and "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true" in jb and "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true" in rn
       and "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true" in du)

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
    ck("J4", "the name rule and the five schedules: SET.JOB's checks and !SOLO_JOB_TIMES (which the clock and the list read) take the same five",
       "if convert('abcdefghijklmnopqrstuvwxyz0123456789-', '', jname) # '' then return" in block(jb, "name.ok") and "if len(jname) < 1 or len(jname) > 32 then return" in block(jb, "name.ok")
       and "(s2 = '5' or s2 = '10' or s2 = '15' or s2 = '20' or s2 = '30')" in so and "dd >= 1 and dd <= 28" in so and "if hh > 23 or mm > 59 then return" in block(jb, "time.ok")
       and "case w1 = 'every' and nw = 3 and w3 = 'minutes' and (w2 = '5' or w2 = '10' or w2 = '15' or w2 = '20' or w2 = '30')" in tm
       and "case w1 = 'hourly' and nw = 1" in tm and "case w1 = 'daily' and nw = 2 and at >= 0" in tm
       and "wpos = index(' sun mon tue wed thu fri sat ', ' ' : w2 : ' ', 1)" in tm and "if w2[1, 1] = '0' or w2 < 1 or w2 > 28 then return" in tm
       and "if tm[1, 2] <= 23 and tm[4, 2] <= 59 then at = tm[1, 2] * 3600 + tm[4, 2] * 60" in tm
       and "return ($n -cmatch '^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$')" in mc
       and "if convert('abcdefghijklmnopqrstuvwxyz0123456789-', '', jname) # '' then return" in block(du, "name.ok"))

    # J5
    co = block(jb, "cmd.ok")
    cx = ps_func(mc, "Get-JobClockXml")
    ck("J5", "a command is printable ASCII (32-126), at most 500, not run.job, set.job or run.jobs.due; it is field 3 of the definition, RUN.JOB reads it there, and no task holds it",
       "if cc < 32 or cc > 126 then return" in co and "$define MAX.CMD    500" in raw["job"]
       and "if cw = 'run.job' or cw = 'set.job' or cw = 'run.jobs.due' then return" in co
       and re.search(r"new\.rec = sched : @fm : [^\n]* : @fm : jcmd : @fm", ds) is not None and "rec<3>" in rn
       and cx != "" and not re.search(r"\$\w*(cmd|command)\b", cx, re.I) and "function Get-JobClockXml([string]$userSid)" in cx)

    # J6
    rc = ps_func(mc, "Register-JobClock")
    ck("J6", "the job clock: the user by SID, S4U, least privilege; one action, the fixed sd-solo.exe 'run.jobs.due'; every minute; no missed tick made up; ticks may overlap; the folder SYSTEM and Administrators only; the user may read and start it, not change it; deleted first, read back after",
       "<LogonType>S4U</LogonType>" in cx and "<RunLevel>LeastPrivilege</RunLevel>" in cx and "<UserId>$(& $e $userSid)</UserId>" in cx
       and cx.count("<Exec>") == 1 and "<Arguments>run.jobs.due</Arguments>" in cx and "<Command>$(& $e $sdexe)</Command>" in cx
       and "<Interval>PT1M</Interval>" in cx and cx.count("<Interval>") == 1
       and "<StartWhenAvailable>false</StartWhenAvailable>" in cx and "<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>" in cx
       and "$sdexe = Join-Path $AppDir 'usr\\bin\\sd-solo.exe'" in mc and "$JobClockName = 'sd-solo-jobs-clock'" in mc
       and "$define CLOCK.TASK 'sd-solo-jobs-clock'" in raw["job"]
       and "$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'" in mc
       and 0 < rc.find("$f.DeleteTask($JobClockName, 0)") < rc.find("Register-ScheduledTask") < rc.find("[string]$t.Principal.LogonType -ne 'S4U'")
       and "$a.Arguments -cne 'run.jobs.due'" in rc
       and "$sid = Get-ForUserSid" in rc and "(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;' + $sid + ')" in rc
       # 20 Nov 26 (sit8 follow-up 1): the folder adds read for the user alone, not inherited, after the task is set, and is read back
       and "$folderSddl = $JobFolderSddl + '(A;;GR;;;' + $sid + ')'" in rc
       and rc.find("(A;;GRGX;;;' + $sid + ')") < rc.find("$f.SetSecurityDescriptor($folderSddl, 0)") < rc.find("$f.GetSecurityDescriptor(4) -notmatch"))

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
    ck("J8", "RUN.JOB: only as the one-shot 'run.job NAME' or from the clock's one-shot 'run.jobs.due' (system(1026)), then the name rule, then the switch, then the definition; the start and the end are audited around the EXECUTE",
       0 < i_one < i_swr < rn.find("if jcmd = '' then") < i_ex and "one = trim(system(1026))" in rn
       and "if dcount(trim(@sentence), ' ') = 2 and downcase(one) = 'run.jobs.due' then ok.call = @true" in rn
       and rn.find("'run.job start name='") < i_ex < rn.find("'run.job end name='") and rn.count("execute ") == 1
       and re.search(r"@system\.return\.code = 0\s*\n\s*execute jcmd", rn) is not None)

    # J9
    i_rm_all = mc.find("try { Remove-AllJobTasks }")
    i_rm_task = mc.find("Note '--- startup task'\n        Remove-SoloTask")
    i_doors = mc.find("if ($Action -eq 'Remove') { Remove-DoorsTask } else { Register-DoorsTask }")
    i_clock = mc.find("        Set-JobClock")
    sc = ps_func(mc, "Set-JobClock")
    ra = ps_func(mc, "Remove-AllJobTasks")
    ck("J9", "the installer's elevated step registers the clock on Install and Upgrade, after the doors helper, an older install's per-job tasks removed first; Remove takes the clock and every job task away first; SET.JOB writes only the definition",
       "action = 'restore'" not in jb and "'restore'" not in jb
       and 0 < i_rm_all < i_rm_task and 0 < i_doors < i_clock
       and "if ($Action -ne 'Remove') {\n        Note ''\n        Note '--- scheduled jobs (the job clock)'\n        Set-JobClock" in mc
       and 0 < sc.find("Remove-JobTask") < sc.find("Register-JobClock") and "if ($t.TaskName -eq $JobClockName) { $null = Remove-JobClock }" in ra
       and "helper.req" not in jb and "doors.request" not in jb and "Register-ScheduledTask" not in jb)

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

    # J11c, J11d - 20 Nov 26, RELEASE_1.1 367 (Linux Solo b5219e1, S.278; the owner: Keep restores what the administrator turned on)
    st = raw["setup"] or ""
    rcb = between(st, "# REGISTER-CARRY-BEGIN", "# REGISTER-CARRY-END")
    ck("J11c", "Keep keeps sdsys accounts; the reload carries only the switch fields (7-12, 15, 18-24; 17 when blank), only to yes, after RELOAD-KEPT and before sd.conf, never copying the record; the finish page says it",
       re.search(r"RemoveFolderContents\(Root \+ '\\sdsys', '\|[^']*\|accounts\|", keep) is not None
       and "@(7, 8, 9, 10, 11, 12, 15, 18, 19, 20, 21, 22, 23, 24)" in rcb and "$f[$j - 1] = 'yes'" in rcb and "'no'" not in rcb
       and "accounts" not in between(st, "# RELOAD-KEPT-BEGIN", "# RELOAD-KEPT-END")
       and 0 < st.find("# RELOAD-KEPT-END") < st.find("# REGISTER-CARRY-BEGIN") < st.find("$keptConf = Join-Path $ReloadFrom 'sd.conf'")
       and "Note ('ACCOUNT SWITCHES : ' + $carried)" in rcb
       and "SwitchesNote := ReportLineAfter(ReportPath, 'ACCOUNT SWITCHES : ');" in keep and "'Account switches: ' + SwitchesNote" in keep)
    res = carry_behaviour(rcb)
    ck("J11d", "the carry, run in PowerShell on scratch CR LF records: kept yes turns on 7, 23 and takes 17; a kept no leaves a yes, and a set tile list stays; nothing else moves; CR LF and the last line end kept; no kept record = none was saved",
       res == "ok", res)

    # J12
    cited = set(re.findall(r"sysmsg\((\d+)", jb + rn + du + ac + pg))
    gone = sorted(n for n in cited if not os.path.exists(os.path.join(SDSYS, "messages", n)))
    vocbad = [d + "/" + v for v, prog in VOCS.items() for d in ("newvoc", "voc_template")
              if raw.get(d + "/" + v) is None or raw[d + "/" + v].split("\n")[1:3] != ["CA", prog]]
    ck("J12", "every message the five programs cite exists (%d), and each verb's VOC record in newvoc and voc_template is CA of its program" % len(cited), cited and not gone and not vocbad, repr((gone, vocbad)))

    # J13
    ck("J13", "the doors helper takes no job request (SYSTEM cannot register the user's S4U task), and solo-machine.ps1 has no -Action Job",
       "if ($kind -cne 'door') { Finish $nonce $false" in dr and "sd-solo-jobs" not in dr and "'-Action', 'Job'" not in dr
       and "[ValidateSet('Install', 'Upgrade', 'Remove', 'Doors')] [string]$Action" in mc and "$JobOp" not in mc
       and "if ($Action -eq 'Job')" not in mc)

    # J14
    rjb_raw = between(raw["login"], "RUN-JOB-IDENTITY-BEGIN", "RUN-JOB-IDENTITY-END")
    rjb = code(rjb_raw)
    i_stored = lg.find("if pw.via # '' then\n         void kernel(K$AUDIT, 'login password account=' : initial.account : ' via=stored')")
    i_id = lg.find("if not(pw.interactive) and pw.dpapi.fail then")
    i_tty = lg.find("if not(pw.interactive) and pw.on.tty then")
    i_q = lg.find("if downcase(trim(system(1026))) = 'run.jobs.due' then")
    i_qgo = lg.find("if not(jc.on) then goto abort.login")
    i_req = lg.find("gosub require.password")
    ck("J14", "login admits by Windows identity only 'run.job NAME' or exactly 'run.jobs.due', only when the kept copy is there and DPAPI would not open it, only when $cred is this Windows user's own; no admin flag; after $stored, before the terminal refusal; with jobs off the clock's one-shot leaves before any password",
       rjb != "" and "if dcount(rj.cmd, ' ') = 2 and downcase(field(rj.cmd, ' ', 1)) = 'run.job' then" in rjb
       and "if downcase(rj.cmd) = 'run.jobs.due' then" in rjb
       and "convert('abcdefghijklmnopqrstuvwxyz0123456789-', '', rj.name) = ''" in rjb and "rj.cmd = trim(system(1026))" in rjb
       and "if SDEXT(@sdsys : @ds : '$cred' : @FM : 'DIR', @TRUE, SD_FILE_PRIVATE) = '1' then" in rjb
       and "K$ADMINISTRATOR" not in rjb and "K$GLOBAL.SESSION" not in rjb and rjb.count("pw.ok = @true") == 1
       and "if pw.text = '' then pw.dpapi.fail = @true" in lg and lg.count("pw.dpapi.fail = @true") == 1
       and "if pw.verb = 'run.jobs.due' and dcount(pw.one, ' ') = 1 then pw.job = @true" in lg
       and 0 < i_q < i_qgo < i_req and "if upcase(trim(jc.rec<ACC$JOBS>)) = 'YES' then jc.on = @true" in lg
       and 0 < i_stored < i_id < i_tty, repr((i_stored, i_id, i_tty, i_q, i_qgo, i_req)))

    # J15
    i_one2 = du.find("if one # 'run.jobs.due' or dcount(trim(@sentence), ' ') # 1 then")
    i_off = du.find("if not(sw.on) then stop")
    i_stamp = du.find("rec<6> = now")
    i_write = du.find("write rec to jobs.f, jname on error")
    i_run = du.find("execute 'run.job ' : due<i>")
    ck("J15", "RUN.JOBS.DUE: only as the clock's one-shot; nothing with jobs off; due = the schedule's latest time after the last run and the setting and within five minutes, or marked 'now'; every due job stamped under its lock before any runs; each through RUN.JOB",
       0 < i_one2 < i_off < i_stamp < i_write < i_run and "one = downcase(trim(system(1026)))" in du
       and "readu rec from jobs.f, jname locked" in du and "$define LATE.LIMIT 300" in raw["due"]
       and "if prev > since and prev > now - LATE.LIMIT then is.due = @true" in du and "if downcase(trim(rec<7>)) = 'now' then" in du
       and "call !SOLO_JOB_TIMES(rec<1>, now, prev, next)" in du and "rec<7> = ''" in du
       and du.count("execute ") == 1 and "rec<3>" not in du and "close jobs.f" in du[:i_run],
       repr((i_one2, i_off, i_stamp, i_write, i_run)))
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
    ("the clock takes any switch value", "J1", sub("due", "if upcase(trim(sw.rec<ACC$JOBS>)) = 'YES' then sw.on = @true", "sw.on = @true")),
    ("add does not ask the switch", "J2", sub("job", "   if action # 'delete' then\n      gosub switch.on", "   if action = 'none' then\n      gosub switch.on")),
    ("the definition is written before the password", "J3", sub("job", "   gosub ask.password\n   if not(pw.ok) then", "   write new.rec to jobs.f, jname on error null\n   gosub ask.password\n   if not(pw.ok) then")),
    ("a one-shot may set a job", "J3", sub("job", "if kernel(K$TTY, 0) = '' or trim(system(1026)) # '' then", "if kernel(K$TTY, 0) = '' then")),
    ("every 7 minutes is taken by set.job", "J4", sub("job", "(s2 = '5' or s2 = '10'", "(s2 = '5' or s2 = '7' or s2 = '10'")),
    ("the clock's times take day 31", "J4", sub("times", "if w2[1, 1] = '0' or w2 < 1 or w2 > 28 then return", "if w2[1, 1] = '0' or w2 < 1 or w2 > 31 then return")),
    ("a command may hold a control character", "J5", sub("job", "if cc < 32 or cc > 126 then return", "if cc < 9 then return")),
    ("a job may run the clock itself", "J5", sub("job", "if cw = 'run.job' or cw = 'set.job' or cw = 'run.jobs.due' then return", "if cw = 'run.job' or cw = 'set.job' then return")),
    ("the clock runs another program", "J6", sub("machine", "<Arguments>run.jobs.due</Arguments>", "<Arguments>run.job x</Arguments>")),
    ("the clock stores a password", "J6", sub("machine", "<LogonType>S4U</LogonType>", "<LogonType>Password</LogonType>")),
    ("a missed tick is made up", "J6", sub("machine", "<StartWhenAvailable>false</StartWhenAvailable>", "<StartWhenAvailable>true</StartWhenAvailable>")),
    ("a long job stops the next tick", "J6", sub("machine", "<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>", "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>")),
    # the doors task has the same grant earlier in the file, so the mutation is anchored on the clock's own comment line above it
    ("the user may change the clock", "J6", sub("machine", "The user cannot change it.\n    $task.SetSecurityDescriptor(('D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;' + $sid + ')'), 0)",
                                                 "The user cannot change it.\n    $task.SetSecurityDescriptor(('D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;' + $sid + ')'), 0)")),
    ("the task folder lets users in", "J6", sub("machine", "$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'", "$JobFolderSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;AU)'")),
    ("the user may write the task folder", "J6", sub("machine", "$folderSddl = $JobFolderSddl + '(A;;GR;;;' + $sid + ')'", "$folderSddl = $JobFolderSddl + '(A;OICI;FA;;;' + $sid + ')'")),
    ("the user cannot open the task folder", "J6", sub("machine", "    $f.SetSecurityDescriptor($folderSddl, 0)\n", "")),
    ("the hand-over file is judged before it is removed", "J7", sub("job", "   ho.action = downcase(trim(ho.lines<1>))\n   if ho.action # 'add' and ho.action # 'change' then return", "   ho.action = downcase(trim(ho.lines<1>))\n   if ho.action # 'add' and ho.action # 'change' then return\n   deleteseq ho.file else null")),
    ("run.job runs from any session", "J8", sub("run", "   if not(ok.call) then", "   if @false then")),
    ("run.job leaves its own -1 as a command's status", "J8", sub("run", "   @system.return.code = 0\n   execute jcmd", "   execute jcmd")),
    ("the uninstaller leaves the job tasks", "J9", sub("machine", "        try { Remove-AllJobTasks } catch", "        try { $null = 0 } catch")),
    ("an install does not register the clock", "J9", sub("machine", "        Note '--- scheduled jobs (the job clock)'\n        Set-JobClock", "        Note '--- scheduled jobs (the job clock)'")),
    ("an upgrade keeps the old per-job tasks", "J9", sub("machine", "    foreach ($t in $old) { $null = Remove-JobTask $t.TaskName.Substring($JobPrefix.Length) }\n", "")),
    ("the page may run another command", "J10", sub("page", "allow = 'set.job'", "allow = 'set.job sh'")),
    ("the password is shown as typed", "J10", sub("page", "@vm : 'Account password' : @vm : 34 : @vm : 64 : @vm : 1", "@vm : 'Account password' : @vm : 34 : @vm : 64 : @vm : ''")),
    ("Keep drops $jobs", "J11", sub("iss", "voc_removed.saved|$jobs|accounts|solo.policy|pdf|'", "voc_removed.saved|accounts|solo.policy|pdf|'")),
    ("the reload does not copy $jobs", "J11", sub("setup", "@{ Rel = 'sdsys\\$jobs';", "@{ Rel = 'sdsys\\$jobz';")),
    # 20 Nov 26 - RELEASE_1.1 367
    ("Keep drops the register", "J11c", sub("iss", "|$jobs|accounts|solo.policy|pdf|'", "|$jobs|solo.policy|pdf|'")),
    ("the carry takes a field that is not a switch", "J11c", sub("setup", "@(7, 8, 9, 10, 11, 12, 15, 18, 19, 20, 21, 22, 23, 24)", "@(3, 7, 8, 9, 10, 11, 12, 15, 18, 19, 20, 21, 22, 23, 24)")),
    ("the finish page drops the line", "J11c", sub("iss", "'Account switches: ' + SwitchesNote", "''")),
    ("the carry copies a kept no over a yes", "J11d", sub("setup", "if ($kv -ieq 'yes') {", "if ($kv -ne '') {")),
    ("the carry writes LF only", "J11d", sub("setup", "$out = [string]::Join(\"`r`n\", $f.ToArray())", "$out = [string]::Join(\"`n\", $f.ToArray())")),
    ("the carry overwrites a set tile list", "J11d", sub("setup", "if ($f[16] -eq '') { $f[16] = $k17; $changed++ }", "$f[16] = $k17; $changed++")),
    ("a cited message is missing", "J12", sub("job", "stop sysmsg(15945)", "stop sysmsg(15929)")),
    ("the clock's VOC record names another program", "J12", lambda raw: (dict(raw, **{"newvoc/run.jobs.due": "V\nCA\n$runjob\n"}) if raw.get("newvoc/run.jobs.due") else None)),
    ("the helper takes job requests again", "J13", sub("doors", "if ($kind -cne 'door') { Finish $nonce $false", "if ($kind -cne 'door' -and $kind -cne 'job') { Finish $nonce $false")),
    ("the identity route takes any one-shot", "J14", sub("login", "if dcount(rj.cmd, ' ') = 2 and downcase(field(rj.cmd, ' ', 1)) = 'run.job' then", "if dcount(rj.cmd, ' ') >= 1 then")),
    ("the identity route skips the owner check", "J14", sub("login", "if SDEXT(@sdsys : @ds : '$cred' : @FM : 'DIR', @TRUE, SD_FILE_PRIVATE) = '1' then", "if @true then")),
    ("the identity route makes an administrator", "J14", sub("login", "            pw.via = 'windows-user'\n", "            pw.via = 'windows-user'\n            void kernel(K$ADMINISTRATOR, 1)\n")),
    ("the identity route fires when $stored opened", "J14", sub("login", "if pw.text = '' then pw.dpapi.fail = @true", "pw.dpapi.fail = @true")),
    ("the clock signs in with jobs off", "J14", sub("login", "         if not(jc.on) then goto abort.login\n", "")),
    ("run.jobs.due runs from any session", "J15", sub("due", "if one # 'run.jobs.due' or dcount(trim(@sentence), ' ') # 1 then", "if @false then")),
    ("a due job is not stamped first", "J15", sub("due", "            rec<6> = now\n", "")),
    ("a missed run is made up", "J15", sub("due", "if prev > since and prev > now - LATE.LIMIT then is.due = @true", "if prev > since then is.due = @true")),
    ("the clock runs a command itself", "J15", sub("due", "      execute 'run.job ' : due<i>", "      execute rec<3>")),
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
