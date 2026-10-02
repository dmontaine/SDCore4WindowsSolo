"""The Solo server is installed as sd-solo.exe, and everything that starts it uses that name.

WHY THIS EXISTS.  Owner's ruling, 1 Oct 2026: "sd" is the FULL product and "sd-solo" is
Solo, on Windows and Linux, and the Solo executable itself is renamed.  It replaces a
text launcher (sd-solo.cmd) that made cmd.exe ask "Terminate batch job (Y/N)?" after OFF.
The build still makes bin\\sd.exe; stage.py ships it as usr\\bin\\sd-solo.exe.  Anything that
still names the old installed file finds nothing: the installer's -stop, the startup task,
the ssh ForceCommand, the daemon's API sessions and cleanup, the client library's local
connect.  Each is a place a tidy-up or a merge from the other tree can bring "sd.exe" back.

A source check: no install, no SD, no elevation.  The mutants run on synthetic text.

  python gplbld/test-soloexe-units.py

Exit 0 all checks passed, 1 a check failed, 2 the tree is not there to read.
"""

import os
import re
import sys

NAME = "sd-solo.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "gplsrc")

failures = 0
passes = 0


def check(label, ok, detail=""):
    global failures, passes
    if ok:
        passes += 1
        print("  [PASS] " + label)
    else:
        failures += 1
        print("  [FAIL] " + label + ("  " + detail if detail else ""))


def read(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read().decode("latin-1").replace("\r\n", "\n")


def code(t):
    """Lines that are not whole-line comments (#, rem, ;, //, *, /*, {)."""
    out = []
    for line in t.split("\n"):
        s = line.strip()
        if not s or re.match(r"(#|rem\b|;|//|\*|/\*|\{)", s, re.I):
            continue
        out.append(s)
    return "\n".join(out)


def stage_problems(t):
    bad = []
    c = code(t)
    if not re.search(r"^SOLO_EXE\s*=\s*'sd-solo\.exe'", c, re.M):
        bad.append("SOLO_EXE is not 'sd-solo.exe'")
    if not re.search(r"os\.path\.join\(pfbin,\s*SOLO_EXE if f == 'sd\.exe' else f\)", c):
        bad.append("the copy loop does not ship sd.exe as SOLO_EXE")
    if not re.search(r"os\.path\.join\(pfbin,\s*SOLO_EXE\)", c):
        bad.append("the bootstrap is not pointed at the staged SOLO_EXE")
    if "sd-solo.cmd" in c:
        bad.append("stage.py still ships the sd-solo.cmd launcher")
    return bad


def daemon_problems(defs, wind):
    bad = []
    if not re.search(r'#define\s+SD_SERVER_NAME\s+"sd-solo"', defs):
        bad.append('sddefs.h does not define SD_SERVER_NAME "sd-solo"')
    if len(re.findall(r'"%s/"\s*SD_SERVER_NAME', code(wind))) != 2:
        bad.append("sdwind.c does not start the server by SD_SERVER_NAME in both places")
    if re.search(r'"%s/sd"', code(wind)):
        bad.append('sdwind.c still builds "%s/sd"')
    return bad


def client_problems(t):
    c = code(t)
    if 'strcpy(p, "\\\\sd-solo.exe")' not in c or 'sizeof("\\\\sd-solo.exe")' not in c:
        return ["sdclilib.c does not look for \\sd-solo.exe beside itself"]
    return []


def installed_path_problems(t):
    """Installed-Solo paths (usr\\bin\\sd.exe) in code lines must say sd-solo.exe.
    The full product's file is allowed where it is named by Program Files / commonpf64."""
    bad = []
    for line in code(t).split("\n"):
        if re.search(r"usr.bin.sd\.exe", line, re.I) and not re.search(
                r"Program Files|commonpf64|ProgramFiles", line, re.I):
            bad.append(line.strip()[:90])
    return bad


# (file, must name sd-solo.exe)
SCRIPTS = ["sd-solo.iss", "solo-machine.ps1", "solo-setup.ps1", "cycle.ps1",
           "verify-solo.ps1", "assert-current.ps1"]

print("test-soloexe-units: the Solo server is installed as %s" % NAME)
stage = read(os.path.join(HERE, "stage.py"))
defs = read(os.path.join(SRC, "sddefs.h"))
wind = read(os.path.join(SRC, "sdwind.c"))
cli = read(os.path.join(SRC, "sdclilib", "sdclilib.c"))
if None in (stage, defs, wind, cli):
    print("test-soloexe-units: a source file was not found - nothing measured.")
    sys.exit(2)

s = stage_problems(stage)
check("stage.py ships bin\\sd.exe as sd-solo.exe and bootstraps that", s == [], "; ".join(s))
check("the sd-solo.cmd launcher is gone", not os.path.exists(os.path.join(HERE, "sd-solo.cmd")))
d = daemon_problems(defs, wind)
check("sdwind.c starts the server by the Solo name", d == [], "; ".join(d))
c = client_problems(cli)
check("sdclilib.c's local connect looks for sd-solo.exe", c == [], "; ".join(c))
for name in SCRIPTS:
    t = read(os.path.join(HERE, name))
    if t is None:
        check("%s is present" % name, False)
        continue
    check("%s names sd-solo.exe" % name, NAME in code(t))
    p = installed_path_problems(t)
    check("%s has no installed-Solo path ending in sd.exe" % name, p == [], "; ".join(p))

# MUTANTS, on synthetic text: each is a plausible tidy-up or a bad merge.
good_stage = ("SOLO_EXE = 'sd-solo.exe'\n"
              "dst = os.path.join(pfbin, SOLO_EXE if f == 'sd.exe' else f)\n"
              "'--sd', os.path.abspath(os.path.join(pfbin, SOLO_EXE)),\n")
check("CONTROL: correct synthetic stage.py passes", stage_problems(good_stage) == [])
check("MUTANT: sd.exe shipped under its own name is caught",
      stage_problems(good_stage.replace("SOLO_EXE if f == 'sd.exe' else f", "f")) != [])
check("MUTANT: bootstrap pointed at sd.exe is caught",
      stage_problems(good_stage.replace("join(pfbin, SOLO_EXE))", "join(pfbin, 'sd.exe'))")) != [])
check("MUTANT: the launcher shipped again is caught",
      stage_problems(good_stage + "x = os.path.join(here, 'sd-solo.cmd')\n") != [])
good_wind = 'snprintf(a, n, "%s/" SD_SERVER_NAME, b);\nsnprintf(c, n, "%s/" SD_SERVER_NAME, b);\n'
good_defs = '#define SD_SERVER_NAME "sd-solo"\n'
check("CONTROL: correct synthetic daemon source passes", daemon_problems(good_defs, good_wind) == [])
check("MUTANT: one spawn back on \"%s/sd\" is caught",
      daemon_problems(good_defs, good_wind.replace('"%s/" SD_SERVER_NAME', '"%s/sd"', 1)) != [])
check("MUTANT: the name changed in sddefs.h is caught",
      daemon_problems('#define SD_SERVER_NAME "sd"\n', good_wind) != [])
check("MUTANT: an installed path ending in sd.exe is caught",
      installed_path_problems("$x = Join-Path $Root 'usr\\bin\\sd.exe'\n") != [])
check("CONTROL: the full product's Program Files path is allowed",
      installed_path_problems("$x = 'C:\\Program Files\\SD\\usr\\bin\\sd.exe'\n") == [])
check("MUTANT: the client library reverting to sd.exe is caught",
      client_problems('strcpy(p, "\\\\sd.exe");\n') != [])

print("")
if passes == 0:
    print("test-soloexe-units: VOID - no check ran.")
    sys.exit(2)
if failures:
    print("test-soloexe-units: %d passed, %d failed." % (passes, failures))
    sys.exit(1)
print("test-soloexe-units: %d passed, 0 failed." % passes)
sys.exit(0)
