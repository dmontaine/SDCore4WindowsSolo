"""test-isstasks-units.py - a [Tasks] parent that has children must be tickable on its own.

    python test-isstasks-units.py

Exit 0 all checks passed, 1 a check failed, 2 the guard could not run.  No install, no VM, no elevation.

WHY IT EXISTS (SOLO 34, 6 Oct 2026).  Inno Setup unchecks a task automatically when none of its children is
checked, unless the task carries `checkablealone` - so a parent without the flag cannot be ticked alone.  Solo's
"Provide the SD Core API" and "Install the OpenSSH server" lacked it: "API on, other computers off" could not be
chosen in the wizard, and it cost an evening of VM testing that blamed the guest.  The full product's sd.iss has
the flag on its parents and says why (its comment before [Tasks] group 2).

THE RULE IT CHECKS, per task that has a child ("parent\\child" in the same section):
  - it carries `checkablealone`, and
  - it carries `unchecked`, because checkablealone alone would make the box start TICKED (Inno's default for a
    task with no `unchecked`), which for these boxes means installing something nobody asked for.
Only the parents named in OPT_IN_PARENTS are held to the second rule: a parent that is meant to start ticked is
a decision, not a defect.  Read from the .iss files themselves, never from a copy of them.

THE NULL CASE IS REFUSED: a file whose [Tasks] section yields no parent is exit 2, not a pass; and a MUTANT (the
flag stripped from the live text) must be flagged, or the checker is not looking at anything.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOLO = os.path.join(HERE, 'sd-solo.iss')
# the full product's installer sits in the other repository; checked as a control when it is reachable
FULL = os.path.normpath(os.path.join(HERE, '..', '..', '..', '..', 'SDCore4Windows', 'sdb_ai', 'sd64', 'gplbld', 'sd.iss'))

# parents that must also start unticked (opt-in boxes); the full product's PATH box has no children
OPT_IN_PARENTS = {'api', 'installssh', 'sshserver', 'apiremote'}

passed = 0
failed = 0


def check(what, ok, detail=''):
    global passed, failed
    if ok:
        passed += 1
        print('  [PASS] ' + what)
    else:
        failed += 1
        print('  [FAIL] ' + what + (' - ' + detail if detail else ''))


def tasks_of(text):
    """{name: set(flags)} for the [Tasks] section, continuation lines joined, comment lines dropped."""
    out = {}
    in_tasks = False
    cur = ''
    for raw in text.splitlines():
        line = raw.rstrip('\r')
        if re.match(r'^\[[A-Za-z]+\]\s*$', line):
            in_tasks = line.strip().lower() == '[tasks]'
            cur = ''
            continue
        if not in_tasks or line.lstrip().startswith(';') or not line.strip():
            continue
        cur += line.strip()
        if cur.endswith('\\'):
            cur = cur[:-1] + ' '
            continue
        m = re.search(r'Name:\s*"([^"]+)"', cur)
        f = re.search(r'Flags:\s*([^;]*)', cur)
        if m:
            out[m.group(1)] = set((f.group(1) if f else '').split())
        cur = ''
    return out


def parents(tasks):
    sep = chr(92)
    return sorted({n.rsplit(sep, 1)[0] for n in tasks if sep in n and n.rsplit(sep, 1)[0] in tasks})


def violations(tasks):
    bad = []
    for p in parents(tasks):
        flags = tasks[p]
        if 'checkablealone' not in flags:
            bad.append(p + ': no checkablealone (cannot be ticked on its own)')
        if p in OPT_IN_PARENTS and 'unchecked' not in flags:
            bad.append(p + ': no unchecked (would start ticked)')
    return bad


def read(path):
    with open(path, 'rb') as fh:
        return fh.read().decode('utf-8', 'replace')


print('test-isstasks-units: ' + SOLO)
if not os.path.isfile(SOLO):
    print('test-isstasks-units: no ' + SOLO)
    sys.exit(2)

solo_text = read(SOLO)
solo = tasks_of(solo_text)
ps = parents(solo)
print('  Solo [Tasks]: ' + str(len(solo)) + ' task(s), parents: ' + ', '.join(ps))
if len(ps) < 2:
    print('test-isstasks-units: VOID - fewer than two parents found in Solo [Tasks]; the parse measured nothing.')
    sys.exit(2)

check('Solo: every parent is tickable alone and opt-in', not violations(solo), '; '.join(violations(solo)))
check('Solo: "api" and "installssh" are both parents the check saw', 'api' in ps and 'installssh' in ps, str(ps))

# MUTANT: strip the flag from the live text; the guard must go red.
mut_text = solo_text.replace('checkablealone', '')
check('CONTROL: the mutation changed the text', mut_text != solo_text)
check('MUTANT: Solo without checkablealone is flagged', len(violations(tasks_of(mut_text))) >= 2)
mut2 = re.sub(r'(Name: "api";[^\n]*?)unchecked ', r'\1', solo_text)
check('CONTROL: the second mutation changed the text', mut2 != solo_text)
check('MUTANT: "api" without unchecked is flagged', any(v.startswith('api:') for v in violations(tasks_of(mut2))))

if os.path.isfile(FULL):
    full = tasks_of(read(FULL))
    fps = parents(full)
    print('  full product [Tasks]: ' + str(len(full)) + ' task(s), parents: ' + ', '.join(fps))
    check('full product: has parents the check saw', len(fps) >= 2, str(fps))
    check('full product: every parent is tickable alone and opt-in', not violations(full), '; '.join(violations(full)))
else:
    print('  (the full product\'s sd.iss is not beside this repository; its control row is skipped)')

print('')
if passed == 0:
    print('test-isstasks-units: VOID - no check ran.')
    sys.exit(2)
if failed:
    print('test-isstasks-units: FAILED - %d passed, %d failed.' % (passed, failed))
    sys.exit(1)
print('test-isstasks-units: PASSED - %d of %d checks passed.' % (passed, passed))
sys.exit(0)
