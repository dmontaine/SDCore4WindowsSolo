"""test-solosignin-units.py - Solo's API sign-in refuses the names it must refuse before any password is checked.

    python test-solosignin-units.py

Exit 0 all checks passed, 1 a check failed, 2 the guard could not run.  No install, no SD.

WHY IT EXISTS (SOLO 60, 16 Nov 2026).  Read against Linux Solo, Windows Solo's vb.scram.first lacked one test Linux has:
with no account password of its own, the global password could sign in under ANY name in the register - and SDSYS is in
the register.  Ruling 11: SDSYS is never an API login.  Linux Solo writes "if have.global and downcase(username) # 'sdsys'";
Windows Solo now does too.  Nothing pinned it on either side.

WHAT IT CHECKS, read from sdsys/gpl.bp/apisrvr itself:
  S1  an empty name or one starting with '$' ($admin, $global, $stored are $cred records) is refused before $cred is opened;
  S2  the global-password route under a name with no password of its own excludes SDSYS, case-blind, before the register read;
  S3  that route still reads the register (a name must be an account) and fails closed when it is not one.
MUTANTS (each must be flagged, or the checker is reading nothing): the '$' test removed, the SDSYS exclusion removed,
the exclusion made case-sensitive, the register read dropped.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, '..', 'sdsys', 'gpl.bp', 'apisrvr'))

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


def code_only(t):
    """Drop full-line comments (* in column 1 after spaces) and ;* tails."""
    out = []
    for line in t.split('\n'):
        if re.match(r'^\s*\*', line):
            continue
        out.append(re.sub(r';\s*\*.*$', '', line))
    return '\n'.join(out)


def violations(text):
    bad = []
    c = code_only(text)
    opn = c.find("openpath @sdsys:@ds:'$cred' to scram.cred.f")
    if opn < 0:
        return ['no $cred open in vb.scram.first (the parse found nothing)']
    dollar = re.search(r"if\s+username\s*=\s*''\s+or\s+username\[1,1\]\s*=\s*'\$'\s+then", c)
    if not dollar or dollar.start() > opn:
        bad.append("S1 the empty / '$' name is not refused before $cred is opened")
    route = re.search(r"if\s+have\.global\s+and\s+downcase\(username\)\s*#\s*'sdsys'\s+then\s*\n(.*?)\n\s*end\s*\n\s*if\s+not\(in\.register\)\s+then", c, re.S)
    if not route:
        bad.append("S2 the global-password route does not exclude SDSYS (downcase(username) # 'sdsys')")
    else:
        if "read scram.acc.rec from scram.acc.f, downcase(username) then in.register = @true" not in route.group(1):
            bad.append('S3 the global-password route does not read the register')
    if not re.search(r"if\s+not\(in\.register\)\s+then\s*\n\s*scram\.gcred\s*=\s*''\s*\n\s*scram\.refuse\.reason\s*=\s*'no credential'", c):
        bad.append('S3 a name that is not an account is not refused (fail closed)')
    return bad


print('test-solosignin-units: ' + SRC)
if not os.path.isfile(SRC):
    print('test-solosignin-units: no ' + SRC)
    sys.exit(2)
with open(SRC, 'rb') as fh:
    text = fh.read().decode('latin-1').replace('\r\n', '\n')
if 'vb.scram.first' not in text:
    print('test-solosignin-units: VOID - no vb.scram.first in the file; the parse measured nothing.')
    sys.exit(2)

v = violations(text)
check("S1-S3 the '$' names refused first; the global route excludes SDSYS, reads the register, fails closed", not v, '; '.join(v))

MUTANTS = [
    ("the '$' test removed", "if username = '' or username[1,1] = '$' then", "if username = '' then", 'S1'),
    ('the SDSYS exclusion removed', "if have.global and downcase(username) # 'sdsys' then", 'if have.global then', 'S2'),
    ('the exclusion made case-sensitive', "if have.global and downcase(username) # 'sdsys' then", "if have.global and username # 'sdsys' then", 'S2'),
    ('the register read dropped', 'read scram.acc.rec from scram.acc.f, downcase(username) then in.register = @true', 'in.register = @true', 'S3'),
]
for name, old, new, tag in MUTANTS:
    m = text.replace(old, new, 1)
    check('CONTROL: mutant "' + name + '" changed the text', m != text)
    check('MUTANT: ' + name + ' is flagged', any(x.startswith(tag) for x in violations(m)))

print('')
if passed == 0:
    print('test-solosignin-units: VOID - no check ran.')
    sys.exit(2)
if failed:
    print('test-solosignin-units: FAILED - %d passed, %d failed.' % (passed, failed))
    sys.exit(1)
print('test-solosignin-units: PASSED - %d of %d checks passed.' % (passed, passed))
sys.exit(0)
