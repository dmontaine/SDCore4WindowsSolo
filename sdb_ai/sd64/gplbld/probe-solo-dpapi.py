#!/usr/bin/env python3
# probe-solo-dpapi.py - SOLO 15 piece 4 on a STAGED tree (MSYS2 python3,
# unelevated), straight after stage.py --force --bootstrap, with no other SD
# running (machine-wide semaphores).  It sets TEST passwords in the stage, so
# run stage.py --force --bootstrap again before building an installer.
#   python3 gplbld/probe-solo-dpapi.py <sd64 dir> <stage dir>
# First passed 26 Sep 2026, 21/21.
# Every session's command line and raw output is printed (bootstrap.sd); the
# test passwords are never printed.  Each check anchors on success-only text
# and also fails on a disqualifier.  Exit 0 only when every check passed.
import getpass
import os
import shutil
import subprocess
import sys
import tempfile

SD64, STAGE = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(SD64, 'gplbld'))
import bootstrap as B  # noqa: E402

ROOT = os.path.join(STAGE, 'SDCoreSolo')
SDSYS = os.path.join(ROOT, 'sdsys')
SDEXE = os.path.join(ROOT, 'usr', 'bin', 'sd.exe')
CRED = os.path.join(SDSYS, '$cred')
STORED = os.path.join(CRED, '$STORED')
USER = (os.environ.get('USERNAME', '') or getpass.getuser()).strip()
ACCT = USER.lower()
ACCDIR = os.path.join(ROOT, 'user_accounts', ACCT)
PW1, PW2, APW = 'Probe-Acct-1x', 'Probe-Acct-2y', 'Probe-Admin-7'
ENV = dict(os.environ)
ENV.pop('SD_CONFIG', None)
fails = []


def verdict(label, ok, why):
    print('  %s  %s  (%s)' % ('PASS' if ok else 'FAIL', label, why))
    if not ok:
        fails.append(label)


def sd_in(args, text):
    """One session with chosen input; marker for -internal; raw output."""
    cmd = [SDEXE] + args
    print('\n    $ %s   [input: %d line(s), not shown]' % (' '.join(cmd), text.count('\n')))
    marker = None
    if args[0].lower() == '-internal':
        marker = os.path.join(SDSYS, '$internal')
        with open(marker, 'w', encoding='ascii', newline='\n') as f:
            f.write('witness-p4 pid=%d\n' % os.getpid())
    try:
        with tempfile.TemporaryFile() as tf:
            subprocess.run(cmd, env=ENV, input=text.encode('latin-1'),
                           stdout=tf, stderr=subprocess.STDOUT, timeout=60)
            tf.seek(0)
            out = tf.read().decode('latin-1').replace('\r', '')
    finally:
        if marker and os.path.exists(marker):
            os.remove(marker)
    for l in out.splitlines():
        print('      | ' + l)
    for p in (PW1, PW2, APW):
        if p in out:
            fails.append('a password was echoed')
    return out


def lines(out):
    return [l.strip().lower() for l in out.splitlines() if l.strip()]


def stored():
    if not os.path.isfile(STORED):
        return None
    with open(STORED, 'rb') as f:
        return f.read().decode('latin-1').replace('\r', '').split('\n')


def lands(out):
    """A WHERE that ran: the account directory as a whole line."""
    want = {ACCDIR.lower()}
    try:
        w = subprocess.run(['cygpath', '-w', ACCDIR], capture_output=True, text=True).stdout.strip()
        want.add(w.lower())
    except OSError:
        pass
    return bool(want & set(lines(out)))


def errlog_count(s):
    p = os.path.join(SDSYS, 'audit')
    if not os.path.isfile(p):
        return -1
    with open(p, 'rb') as f:
        return f.read().decode('latin-1').count(s)


print('inputs: sd.exe=%s exists=%s  user=%r account=%r' % (SDEXE, os.path.isfile(SDEXE), USER, ACCT))
print('        $STORED before: %s' % ('present' if os.path.exists(STORED) else 'absent'))
if not os.path.isfile(SDEXE) or not ACCT:
    print('REFUSING: no staged sd.exe or no user name - nothing to measure')
    sys.exit(2)

B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)
B.sd(SDEXE, ENV, ['-start'])
try:
    print('\n== 1. installer steps: account, admin password, account password')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_account', USER], '\n')
    verdict('solo_account', any(l.startswith('solo account ready %s ' % ACCT) for l in lines(out)), 'want SOLO ACCOUNT READY')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ADMIN'], APW + '\n')
    verdict('solo_password ADMIN', 'solo password set admin' in lines(out), 'want SOLO PASSWORD SET ADMIN')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ACCOUNT', ACCT], PW1 + '\n')
    verdict('solo_password ACCOUNT', 'solo password set account' in lines(out)
            and 'could not be kept' not in out.lower(), 'want SOLO PASSWORD SET ACCOUNT, no "could not be kept"')
    rec = stored()
    print('  $STORED fields: %s' % (None if rec is None else [rec[0], '<%d base64 chars>' % len(rec[1])]))
    verdict('$STORED written for this account', rec is not None and rec[0] == ACCT.upper()
            and len(rec[1]) > 100 and PW1 not in ''.join(rec), 'want <1>=%s, <2> a long blob, no plaintext' % ACCT.upper())
    blob1 = rec[1] if rec else ''

    print('\n== 2. one-shot WHERE with NO password on its input')
    n0 = errlog_count('via=stored')
    out = sd_in(['WHERE'], '\n')
    verdict('one-shot runs from $STORED', lands(out) and 'wrong password' not in out.lower(), 'want the account dir line')
    n1 = errlog_count('via=stored')
    print('  audit "via=stored" count %d -> %d' % (n0, n1))
    verdict('audited via=stored', n1 == n0 + 1 and n0 >= 0, 'want exactly one new line')

    print('\n== 3. CONTROL: $STORED moved aside -> the same one-shot is refused')
    aside = STORED + '.aside'
    shutil.move(STORED, aside)
    out = sd_in(['WHERE'], '\n')
    verdict('no $STORED: refused', not lands(out) and 'wrong password' in out.lower(), 'want "Wrong password", no dir line')
    out = sd_in(['WHERE'], PW1 + '\n')
    verdict('no $STORED: password on input still works', lands(out), 'want the dir line')
    shutil.move(aside, STORED)

    print('\n== 4. a blob this user cannot open (damaged) -> falls back to input')
    with open(STORED, 'rb') as f:
        good = f.read()
    bad = good.replace(blob1[40:60].encode(), b'A' * 20)
    verdict('damage actually changed the file', bad != good, 'bytes differ')
    with open(STORED, 'wb') as f:
        f.write(bad)
    out = sd_in(['WHERE'], '\n')
    verdict('damaged blob: no-input one-shot refused', not lands(out) and 'wrong password' in out.lower(), 'want refusal')
    out = sd_in(['WHERE'], PW1 + '\n')
    verdict('damaged blob: password on input works', lands(out), 'want the dir line')
    with open(STORED, 'wb') as f:
        f.write(good)

    print('\n== 5. SET.PASSWORD rewrites $STORED')
    bp = os.path.join(ACCDIR, 'bp')
    print('  bp dir %s exists=%s' % (bp, os.path.isdir(bp)))
    src = '\n'.join([
        'data "%s"' % APW, 'execute "ADMIN" capturing o', 'crt "LEG.A " : change(o, @fm, " | ")',
        'data "%s"' % PW2, 'data "%s"' % PW2, 'execute "SET.PASSWORD" capturing o',
        'crt "LEG.B " : change(o, @fm, " | ")',
        'end', ''])
    src2 = '\n'.join(['x = sdext("%s", @false, 112)' % blob1, 'crt "LEG.D LEN=" : len(x)', 'end', ''])
    with open(os.path.join(bp, 'probe15b'), 'w', encoding='ascii', newline='\n') as f:
        f.write(src2)
    with open(os.path.join(bp, 'probe15'), 'w', encoding='ascii', newline='\n') as f:
        f.write(src)
    out = sd_in(['BASIC', 'bp', 'probe15'], '\n')
    verdict('test program compiles (from $STORED, no input)', '0 error(s)' in lines(out), "want '0 error(s)'")
    out = sd_in(['RUN', 'bp', 'probe15'], '\n')
    L = lines(out)
    verdict('A: ADMIN unlocks', any(l.startswith('leg.a ') and 'unlocked' in l for l in L), 'want LEG.A ... unlocked')
    verdict('B: SET.PASSWORD changes, and keeps it', any(l.startswith('leg.b ') and 'password changed' in l
            and 'could not be kept' not in l for l in L), 'want LEG.B ... Password changed, no 12022')
    rec2 = stored()
    verdict('$STORED rewritten (new blob)', rec2 is not None and rec2[0] == ACCT.upper() and rec2[1] != blob1, 'blob differs')
    out = sd_in(['WHERE'], '\n')
    verdict('one-shot still runs from the new $STORED', lands(out), 'want the dir line')
    shutil.move(STORED, aside)
    out = sd_in(['WHERE'], PW1 + '\n')
    verdict('CONTROL ($STORED aside): the old password is refused', not lands(out), 'no dir line')
    out = sd_in(['WHERE'], PW2 + '\n')
    verdict('CONTROL ($STORED aside): the new password works', lands(out), 'want the dir line')
    shutil.move(aside, STORED)

    print('\n== 6. a non-$internal program cannot use the DPAPI keys')
    # SDEXT is an internal-only intrinsic (bcomp:662): ordinary BASIC reads it
    # as an undimensioned matrix.  The C gate behind it is not reachable here.
    out = sd_in(['BASIC', 'bp', 'probe15b'], '\n')
    verdict('D: ordinary BASIC cannot compile SDEXT', 'matrix sdext is not referenced in a dim statement' in out.lower()
            and '0 error(s)' not in lines(out), "want the 'Matrix SDEXT' error, not '0 error(s)'")
    out = sd_in(['RUN', 'bp', 'probe15b'], '\n')
    verdict('D: and nothing runs', not any(l.startswith('leg.d') for l in lines(out)), 'no LEG.D line')
finally:
    B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)

print('\nRESULT: %s' % ('ALL PASS' if not fails else 'FAILED: ' + '; '.join(fails)))
sys.exit(1 if fails else 0)
