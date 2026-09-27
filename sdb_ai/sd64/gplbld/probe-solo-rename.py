#!/usr/bin/env python3
# probe-solo-rename.py - SOLO 15 piece 5 on a STAGED tree (MSYS2 python3,
# unelevated), straight after stage.py --force --bootstrap, with no other SD
# running (machine-wide semaphores).  It sets TEST passwords and accounts in
# the stage, so run stage.py --force --bootstrap again before building an
# installer, and between the two modes.
#   python3 gplbld/probe-solo-rename.py <sd64 dir> <stage dir> [renamed|kept]
#
# A tree moved from another Windows user is simulated by making its one
# account under the name OLD ('olduser') and its $STORED blob unopenable
# (damaged - another user's blob opens for nobody here), then signing in as
# this Windows user.  "renamed": the folder is renamed with the account.
# "kept": a NATIVE process (py -3, sleeping) sits inside the old folder, which
# Windows then will not rename, so the folder must be kept and the register
# must name it.  MEASURED 26 Sep 2026: starting sd.exe itself inside the old
# folder does NOT block the rename - the MSYS2 runtime's working-directory
# handle allows it - so that first version of this mode renamed the folder and
# never reached the fallback.
#
# Every session's command line and raw output is printed; test passwords never
# are.  Checks anchor on success-only text and on the tree's state on disk,
# BEFORE and AFTER.  Exit 0 only when every check passed.
import getpass
import os
import subprocess
import sys
import tempfile

SD64, STAGE = sys.argv[1], sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else 'renamed'
sys.path.insert(0, os.path.join(SD64, 'gplbld'))
import bootstrap as B  # noqa: E402

ROOT = os.path.join(STAGE, 'SDCoreSolo')
SDSYS = os.path.join(ROOT, 'sdsys')
SDEXE = os.path.join(ROOT, 'usr', 'bin', 'sd.exe')
CRED = os.path.join(SDSYS, '$cred')
REG = os.path.join(SDSYS, 'accounts')
USRDIR = os.path.join(ROOT, 'user_accounts')
OLD = 'olduser'
NEW = (os.environ.get('USERNAME', '') or getpass.getuser()).strip().lower()
PW, APW = 'Probe-Move-1x', 'Probe-Admin-7'
ENV = dict(os.environ)
ENV.pop('SD_CONFIG', None)
fails = []


def verdict(label, ok, why):
    print('  %s  %s  (%s)' % ('PASS' if ok else 'FAIL', label, why))
    if not ok:
        fails.append(label)


def sd_in(args, text, cwd=None):
    cmd = [SDEXE] + args
    print('\n    $ %s   [input: %d line(s), not shown]  cwd=%s' % (' '.join(cmd), text.count('\n'), cwd or '(inherited)'))
    marker = None
    if args[0].lower() == '-internal':
        marker = os.path.join(SDSYS, '$internal')
        with open(marker, 'w', encoding='ascii', newline='\n') as f:
            f.write('probe-solo-rename pid=%d\n' % os.getpid())
    try:
        with tempfile.TemporaryFile() as tf:
            subprocess.run(cmd, env=ENV, input=text.encode('latin-1'), cwd=cwd,
                           stdout=tf, stderr=subprocess.STDOUT, timeout=60)
            tf.seek(0)
            out = tf.read().decode('latin-1').replace('\r', '')
    finally:
        if marker and os.path.exists(marker):
            os.remove(marker)
    for l in out.splitlines():
        print('      | ' + l)
    for p in (PW, APW):
        if p in out:
            fails.append('a password was echoed')
    return out


def lines(out):
    return [l.strip().lower() for l in out.splitlines() if l.strip()]


def ls(d):
    return sorted(os.listdir(d)) if os.path.isdir(d) else None


def readf(p):
    if not os.path.isfile(p):
        return None
    with open(p, 'rb') as f:
        return f.read()


def state(label):
    print('  state %s: register=%s user_accounts=%s $cred=%s' % (label, ls(REG), ls(USRDIR), ls(CRED)))
    s = readf(os.path.join(CRED, '$STORED'))
    if s is not None:
        print('         $STORED owner=%r' % s.decode('latin-1').replace('\r', '').split('\n')[0])


def dirline(out, name):
    d = os.path.join(USRDIR, name).lower()
    return d in lines(out)


def audit_count(s):
    p = os.path.join(SDSYS, 'audit')
    b = readf(p)
    return -1 if b is None else b.decode('latin-1').count(s)


print('inputs: sd.exe=%s exists=%s  mode=%s  old=%r new=%r' % (SDEXE, os.path.isfile(SDEXE), MODE, OLD, NEW))
if not os.path.isfile(SDEXE) or not NEW or NEW == OLD or MODE not in ('renamed', 'kept'):
    print('REFUSING: no staged sd.exe, no user name, or a bad mode - nothing to measure')
    sys.exit(2)
if ls(USRDIR):
    print('REFUSING: user_accounts is not empty (%s) - restage first' % ls(USRDIR))
    sys.exit(2)

B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)
B.sd(SDEXE, ENV, ['-start'])
try:
    print('\n== 1. a tree whose one account belongs to %r' % OLD)
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_account', OLD], '\n')
    verdict('old account made', 'solo account ready %s ' % OLD in (' '.join(lines(out)) + ' '), 'SOLO ACCOUNT READY olduser')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ADMIN'], APW + '\n')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ACCOUNT', OLD], PW + '\n')
    verdict('old account password set', 'solo password set account' in lines(out), 'SOLO PASSWORD SET ACCOUNT')
    stp = os.path.join(CRED, '$STORED')
    s = readf(stp).decode('latin-1')
    rec = s.replace('\r', '').split('\n')
    bad = s.replace(rec[1][40:60], 'A' * 20).encode('latin-1')
    with open(stp, 'wb') as f:
        f.write(bad)
    verdict('$STORED made unopenable (damaged)', readf(stp) != s.encode('latin-1'), 'bytes differ')
    old_cred = readf(os.path.join(CRED, OLD.upper()))
    state('before')

    print('\n== 2. the installer over the moved tree: nothing doubled')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_account', NEW], '\n')
    verdict('solo_account reports MOVED', any(l.startswith('solo account moved %s ' % OLD) for l in lines(out)), 'SOLO ACCOUNT MOVED olduser ...')
    verdict('and creates no second account', ls(USRDIR) == [OLD] and ls(REG) == sorted(['sdsys', OLD]), 'user_accounts=[olduser]')

    print('\n== 3. a wrong password renames nothing')
    out = sd_in(['WHERE'], 'not-the-password\n')
    verdict('refused', 'wrong password' in out.lower() and not dirline(out, OLD) and not dirline(out, NEW), 'Wrong password, no dir line')
    verdict('tree unchanged', ls(USRDIR) == [OLD] and ls(REG) == sorted(['sdsys', OLD]) and OLD.upper() in ls(CRED), 'still olduser')

    print('\n== 4. the password: renamed to %r' % NEW)
    n0 = audit_count('ACCOUNT RENAMED old=%s new=%s' % (OLD.upper(), NEW.upper()))
    holder = None
    if MODE == 'kept':
        olddir = os.path.join(USRDIR, OLD)
        holder = subprocess.Popen(['py', '-3', '-c', 'import time; time.sleep(60)'], cwd=olddir)
        import time
        time.sleep(2)
        print('  holder: native py -3 pid %d, cwd %s, running=%s' % (holder.pid, olddir, holder.poll() is None))
        verdict('holder is running in the old folder', holder.poll() is None, 'py -3 alive')
    try:
        out = sd_in(['WHERE'], PW + '\n')
    finally:
        if holder is not None:
            holder.kill()
            holder.wait()
    state('after')
    L = lines(out)
    verdict('12023 said', 'this sd core solo account was %s and is now %s' % (OLD, NEW) in L, 'the rename message')
    reg_new = readf(os.path.join(REG, NEW))
    reg_path = reg_new.decode('latin-1').replace('\r', '').split('\n')[0] if reg_new else None
    print('  register %s field 1 = %r' % (NEW, reg_path))
    verdict('register renamed', ls(REG) == sorted(['sdsys', NEW]), 'register = sdsys, %s' % NEW)
    verdict('$cred re-keyed verbatim', readf(os.path.join(CRED, NEW.upper())) == old_cred and old_cred
            and OLD.upper() not in ls(CRED), 'new record == old bytes, old gone')
    st = readf(stp).decode('latin-1').replace('\r', '').split('\n')
    verdict('$STORED owner renamed, blob kept', st[0] == NEW.upper() and st[1] == bad.decode('latin-1').replace('\r', '').split('\n')[1], 'owner=%s' % NEW.upper())
    n1 = audit_count('ACCOUNT RENAMED old=%s new=%s' % (OLD.upper(), NEW.upper()))
    if MODE == 'renamed':
        verdict('session landed in the renamed folder', dirline(out, NEW), 'WHERE = user_accounts/%s' % NEW)
        verdict('folder renamed', ls(USRDIR) == [NEW], 'user_accounts = [%s]' % NEW)
        verdict('register names @USRDIR/<new>', reg_path is not None and reg_path.lower().endswith(NEW) and reg_path.startswith('@USRDIR'), reg_path)
        verdict('audited folder=renamed', n1 == n0 + 1 and audit_count('new=%s folder=renamed' % NEW.upper()) >= 1, 'one new ACCOUNT RENAMED line')
    else:
        verdict('12024 said', 'the folder' in out.lower() and 'could not be renamed and is still used' in out.lower(), 'folder kept message')
        verdict('session landed in the kept folder', dirline(out, OLD), 'WHERE = user_accounts/%s' % OLD)
        verdict('folder kept', ls(USRDIR) == [OLD], 'user_accounts = [%s]' % OLD)
        verdict('register names @USRDIR/<old>', reg_path is not None and reg_path.lower().endswith(OLD) and reg_path.startswith('@USRDIR'), reg_path)
        verdict('audited folder=kept', n1 == n0 + 1 and audit_count('new=%s folder=kept' % NEW.upper()) >= 1, 'one new ACCOUNT RENAMED line')

    print('\n== 5. the next sign-in is ordinary')
    out = sd_in(['WHERE'], PW + '\n')
    home = NEW if MODE == 'renamed' else OLD
    verdict('lands, no second rename', dirline(out, home) and 'is now' not in out.lower(), 'WHERE = %s, no 12023' % home)
    out = sd_in(['WHERE'], 'not-the-password\n')
    verdict('CONTROL: wrong password still refused', 'wrong password' in out.lower() and not dirline(out, home), 'refused')
finally:
    B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)

print('\nRESULT (%s): %s' % (MODE, 'ALL PASS' if not fails else 'FAILED: ' + '; '.join(fails)))
sys.exit(1 if fails else 0)
