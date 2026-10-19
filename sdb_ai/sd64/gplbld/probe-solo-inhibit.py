#!/usr/bin/env python3
# probe-solo-inhibit.py - the witness for RELEASE_1.1 157 (INHIBIT.LOGIN on Solo) and RELEASE_1.1 158 (the MASTER.LOGIN
# paragraph run for an API session), on a STAGED tree (MSYS2 python3, unelevated), straight after stage.py --force
# --bootstrap, with no other SD Core Solo running (machine-wide semaphores and the fixed API port 4249).  It sets TEST
# passwords in the stage and creates <stage>/SDCoreSolo/sd-tls, exactly as probe-solo-api.py does, so run stage.py --force
# --bootstrap again before building an installer (a cycle does).
#   python3 gplbld/probe-solo-inhibit.py <sd64 dir> <stage dir>
#
# WHAT IT MEASURES, every line printed with the real command, the raw output and a verdict:
#   157  1. a session that is the administrator (ADMIN with the test password) is told "Logins are allowed" with the
#           inhibit off (the null case: the state read is not just an empty answer);
#        2. after INHIBIT.LOGIN ON it is told "Logins are inhibited by <name> (user <n>)";
#        3. a NEW session is refused with the refusal's own words (not accepting new sessions ... inhibit.login) and is
#           not landed in the account (nothing from WHERE);
#        4. the audit trail carries "logins are inhibited (inhibit.login)";
#        5. after INHIBIT.LOGIN OFF the state reads "Logins are allowed" again, and a NEW session lands (control).
#        On Solo no new session is an administrator at sign-in, so there is no row for "an administrator signs in
#        during the inhibit": that is the property the changelog and page 06a state.
#   158  6. CONTROL: with a MASTER.LOGIN paragraph (LOGMSG MASTERLOGIN-RAN) written into the SDSYS VOC, a new local
#           session runs it: the error log gains one MASTERLOGIN-RAN line;
#        7. an API session (gplbld/scram-probe.py, the real wire: TLS 1.3 + SCRAM) runs it once: the error log gains
#           exactly one more line, and the login was VERIFIED.
#        The paragraph is deleted again in a finally, and the inhibit is switched off in a finally.
#
# THE HELD SESSION.  The administrator session stays open on a pipe while the others are tried, its output going to a
# FILE that is read back (never a pipe: bootstrap.py's note on PROJECT_STATUS.md 6), and it is ended with OFF, never
# killed.  A session that does not end is reported; the final "sd -stop" of the staged tree ends what is left.
# Passwords are test values and are never echoed (show() fails the run if one is).  Exit 0 only when every check passed.
import os
import subprocess
import sys
import tempfile
import time

SD64, STAGE = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(SD64, 'gplbld'))
import bootstrap as B  # noqa: E402

ROOT = os.path.join(STAGE, 'SDCoreSolo')
SDSYS = os.path.join(ROOT, 'sdsys')
SDEXE = os.path.join(ROOT, 'usr', 'bin', 'sd-solo.exe')   # the Solo front (probe-solo-api.py still says sd.exe)
ACCT = 'sduser'
ACCDIR = os.path.join(ROOT, 'user_accounts', ACCT)
PW, APW = 'Probe-Inhib-3x', 'Probe-Admin-9'
MARK = 'MASTERLOGIN-RAN'
ENV = dict(os.environ)
ENV.pop('SD_CONFIG', None)
fails = []


def winpath(p):
    return subprocess.run(['cygpath', '-w', p], capture_output=True, text=True).stdout.strip()


SCRAM = winpath(os.path.join(SD64, 'gplbld', 'scram-probe.py'))


def verdict(label, ok, why):
    print('  %s  %s  (%s)' % ('PASS' if ok else 'FAIL', label, why))
    if not ok:
        fails.append(label)


def show(out):
    for l in out.splitlines():
        print('      | ' + l)
    for p in (PW, APW):
        if p in out:
            fails.append('a password was echoed')


def lines(out):
    return [l.strip().lower() for l in out.splitlines() if l.strip()]


def landed(out):
    """True when the session answered WHERE with the account's own directory.  Solo reports @PATH tree-relative
    ('/user_accounts/sduser'), so the test is the ending; testing a full Windows path would pass the refusal
    case for the wrong reason (nothing is ever equal to it)."""
    return any(l.endswith('/user_accounts/' + ACCT) or l.endswith(chr(92) + 'user_accounts' + chr(92) + ACCT)
               for l in lines(out))


def sd_in(args, text):
    cmd = [SDEXE] + args
    print('\n    $ %s   [input: %d line(s), not shown]' % (' '.join(cmd), text.count('\n')))
    marker = None
    if args and args[0].lower() == '-internal':
        marker = os.path.join(SDSYS, '$internal')
        with open(marker, 'w', encoding='ascii', newline='\n') as f:
            f.write('probe-solo-inhibit pid=%d\n' % os.getpid())
    try:
        with tempfile.TemporaryFile() as tf:
            subprocess.run(cmd, env=ENV, input=text.encode('latin-1'),
                           stdout=tf, stderr=subprocess.STDOUT, timeout=60)
            tf.seek(0)
            out = tf.read().decode('latin-1').replace('\r', '')
    finally:
        if marker and os.path.exists(marker):
            os.remove(marker)
    show(out)
    return out


def scram(password, commands):
    cmd = ['py', '-3', SCRAM, '--user', ACCT, '--account', ACCT, '--'] + commands
    print('\n    $ %s   [SD_SCRAM_PASSWORD from the environment, not shown]' % ' '.join(cmd))
    env = dict(os.environ)
    env['SD_SCRAM_PASSWORD'] = password
    env['PYTHONIOENCODING'] = 'utf-8'
    r = subprocess.run(cmd, env=env, capture_output=True, timeout=90)
    out = (r.stdout + r.stderr).decode('latin-1').replace('\r', '')
    show(out)
    return out


class Held:
    """One session kept open on a pipe; its output goes to a file that is read back."""

    def __init__(self):
        fd, self.path = tempfile.mkstemp(prefix='probe-inhibit-held-', suffix='.txt')
        self.f = os.fdopen(fd, 'wb')
        print('\n    $ %s   [held session, output in %s]' % (SDEXE, self.path))
        self.p = subprocess.Popen([SDEXE], env=ENV, stdin=subprocess.PIPE, stdout=self.f, stderr=subprocess.STDOUT)

    def send(self, text):
        shown = text if (PW not in text and APW not in text) else '[password line, not shown]'
        print('      > ' + shown.strip())
        self.p.stdin.write(text.encode('latin-1'))
        self.p.stdin.flush()

    def text(self):
        self.f.flush()
        with open(self.path, 'rb') as r:
            return r.read().decode('latin-1').replace('\r', '')

    def wait_for(self, needle, count=1, timeout=45):
        end = time.time() + timeout
        while time.time() < end:
            if self.text().lower().count(needle.lower()) >= count:
                return True
            if self.p.poll() is not None:
                break
            time.sleep(0.4)
        return self.text().lower().count(needle.lower()) >= count

    def end(self):
        try:
            self.send('OFF\n')
            self.p.stdin.close()
        except Exception as e:  # noqa: BLE001 - reported, not hidden
            print('      (closing the held session: %s)' % e)
        try:
            self.p.wait(timeout=40)
            print('      held session ended, exit %s' % self.p.returncode)
        except subprocess.TimeoutExpired:
            print('      HELD SESSION DID NOT END IN 40 s - left for the final sd -stop (it is not killed here)')
            fails.append('the held session did not end')
        text = self.text()
        self.f.close()
        print('\n    the held session\'s whole output:')
        show(text)


def errlog_count():
    path = os.path.join(SDSYS, 'errlog')
    if not os.path.exists(path):
        return 0
    with open(path, 'rb') as f:
        return f.read().decode('latin-1').count(MARK)


def audit_text():
    path = os.path.join(SDSYS, 'audit')
    if not os.path.exists(path):
        return ''
    with open(path, 'rb') as f:
        return f.read().decode('latin-1').replace('\r', '')


def write_prog(name, body):
    with open(os.path.join(ACCDIR, 'bp', name), 'w', encoding='ascii', newline='\n') as f:
        f.write('\n'.join(body) + '\n')


print('inputs: sd.exe=%s exists=%s  account=%r  scram-probe=%s' % (SDEXE, os.path.isfile(SDEXE), ACCT, SCRAM))
if not os.path.isfile(SDEXE) or not os.path.isfile(os.path.join(SD64, 'gplbld', 'scram-probe.py')):
    print('REFUSING: no staged sd.exe or no scram-probe.py - nothing to measure')
    sys.exit(2)
os.makedirs(os.path.join(ROOT, 'sd-tls'), exist_ok=True)

B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)
B.sd(SDEXE, ENV, ['-start'])
held = None
try:
    print('\n== 0. the installer steps')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_account', ACCT], '\n')
    verdict('account made', any(l.startswith('solo account ready %s ' % ACCT) for l in lines(out)), 'SOLO ACCOUNT READY')
    sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ADMIN'], APW + '\n')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ACCOUNT', ACCT], PW + '\n')
    verdict('account password set', 'solo password set account' in lines(out), 'SOLO PASSWORD SET ACCOUNT')
    stored = os.path.join(SDSYS, '$cred', '$STORED')
    if os.path.exists(stored):
        os.remove(stored)

    # the two programs that edit the SDSYS VOC, compiled in the account
    write_prog('probemset', ["openpath @sdsys:@ds:'voc' to v else", "   crt 'MASTER.OPEN.FAILED'", '   stop', 'end',
                             "rec = 'PA' : @fm : 'LOGMSG %s'" % MARK,
                             "write rec on v, 'MASTER.LOGIN' on error", "   crt 'MASTER.WRITE.FAILED ' : status()", '   stop', 'end',
                             "crt 'MASTER.WRITTEN'", 'end'])
    write_prog('probemdel', ["openpath @sdsys:@ds:'voc' to v else", "   crt 'MASTER.OPEN.FAILED'", '   stop', 'end',
                             "delete v, 'MASTER.LOGIN'", "crt 'MASTER.DELETED'", 'end'])

    print('\n== 157. INHIBIT.LOGIN')
    held = Held()
    held.send(PW + '\n')
    held.send('ADMIN\n')
    held.send(APW + '\n')
    held.send('inhibit.login\n')
    ok = held.wait_for('logins are allowed', 1)
    verdict('the null case: with nothing set the administrator session is told logins are allowed', ok, 'Logins are allowed')
    held.send('inhibit.login on\n')
    held.send('inhibit.login\n')
    ok = held.wait_for('logins are inhibited by', 1)
    verdict('after ON the state reads inhibited, naming the setter', ok, 'Logins are inhibited by sduser (user n)')

    out = sd_in(['WHERE'], PW + '\n')
    verdict('a NEW session is refused with the refusal words',
            'not accepting new sessions' in out.lower() and '(inhibit.login)' in out.lower(),
            'SD is not accepting new sessions ... (inhibit.login)')
    verdict('and it is not landed in the account', not landed(out), 'no WHERE answer')
    au = audit_text().lower()
    hits = [l for l in au.splitlines() if 'inhibit.login' in l]
    print('  audit lines naming inhibit.login: %d' % len(hits))
    for l in hits[-4:]:
        print('      | ' + l[:200])
    verdict('the audit trail carries the refusal', any('logins are inhibited' in l for l in hits), 'reason=logins are inhibited (inhibit.login)')

    held.send('inhibit.login off\n')
    held.send('inhibit.login\n')
    ok = held.wait_for('logins are allowed', 2)
    verdict('after OFF the state reads allowed again', ok, 'a second "Logins are allowed"')
    out = sd_in(['WHERE'], PW + '\n')
    verdict('CONTROL: a NEW session now lands', landed(out), 'WHERE = the account dir')

    print('\n== 158. MASTER.LOGIN for an API session')
    held.send('BASIC bp probemset\n')
    held.send('BASIC bp probemdel\n')
    ok = held.wait_for('0 error(s)', 2)
    verdict('the two helper programs compile', ok, "two '0 error(s)'")
    held.send('RUN bp probemset\n')
    ok = held.wait_for('MASTER.WRITTEN', 1)
    verdict('the MASTER.LOGIN paragraph is written into the SDSYS VOC (as the administrator)', ok, 'MASTER.WRITTEN')
    n0 = errlog_count()
    out = sd_in(['WHERE'], PW + '\n')
    n1 = errlog_count()
    verdict('CONTROL: a new local session runs the paragraph once', n1 == n0 + 1 and landed(out),
            '%s lines in errlog: %d -> %d' % (MARK, n0, n1))
    out = scram(PW, ['WHERE'])
    n2 = errlog_count()
    verdict('the API login was VERIFIED', 'scram: server signature verified' in out.lower() and 'refused' not in out.lower(),
            'SCRAM: server signature VERIFIED')
    verdict('and the API session ran the paragraph, once', n2 == n1 + 1, '%s lines in errlog: %d -> %d' % (MARK, n1, n2))
finally:
    if held is not None:
        try:
            held.send('inhibit.login off\n')
            held.send('RUN bp probemdel\n')
            held.wait_for('MASTER.DELETED', 1, 30)
        finally:
            held.end()
    B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)

print('\nRESULT: %s' % ('ALL PASS' if not fails else 'FAILED: ' + '; '.join(fails)))
sys.exit(1 if fails else 0)
