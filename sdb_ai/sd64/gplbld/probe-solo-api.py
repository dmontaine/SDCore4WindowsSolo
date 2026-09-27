#!/usr/bin/env python3
# probe-solo-api.py - SOLO 3 step 5's smoke witness on a STAGED tree (MSYS2
# python3, unelevated), straight after stage.py --force --bootstrap, with no
# other SD running (machine-wide semaphores).  It sets TEST passwords in the
# stage and creates <stage>/SDCoreSolo/sd-tls, so run stage.py --force
# --bootstrap again before building an installer.
#   python3 gplbld/probe-solo-api.py <sd64 dir> <stage dir>
#
# What the retirements must not break, and what they must close:
#   1. a local one-shot session still lands with the account password;
#   2. an API login (gplbld/scram-probe.py, the real wire: TLS 1.3 + SCRAM)
#      is VERIFIED and serves WHO/WHERE; a wrong password is REFUSED;
#   3. "sd -N -H" - the pre-authenticated API session that skipped SCRAM - is
#      refused as an unrecognised argument and serves nothing.
# scram-probe.py runs under Windows Python (py -3) because it loads UCRT64's
# libssl by ctypes.  Every command line and raw output is printed; passwords
# never are.  Exit 0 only when every check passed.
import getpass
import os
import subprocess
import sys
import tempfile

SD64, STAGE = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(SD64, 'gplbld'))
import bootstrap as B  # noqa: E402

ROOT = os.path.join(STAGE, 'SDCoreSolo')
SDSYS = os.path.join(ROOT, 'sdsys')
SDEXE = os.path.join(ROOT, 'usr', 'bin', 'sd.exe')
ACCT = (os.environ.get('USERNAME', '') or getpass.getuser()).strip().lower()
ACCDIR = os.path.join(ROOT, 'user_accounts', ACCT)
PW, APW = 'Probe-Api-1x', 'Probe-Admin-7'
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


def sd_in(args, text):
    cmd = [SDEXE] + args
    print('\n    $ %s   [input: %d line(s), not shown]' % (' '.join(cmd), text.count('\n')))
    marker = None
    if args[0].lower() == '-internal':
        marker = os.path.join(SDSYS, '$internal')
        with open(marker, 'w', encoding='ascii', newline='\n') as f:
            f.write('probe-solo-api pid=%d\n' % os.getpid())
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
    env['PYTHONIOENCODING'] = 'utf-8'   # session output is not always cp1252
    r = subprocess.run(cmd, env=env, capture_output=True, timeout=90)
    out = (r.stdout + r.stderr).decode('latin-1').replace('\r', '')
    show(out)
    return out


def lines(out):
    return [l.strip().lower() for l in out.splitlines() if l.strip()]


print('inputs: sd.exe=%s exists=%s  account=%r  scram-probe=%s' % (SDEXE, os.path.isfile(SDEXE), ACCT, SCRAM))
if not os.path.isfile(SDEXE) or not ACCT or not os.path.isfile(os.path.join(SD64, 'gplbld', 'scram-probe.py')):
    print('REFUSING: no staged sd.exe, no user name or no scram-probe.py - nothing to measure')
    sys.exit(2)
os.makedirs(os.path.join(ROOT, 'sd-tls'), exist_ok=True)

B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)
B.sd(SDEXE, ENV, ['-start'])
try:
    print('\n== 0. the installer steps')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_account', ACCT], '\n')
    verdict('account made', any(l.startswith('solo account ready %s ' % ACCT) for l in lines(out)), 'SOLO ACCOUNT READY')
    sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ADMIN'], APW + '\n')
    out = sd_in(['-internal', 'RUN', 'gpl.bp', 'solo_password', 'ACCOUNT', ACCT], PW + '\n')
    verdict('account password set', 'solo password set account' in lines(out), 'SOLO PASSWORD SET ACCOUNT')
    stored = os.path.join(SDSYS, '$cred', '$STORED')
    if os.path.exists(stored):
        os.remove(stored)   # so leg 1 proves the password on input, not the kept copy
    print('  $STORED removed for leg 1: %s' % (not os.path.exists(stored)))

    print('\n== 1. a local one-shot session')
    out = sd_in(['WHERE'], PW + '\n')
    verdict('lands with the password', ACCDIR.lower() in lines(out), 'WHERE = the account dir')
    out = sd_in(['WHERE'], 'not-the-password\n')
    verdict('CONTROL: refused without it', 'wrong password' in out.lower() and ACCDIR.lower() not in lines(out), 'Wrong password')

    print('\n== 2. the API: TLS 1.3 + SCRAM, served by the front itself')
    out = scram(PW, ['WHO', 'WHERE'])
    verdict('API login VERIFIED', 'scram: server signature verified' in out.lower() and 'refused' not in out.lower(), 'SCRAM: server signature VERIFIED')
    verdict('and it serves WHERE', any(l.endswith('/user_accounts/' + ACCT) or l.endswith(chr(92) + 'user_accounts' + chr(92) + ACCT) for l in lines(out)), 'a WHERE line ending user_accounts/%s' % ACCT)
    out = scram('not-the-password', ['WHO'])
    verdict('CONTROL: wrong password REFUSED', 'scram: login refused at request' in out.lower() and 'verified' not in out.lower(), 'SCRAM: login REFUSED at request ...')

    print('\n== 3. sd -N -H, the pre-authenticated session, is gone')
    out = sd_in(['-N', '-H'], 'WHO\n')
    verdict('refused as unrecognised', "unrecognised argument '-h'" in out.lower(), "Unrecognised argument '-H'")
    verdict('and served nothing', not any(l.startswith('1 ') for l in lines(out)) and ACCDIR.lower() not in lines(out), 'no WHO/WHERE answer')

    print('\n== 4. the operating system from an API session (SOLO 3 step 5 E)')
    # WHOSE TOKEN.  PowerShell's own answers, NOT whoami.exe: in a session of
    # the staged tree a native .exe run from SH prints nothing, and in a pipe
    # PowerShell calls it "a document" (measured 26 Sep, pre-existing, not
    # this change's).  So: the token's name, and whether Administrators is
    # ENABLED in it (IsInRole(544) is False when it is deny-only or absent).
    # The integrity level is not readable this way and is not claimed here -
    # ruling 16's own witness read the daemon at Medium (SOLO 3).
    out = scram(PW, ['SH Write-Output ("TOKEN-NAME " + [Security.Principal.WindowsIdentity]::GetCurrent().Name)',
                     'SH Write-Output ("TOKEN-ADMIN " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(544))'])
    L = lines(out)
    me = (os.environ.get('USERNAME', '') or getpass.getuser()).strip().lower()
    names = [l for l in L if 'token-name ' in l]
    print('  expected user %r; token lines %r' % (me, names + [l for l in L if 'token-admin ' in l]))
    verdict('SH over the API runs as the user', any(l.endswith(chr(92) + me) for l in names), 'TOKEN-NAME <domain>\\%s' % me)
    verdict('with Administrators not enabled', any(l.endswith('token-admin false') for l in L), 'TOKEN-ADMIN False')
    # A USER PROGRAM'S OS.EXECUTE, the path op_sh.c's socket exception gates.
    src = '\n'.join(["os.execute 'Write-Output (\"OSX-RAN-\" + $env:USERNAME)' capturing o",
                     'crt "OSX " : change(o, @fm, " | ")', 'end', ''])
    with open(os.path.join(ACCDIR, 'bp', 'probeosx'), 'w', encoding='ascii', newline='\n') as f:
        f.write(src)
    out = sd_in(['BASIC', 'bp', 'probeosx'], PW + '\n')
    verdict('test program compiles', '0 error(s)' in lines(out), "want '0 error(s)'")
    out = scram(PW, ['RUN bp probeosx'])
    # scram-probe prints each response line as "| <line>".
    verdict('OS.EXECUTE from a user program over the API runs', any(l.startswith('| osx osx-ran-') for l in lines(out)) and 'not permitted' not in out.lower(), "a line '| OSX OSX-RAN-...', no 10054")
    out = sd_in(['RUN', 'bp', 'probeosx'], PW + '\n')
    verdict('CONTROL: the same program runs locally', any(l.startswith('osx osx-ran-') for l in lines(out)), "a line 'OSX OSX-RAN-<user>'")
finally:
    B.sd(SDEXE, ENV, ['-stop'], expect_fail=True)

print('\nRESULT: %s' % ('ALL PASS' if not fails else 'FAILED: ' + '; '.join(fails)))
sys.exit(1 if fails else 0)
