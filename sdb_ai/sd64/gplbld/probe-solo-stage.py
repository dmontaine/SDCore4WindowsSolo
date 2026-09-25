#
# probe-solo-stage.py - SOLO 2's witness: does a bootstrapped Solo tree find its
# own folders with NOTHING naming them?
#
# command line (MSYS2 python3, ELEVATED - the "sd -internal" sessions need it):
#   cd sdb_ai/sd64 && python3 gplbld/probe-solo-stage.py --stage <stage dir>
# Normally run by probe-solo-stage.ps1, straight after stage.py --bootstrap.
#
# WHAT IT MEASURES (SOLO 2, 25 Sep 2026).  gplsrc/inipath.c finds sd.conf, and
# config.c derives SDSYS, USRDIR and GRPDIR, from the folder two above sd.exe;
# stage.py ships an sd.conf with no path in it and an accounts/sdsys record of
# "@SDSYS".  So with SD_CONFIG REMOVED from the environment, the staged sd.exe
# must report paths inside the staged root:
#
#   CONFIG  USRDIR  = <root>\user_accounts     (config.c default)
#   CONFIG  GRPDIR  = <root>\group_accounts    (config.c default)
#   WHERE   @PATH   = <root>\sdsys             (login expanding @SDSYS)
#
# Each is anchored on the exact expected value, not on a word the failure also
# prints; "ProgramData", "not found" and "Cannot" disqualify; an empty session
# output fails rather than passing.  Inputs, the register record and the
# session output are printed in full every time.  Exit 0 only when every check
# passed.
#

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bootstrap as B  # noqa: E402  - sd(), the marker, the elevation test

BS = chr(92)
# 'has not been started' added after the first elevated run (25 Sep 2026)
# printed it for all three sessions: the bootstrap stops SD when it finishes.
DISQUALIFY = ['programdata', 'not found', 'cannot', 'has not been started']


def posixpath(winp):
    """The MSYS2 form of a Windows path - how SD prints @PATH, which comes
    from getcwd() (op_dio2.c: getcwd() -> /c/ProgramData/SD/sdsys)."""
    if os.name == 'nt':
        return winp
    return subprocess.run(['cygpath', '-u', winp],
                          capture_output=True, text=True).stdout.strip()


def winpath(p):
    """The Windows form of a path, as sd.exe will print it."""
    if os.name == 'nt':
        return os.path.abspath(p)
    return subprocess.run(['cygpath', '-w', os.path.abspath(p)],
                          capture_output=True, text=True).stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stage', required=True)
    args = ap.parse_args()

    root = os.path.join(args.stage, 'SDCoreSolo')
    sdsys = os.path.join(root, 'sdsys')
    sdexe = os.path.join(root, 'usr', 'bin', 'sd.exe')
    wroot = winpath(root)

    print('probe-solo-stage: inputs')
    print('  stage root   %s' % wroot)
    print('  sd.exe       %s  exists=%s' % (winpath(sdexe), os.path.isfile(sdexe)))
    print('  elevated     %s' % B.is_elevated())
    fails = []

    if not os.path.isfile(sdexe) or not os.path.isdir(sdsys):
        print('  FAIL  no staged tree at %s - nothing to measure' % wroot)
        return 1
    # 25 Sep 26 - SOLO 4: elevation is not required any more; printed above.

    env = dict(os.environ)
    env.pop('SD_CONFIG', None)
    print('  SD_CONFIG    removed from the environment (was %r)'
          % os.environ.get('SD_CONFIG'))

    conf = os.path.join(root, 'sd.conf')
    with open(conf, encoding='latin-1') as f:
        lines = [l.strip() for l in f]
    named = [l for l in lines if l.split('=')[0] in ('SDSYS', 'USRDIR', 'GRPDIR',
                                                    'DUMPDIR')]
    print('  sd.conf      %d lines; path settings: %s' % (len(lines), named or 'none'))
    if named:
        fails.append('sd.conf still names %s' % named)

    rec = os.path.join(sdsys, 'accounts', 'sdsys')
    with open(rec, 'rb') as f:
        field1 = f.read().decode('latin-1').split('\n')[0]
    print('  accounts/sdsys field 1 = %r' % field1)
    if field1 != '@SDSYS':
        fails.append('accounts/sdsys field 1 is %r, not @SDSYS' % field1)

    B.INTERNAL_MARKER_DIR = sdsys
    expect = [
        (['-internal', 'CONFIG'], 'USRDIR', wroot + BS + 'user_accounts'),
        (['-internal', 'CONFIG'], 'GRPDIR', wroot + BS + 'group_accounts'),
        (['-internal', 'WHERE'], None, wroot + BS + 'sdsys'),
    ]
    # SD MUST BE RUNNING, and starting it is itself a check: the daemon reads
    # sd.conf through GetConfigPath() with SD_CONFIG gone.  bootstrap.py stops
    # SD when it finishes, so the first version of this probe asked a stopped
    # system and got "SD has not been started" three times.  Stopped again in
    # the finally, whatever happens.
    print('\nsession: sd -start')
    try:
        B.sd(sdexe, env, ['-stop'], expect_fail=True)
        B.sd(sdexe, env, ['-start'])  # dies, non-zero, if SD will not start
        return finish(sdexe, sdsys, env, expect, fails)
    finally:
        print('\nsession: sd -stop')
        B.sd(sdexe, env, ['-stop'], expect_fail=True)


def finish(sdexe, sdsys, env, expect, fails):
    outputs = {}
    for cmd, key, want in expect:
        k = ' '.join(cmd)
        if k not in outputs:
            print('\nsession: sd %s' % k)
            outputs[k] = B.sd(sdexe, env, cmd, expect_fail=True)
        out = outputs[k]
        if not out.strip():
            fails.append('sd %s printed nothing' % k)
            continue
        bad = [d for d in DISQUALIFY if d in out.lower()]
        if key:
            got = [l.split(None, 1)[1].strip() for l in out.splitlines()
                   if l.startswith(key + ' ') and len(l.split(None, 1)) == 2]
        else:
            got = [l.strip() for l in out.splitlines() if l.strip()]
        # A WHOLE line must equal the expected path, in either spelling: run 3
        # (25 Sep 2026) printed @PATH as /c/.../SDCoreSolo/sdsys, which is the
        # right folder in getcwd()'s form, and the Windows-only match failed it.
        wants = {want.lower()} if key else {want.lower(), posixpath(want).lower()}
        ok = any(g.lower() in wants for g in got) and not bad
        print('  %s  %s: want %s' % ('PASS' if ok else 'FAIL', key or '@PATH', want))
        print('        got  %s%s' % (got, ('  DISQUALIFIED by %s' % bad) if bad else ''))
        if not ok:
            fails.append('%s is not %s' % (key or '@PATH', want))

    solo4(sdexe, sdsys, env, fails)

    print()
    if fails:
        for f in fails:
            print('  FAILED: %s' % f)
        print('probe-solo-stage: %d check(s) FAILED' % len(fails))
        return 1
    print('probe-solo-stage: all checks passed')
    return 0


def solo4(sdexe, sdsys, env, fails):
    """SOLO 4's legs (25 Sep 2026): the one account, the closed internal door,
    SDSYS not a target, and the shell open to the user.

    Each leg anchors on text that appears only on its own outcome: a WHOLE line
    for a success, the refusal's own message for a refusal - and a refusal leg
    also fails if the success value appears.  The raw output of every session
    is printed by bootstrap.sd() whatever the verdict."""
    # getpass, not USERNAME: an MSYS2 login shell does not pass USERNAME on
    # (measured 25 Sep 2026 - the guard below caught it), but sets USER.
    import getpass
    user = (os.environ.get('USERNAME', '') or getpass.getuser() or '').strip()
    acct = user.lower()
    print('\n== SOLO 4 legs, Windows user %r, account %r' % (user, acct))
    if not acct:
        fails.append('USERNAME is empty - no account to create or enter')
        return
    root = os.path.dirname(sdsys)
    accdir = winpath(os.path.join(root, 'user_accounts', acct))
    sdsysdir = winpath(sdsys)
    refused = 'Connection terminated'

    def run(label, args, marker):
        print('\nsession (%s): sd %s   [marker %s]'
              % (label, ' '.join(args), 'written' if marker else 'NOT written'))
        B.INTERNAL_MARKER_DIR = sdsys if marker else None
        try:
            return B.sd(sdexe, env, args, expect_fail=True)
        finally:
            B.INTERNAL_MARKER_DIR = sdsys

    def lines(out):
        return [l.strip().lower() for l in out.splitlines() if l.strip()]

    def verdict(label, ok, why):
        print('  %s  %s  (%s)' % ('PASS' if ok else 'FAIL', label, why))
        if not ok:
            fails.append('%s: %s' % (label, why))

    # 1. The installer's step: create the account for this Windows user.
    out = run('account', ['-internal', 'RUN', 'gpl.bp', 'solo_account', user], True)
    want = 'solo account ready %s ' % acct
    ok = any(l.startswith(want) for l in lines(out))
    verdict('solo_account creates the account', ok, 'want a line starting %r' % want)

    # 2. An ordinary "sd", no marker, no -internal: lands in that account.
    out = run('login', ['WHERE'], False)
    wants = {accdir.lower(), posixpath(accdir).lower()}
    ok = bool(wants & set(lines(out))) and refused.lower() not in out.lower()
    verdict('plain sd lands in the user account', ok, 'want a line %s' % sorted(wants))

    # 3. The internal door with NO marker must stay shut (ruling 13).
    out = run('door', ['-internal', 'WHERE'], False)
    leaked = {sdsysdir.lower(), posixpath(sdsysdir).lower()} & set(lines(out))
    ok = refused.lower() in out.lower() and not leaked and \
        'internal session admitted' not in out.lower()
    verdict('sd -internal without a marker is refused', ok,
            'want %r and no SDSYS path' % refused)

    # 4. SDSYS is not a login target (ruling 11).
    out = run('sdsys', ['-ASDSYS', 'WHERE'], False)
    leaked = {sdsysdir.lower(), posixpath(sdsysdir).lower()} & set(lines(out))
    ok = refused.lower() in out.lower() and not leaked
    verdict('sd -ASDSYS is refused', ok, 'want %r and no SDSYS path' % refused)

    # 5. The shell is the user's (os.users gone).  6*7 is typed, 42 is not.
    out = run('shell', ['SH', '6*7'], False)
    ok = '42' in lines(out) and refused.lower() not in out.lower() and \
        'not permitted' not in out.lower()
    verdict('SH runs for the user', ok, "want a line '42'")


if __name__ == '__main__':
    sys.exit(main())
