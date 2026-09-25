#
# probe-solo-dropadmin.py - SOLO 3, ruling 16: the SD legs of the elevated
# witness.  Driven by probe-solo-dropadmin.ps1, which reads the daemon's token
# in between (Python cannot); not normally run by hand.
#
#   python3 gplbld/probe-solo-dropadmin.py --stage <dir> start|sessions|stop
#
#   start     sd -stop, then sd -start - from the ELEVATED caller, so -START must
#             re-launch on a standard token (win32token.c).
#   sessions  SH whoami /groups in a session WITH SSH_CONNECTION set (must be
#             Medium, Administrators deny-only), and WITHOUT it (a local
#             elevated console, left alone by the ruling: must stay High -
#             the control that proves the first leg measured the drop and not
#             a window that was never elevated).
#   stop      sd -stop.
#
# Anchored on whoami's own lines, never on text the command line carries.
# Exit 0 only when every leg of the chosen step passed.
#

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bootstrap as B  # noqa: E402

HIGH = 'mandatory label\\high mandatory level'
MEDIUM = 'mandatory label\\medium mandatory level'


def token_of(out):
    """(integrity, Administrators attributes) from whoami /groups /fo list."""
    lines = [l.strip() for l in out.splitlines()]
    integ = next((l for l in lines if 'mandatory label' in l.lower()), '')
    admin = ''
    for i, l in enumerate(lines):
        if l.lower().replace(' ', '') == 'sid:s-1-5-32-544':
            for m in lines[i + 1:i + 3]:
                if m.lower().startswith('attributes:'):
                    admin = m.split(':', 1)[1].strip()
    return integ, admin


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stage', required=True)
    ap.add_argument('step', choices=['start', 'sessions', 'stop'])
    a = ap.parse_args()

    root = os.path.join(a.stage, 'SDCoreSolo')
    sdexe = os.path.join(root, 'usr', 'bin', 'sd.exe')
    env = dict(os.environ)
    env.pop('SD_CONFIG', None)
    env.pop('SSH_CONNECTION', None)
    env.pop('SD_TOKEN_FILTERED', None)
    print('probe-solo-dropadmin %s: sd.exe %s exists=%s elevated=%s'
          % (a.step, sdexe, os.path.isfile(sdexe), B.is_elevated()))
    if not os.path.isfile(sdexe):
        print('  FAIL  no staged tree')
        return 1
    if not B.is_elevated():
        print('  FAIL  not elevated - this measures what happens to an ADMIN token')
        return 1

    fails = 0
    if a.step == 'start':
        B.sd(sdexe, env, ['-stop'], expect_fail=True)
        out = B.sd(sdexe, env, ['-start'], expect_fail=True)
        ok = 'has been started' in out.lower() and 'administrator token' not in out.lower()
        print('  %s  sd -start from the elevated window started SD' % ('PASS' if ok else 'FAIL'))
        fails += not ok
    elif a.step == 'stop':
        B.sd(sdexe, env, ['-stop'], expect_fail=True)
    else:
        ssh = dict(env)
        ssh['SSH_CONNECTION'] = '127.0.0.1 50000 127.0.0.1 22'
        print('\nsession WITH SSH_CONNECTION (as sshd would start it):')
        out = B.sd(sdexe, ssh, ['SH', 'whoami', '/groups', '/fo', 'list'], expect_fail=True)
        integ, admin = token_of(out)
        print('    integrity: %r   Administrators: %r' % (integ, admin))
        ok = integ.lower().endswith(MEDIUM) and 'deny only' in admin.lower()
        print('  %s  an ssh session runs on a standard token' % ('PASS' if ok else 'FAIL'))
        fails += not ok

        print('\nCONTROL: session WITHOUT SSH_CONNECTION (a local elevated console):')
        out = B.sd(sdexe, env, ['SH', 'whoami', '/groups', '/fo', 'list'], expect_fail=True)
        integ, admin = token_of(out)
        print('    integrity: %r   Administrators: %r' % (integ, admin))
        ok = integ.lower().endswith(HIGH) and 'enabled group' in admin.lower()
        print('  %s  a local elevated console is left alone (and the window really is elevated)'
              % ('PASS' if ok else 'FAIL'))
        fails += not ok

    print('probe-solo-dropadmin %s: %s' % (a.step, 'PASS' if fails == 0 else '%d FAILED' % fails))
    return 0 if fails == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
