"""test-uninstallkeep-units.py - the installer may delete the user's data in ONE place, behind two guards.

    python test-uninstallkeep-units.py

Exit 0 all checks passed, 1 a check failed, 2 the guard could not run.  No install, no VM, no elevation.

WHY IT EXISTS (SOLO 37, 6 Oct 2026).  PROJECT_STATUS 5.9.1 (14 Aug 2026) decided that the default must keep the
user's data, that removing it is a separate opt-in choice naming exactly what it destroys and where, and that a
SILENT uninstall must never delete it.  It was never built; SOLO 37 builds it, with SD Core for Linux Solo's shape:
Keep leaves the account and sd.conf and removes the rest, Delete removes the folder.  The multi-user product's
2 Sep 2026 incident - the data gone while the owner believed he had kept it - is the failure this stops: a reversed
Keep/Delete pair, a delete reachable without the question, a Keep that deletes the account.

THE RULES IT CHECKS, read from sd-solo.iss itself, never from a copy:
  1. OfferDataRemoval asks only when the uninstall is not silent, and the delete-everything call comes after the
     answer was tested and the Keep branch has Exit-ed.
  2. KeepOrDelete lists Keep first and Delete second, and answers "Delete" only when the dialog returned IDNO - the
     focus follows the first label, so Keep is the default and the inversion lives in one place.
  3. RemoveFolderContents is called from OfferDataRemoval and KeepDataOnly and nowhere else, and DelTree( is called
     only inside RemoveFolderContents - so no other path deletes a tree.
  4. KeepDataOnly keeps user_accounts, sduser and sd.conf, so Keep cannot take the account.
  5. Reload (PrepareToInstall) MOVES the old folder (MoveFileW) and calls nothing that deletes.
  6. The delete helper refuses a reparse point (0x400), so a junction cannot lead it out of the folder.

THE NULL CASE IS REFUSED: a file without these routines is exit 2, not a pass; and MUTANTS (guard removed, labels
swapped, a DelTree in PrepareToInstall, the keep list emptied, the reparse check removed) must each be flagged,
or the checker is not looking at anything.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOLO = os.path.join(HERE, 'sd-solo.iss')

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


def body(text, kind, name):
    """The text of `procedure name` / `function name` up to its closing 'end;' at column 0, or ''."""
    m = re.search(r'(?ms)^' + kind + r'\s+' + re.escape(name) + r'\b.*?^end;', text)
    return m.group(0) if m else ''


def strip_comments(t):
    t = re.sub(r'(?s)\{.*?\}', '', t)
    t = re.sub(r'(?s)\(\*.*?\*\)', '', t)
    return t


def violations(text):
    bad = []
    offer = strip_comments(body(text, 'procedure', 'OfferDataRemoval'))
    kod = strip_comments(body(text, 'function', 'KeepOrDelete'))
    helper = strip_comments(body(text, 'function', 'RemoveFolderContents'))
    # KeepDataOnly retries KeepDataPass (9 Oct 2026: a delete held for an instant is not a file that cannot be
    # removed), so the Keep deletions live in the pair; every rule below reads them together.
    keep = strip_comments(body(text, 'function', 'KeepDataPass')) + strip_comments(body(text, 'function', 'KeepDataOnly'))
    prep = strip_comments(body(text, 'function', 'PrepareToInstall'))
    code = strip_comments(text)

    # 1. asked only when not silent; the delete-everything call is after the Keep branch's Exit
    ask = offer.find('KeepOrDelete(')
    guard = re.search(r'if\s+not\s+UninstallSilent\s+then\s+ChoseDelete\s*:=\s*KeepOrDelete\(', offer)
    if ask < 0 or not guard:
        bad.append('OfferDataRemoval: KeepOrDelete is not behind "if not UninstallSilent"')
    wipe = offer.find("RemoveFolderContents(Root, '|', '|')")
    ex = offer.find('Exit;')
    test = offer.find('if not ChoseDelete')
    if wipe < 0 or ex < 0 or test < 0 or not (test < ex < wipe):
        bad.append('OfferDataRemoval: the delete-everything call is not after the Keep branch has Exit-ed')
    # 2. Keep first, Delete second, Delete = IDNO
    lab = re.findall(r"Labels\[(\d)\]\s*:=\s*'([A-Za-z]+)'", kod)
    if lab != [('0', 'Keep'), ('1', 'Delete')]:
        bad.append('KeepOrDelete: labels are not Keep (0) then Delete (1): ' + str(lab))
    if not re.search(r'=\s*IDNO\s*;', kod):
        bad.append('KeepOrDelete: does not answer Delete only on IDNO')
    # 3. callers of the helper, and the one place DelTree( lives
    decl = len(re.findall(r'function\s+RemoveFolderContents\(', code))
    calls = len(re.findall(r'RemoveFolderContents\(', code)) - decl
    in_offer_keep = len(re.findall(r'RemoveFolderContents\(', offer)) + len(re.findall(r'RemoveFolderContents\(', keep))
    if calls != in_offer_keep:
        bad.append('RemoveFolderContents is called outside OfferDataRemoval and KeepDataOnly (' + str(calls) + ' calls, ' + str(in_offer_keep) + ' there)')
    deltrees = len(re.findall(r'\bDelTree\(', code))
    deltrees_in_helper = len(re.findall(r'\bDelTree\(', helper))
    if deltrees != deltrees_in_helper or deltrees == 0:
        bad.append('DelTree( is called outside RemoveFolderContents (' + str(deltrees) + ' calls, ' + str(deltrees_in_helper) + ' inside it)')
    # 4. Keep cannot take the account or sd.conf
    if "'|user_accounts|'" not in keep or '|sd.conf|' not in keep or "'|sduser|'" not in keep:
        bad.append('KeepDataOnly: the keep lists do not name user_accounts, sduser and sd.conf')
    # 5. reload moves, never deletes
    if 'MoveFileW(' not in prep:
        bad.append('PrepareToInstall: the kept data is not moved with MoveFileW')
    if re.search(r'\b(DelTree|DeleteFile|RemoveDir|RemoveFolderContents|KeepDataOnly)\(', prep):
        bad.append('PrepareToInstall deletes something')
    # 6. a reparse point is refused
    if '$400' not in helper:
        bad.append('RemoveFolderContents: no reparse-point check')
    return bad


print('test-uninstallkeep-units: ' + SOLO)
if not os.path.isfile(SOLO):
    print('test-uninstallkeep-units: no ' + SOLO)
    sys.exit(2)
with open(SOLO, 'rb') as fh:
    text = fh.read().decode('utf-8', 'replace')

for kind, need in (('procedure', 'OfferDataRemoval'), ('function', 'KeepOrDelete'), ('function', 'RemoveFolderContents'),
                   ('function', 'KeepDataPass'), ('function', 'KeepDataOnly'), ('function', 'PrepareToInstall')):
    if not body(text, kind, need):
        print('test-uninstallkeep-units: VOID - no ' + need + ' found; the parse measured nothing.')
        sys.exit(2)

v = violations(text)
check('the installer deletes only behind the silent guard, Keep-first, Keep keeps the account, reload moves', not v, '; '.join(v))

# MUTANTS, each of which must be flagged.
m1 = text.replace('UninstallSilent', 'Uninstall_Silent')
check('CONTROL: mutation 1 changed the text', m1 != text)
check('MUTANT: no UninstallSilent guard is flagged', any('UninstallSilent' in x for x in violations(m1)))

m2 = text.replace("Labels[0] := 'Keep';", "Labels[0] := 'Delete';").replace("Labels[1] := 'Delete';", "Labels[1] := 'Keep';", 1)
check('CONTROL: mutation 2 changed the text', m2 != text)
check('MUTANT: Delete first is flagged', any('labels' in x for x in violations(m2)))

m3 = text.replace('if KeptWasFound then\n  begin\n    KeptFolder :=', 'if KeptWasFound then\n  begin\n    DelTree(SoloRoot, True, True, True);\n    KeptFolder :=', 1)
check('CONTROL: mutation 3 changed the text', m3 != text)
check('MUTANT: a DelTree in the reload path is flagged', any(('PrepareToInstall' in x) or ('outside' in x) for x in violations(m3)))

m4 = text.replace('$400', '$0')
check('CONTROL: mutation 4 changed the text', m4 != text)
check('MUTANT: no reparse-point check is flagged', any('reparse' in x for x in violations(m4)))

m5 = text.replace("RemoveFolderContents(Root, '|user_accounts|', '|sd.conf|.sdcore-kept|')", "RemoveFolderContents(Root, '|', '|')")
check('CONTROL: mutation 5 changed the text', m5 != text)
check('MUTANT: a Keep that keeps nothing is flagged', any('keep lists' in x for x in violations(m5)))

print('')
if passed == 0:
    print('test-uninstallkeep-units: VOID - no check ran.')
    sys.exit(2)
if failed:
    print('test-uninstallkeep-units: FAILED - %d passed, %d failed.' % (passed, failed))
    sys.exit(1)
print('test-uninstallkeep-units: PASSED - %d of %d checks passed.' % (passed, passed))
sys.exit(0)
