"""test-finishfail-units.py - the installer's finish page must not say "finished installing" after a failed step.

    python test-finishfail-units.py

Exit 0 all checks passed, 1 a check failed, 2 the guard could not run.  No install, no VM, no elevation.

WHY IT EXISTS (SOLO 39, 6 Oct 2026).  On a standard Windows account the machine step failed, the installer showed
"These steps did not complete: startup task", and the page behind it - once the owner clicked OK - still said
"Setup has finished installing SD Core Solo for Windows on your computer".  The dialog is a MsgBox shown from
CurStepChanged; the finish page's text is Inno's default, and nothing carried the failure to it.  SOLO 39 carries the
dialog's list in StepsNotCompleted to CurPageChanged, which replaces the heading and the text on the finish page.

THE RULES IT CHECKS, read from sd-solo.iss itself, never from a copy:
  1. StepsNotCompleted is declared BEFORE CurPageChanged (Pascal needs the name first, and CurPageChanged comes
     before CurStepChanged in the file - a declaration after it is a compile error the owner finds in a cycle).
  2. CurStepChanged assigns it from Failed UNCONDITIONALLY and after the last step has added to Failed, so a clean
     install leaves it empty and a failed one carries every step.
  3. CurPageChanged changes the finish page only on wpFinished AND a non-empty StepsNotCompleted - a clean install's
     page is untouched - and sets BOTH the heading and the text, with the list, the log path and "Click Finish".
  4. That replacement comes BEFORE the sentences CurPageChanged appends (control file, kept folder), so they are
     added to it and not overwritten by it.
  5. The dialog is still shown, with its old wording, and the failure is logged.
  6. The label is fitted (AdjustHeight) on the finish page AFTER the last caption is set: it is only as tall as Inno's
     short default text, and the first try's last line was cut off in the guest - as the SOLO 36/37 sentences would be.

THE NULL CASE IS REFUSED: a file without these routines is exit 2, not a pass; and MUTANTS (the assignment removed,
the declaration moved after CurPageChanged, the non-empty condition dropped, the replacement moved after the appends,
only the text and not the heading) must each be flagged, or the checker is not looking at anything.
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
    """A list of the rules this text breaks.  An empty list means it keeps all of them."""
    bad = []
    code = strip_comments(text)
    page = strip_comments(body(text, 'procedure', 'CurPageChanged'))
    step = strip_comments(body(text, 'procedure', 'CurStepChanged'))

    # 1. declared before CurPageChanged
    decl = re.search(r'(?m)^\s*StepsNotCompleted\s*:\s*String\s*;', code)
    page_at = re.search(r'(?m)^procedure\s+CurPageChanged\b', code)
    if not decl:
        bad.append('StepsNotCompleted is not declared as a String')
    elif not page_at or decl.start() > page_at.start():
        bad.append('StepsNotCompleted is declared AFTER CurPageChanged (a compile error: the name is used first)')

    # 2. assigned from Failed, unconditionally, after the last addition to Failed
    assign = [m.start() for m in re.finditer(r'(?m)^\s*StepsNotCompleted\s*:=\s*Failed\s*;', step)]
    last_add = [m.start() for m in re.finditer(r'Failed\s*:=\s*Failed\s*\+', step)]
    if len(assign) != 1:
        bad.append('CurStepChanged does not assign StepsNotCompleted := Failed exactly once (%d times)' % len(assign))
    else:
        if last_add and assign[0] < max(last_add):
            bad.append('StepsNotCompleted is assigned BEFORE the last step has added to Failed')
        before = step[:assign[0]]
        # unconditional = not the single statement of an if/else just above it
        tail = before.rstrip().splitlines()[-1] if before.strip() else ''
        if re.match(r'\s*(if|else)\b', tail) and not tail.rstrip().endswith(';'):
            bad.append('the assignment is the body of an if/else, so a clean install would keep an old value')

    # 3. the finish page: wpFinished and non-empty, heading AND text, list + log path + Click Finish
    blk = re.search(r'(?s)if\s*\(CurPageID\s*=\s*wpFinished\)\s*and\s*\(StepsNotCompleted\s*<>\s*\'\'\)\s*then\s*begin(.*?)\bend;', page)
    if not blk:
        bad.append("CurPageChanged has no 'if (CurPageID = wpFinished) and (StepsNotCompleted <> '') then begin ... end;'")
    else:
        b = blk.group(1)
        if 'FinishedHeadingLabel.Caption' not in b:
            bad.append('the finish page heading is not changed (it would still read "Completing the ... Setup Wizard")')
        if 'FinishedLabel.Caption' not in b:
            bad.append('the finish page text is not changed')
        if 'StepsNotCompleted' not in b:
            bad.append('the finish page text does not carry the list of steps')
        if 'install-summary.log' not in b:
            bad.append('the finish page text does not name install-summary.log')
        if 'Click Finish' not in b:
            bad.append('the finish page text lost "Click Finish to exit Setup."')
        if 'did not complete' not in b:
            bad.append('the finish page text does not say a step did not complete')
        # 4. before the appended sentences
        first_append = re.search(r'FinishedLabel\.Caption\s*:=\s*WizardForm\.FinishedLabel\.Caption\s*\+', page)
        if first_append and blk.start() > first_append.start():
            bad.append('the replacement comes AFTER the sentences that are appended to the page, and would overwrite them')

    # 4b. the label is fitted AFTER the last caption is set: it is only as tall as Inno's short default text, and the
    # first try's last line ("Click Finish to exit Setup.") was cut off at the bottom in the guest.
    fit = re.search(r'(?m)^\s*WizardForm\.FinishedLabel\.AdjustHeight\s*;', page)
    last_caption = [m.start() for m in re.finditer(r'FinishedLabel\.Caption\s*:=', page)]
    if not fit:
        bad.append('the finish page label is not fitted (AdjustHeight): a longer text is clipped at the bottom')
    elif last_caption and fit.start() < max(last_caption):
        bad.append('the label is fitted BEFORE the last caption is set, so the later text is still clipped')
    elif not re.search(r'if\s+CurPageID\s*=\s*wpFinished\s+then\s*\n\s*WizardForm\.FinishedLabel\.AdjustHeight', page):
        bad.append('the fit is not limited to the finish page')

    # 5. the dialog and the log
    if "MsgBox('These steps did not complete:'" not in step:
        bad.append('the failure dialog is gone or its wording changed')
    if "Log('SD Core Solo: steps not completed: '" not in step:
        bad.append('the failure is not written to the setup log')

    # 7. SOLO 90 (sit12, 21 Nov 26): a clean install's page says what happened and where to start it, not Inno's stock "The application
    # may be launched by selecting the installed shortcuts"; the shortcut it names is the [Icons] one.
    msgs = re.search(r'(?ms)^\[Messages\]\s*\n(.*?)(?=^\[)', text)
    ms = msgs.group(1) if msgs else ''
    fl = re.search(r'(?m)^FinishedLabel=(.*)$', ms)
    fn = re.search(r'(?m)^FinishedLabelNoIcons=(.*)$', ms)
    icon = re.search(r'(?m)^Name:\s*"\{userprograms\}\\([^"]+)"', text)
    if not fl or 'SD Core Solo is installed.' not in fl.group(1):
        bad.append('[Messages] FinishedLabel is not a plain result line ("SD Core Solo is installed.")')
    elif not icon or ('Start menu: ' + icon.group(1).strip() + '.') not in fl.group(1).replace('%n', ' '):
        bad.append('the finish text does not name the Start menu shortcut of [Icons]')
    if not fn or 'SD Core Solo is installed.' not in fn.group(1):
        bad.append('[Messages] FinishedLabelNoIcons is not a plain result line')

    # 8. SOLO 88 (sit12, 21 Nov 26): a user who cannot elevate is refused at the START, before anything is sampled or written; the test is
    # membership of Administrators (IsAdmin, Inno 6's name for IsAdminLoggedOn: a split-token administrator is NOT elevated, so the
    # elevation test, IsAdminInstallMode, would refuse them - it is False under PrivilegesRequired=lowest),
    # and the box is suppressible so a silent install does not wait for a click.
    init = strip_comments(body(text, 'function', 'InitializeSetup'))
    m8 = re.search(r'(?s)if\s+not\s+IsAdmin\s+then\s*begin(.*?)\bend;', init)
    if not m8:
        bad.append('InitializeSetup has no "if not IsAdmin then begin ... end;" refusal (a standard account would get as far as the elevation prompt)')
    else:
        r = m8.group(1)
        if 'SuppressibleMsgBox' not in r or 'Result := False' not in r or 'Exit;' not in r:
            bad.append('the administrator refusal does not show a suppressible box and stop (Result := False; Exit;)')
        if "Log('SD Core Solo: NOT INSTALLED" not in r:
            bad.append('the administrator refusal is not written to the setup log')
        if m8.start() > init.find('DataTreeWasAbsent :=') or m8.start() > init.find('LoadControlFile'):
            bad.append('the administrator refusal comes AFTER the first sampling or the control file is read (it must be the start)')
    return bad


def mutate(text, what):
    """A copy of the text with one rule broken, for the checker to catch."""
    if what == 'no assignment':
        return text.replace('  StepsNotCompleted := Failed;\n', '', 1)
    if what == 'declared late':
        # take the declaration out of the top var block and put a copy just before CurStepChanged (after CurPageChanged)
        t = text.replace('  StepsNotCompleted: String;\n', '', 1)
        return re.sub(r'(?m)^(procedure CurStepChanged)', 'var\n  StepsNotCompleted: String;\n\n\\1', t, count=1)
    if what == 'no empty test':
        return text.replace("(CurPageID = wpFinished) and (StepsNotCompleted <> '')", '(CurPageID = wpFinished)', 1)
    if what == 'text only':
        return text.replace("    WizardForm.FinishedHeadingLabel.Caption := 'Setup finished with problems';\n", '', 1)
    if what == 'no log path':
        return text.replace("'Details: ' + ExpandConstant('{app}\\install-summary.log') + #13#10#13#10 + 'Click Finish to exit Setup.'",
                            "'Click Finish to exit Setup.'", 1)
    if what == 'after the appends':
        m = re.search(r"(?s)(  \{ SOLO 39: a step that did not complete.*?\n  end;\n)", text)
        if not m:
            return text
        blk = m.group(1)
        t = text.replace(blk, '', 1)
        return t.replace('  { SOLO 37: where the old folder went.', blk + '  { SOLO 37: where the old folder went.', 1)
    if what == 'dialog gone':
        return text.replace("MsgBox('These steps did not complete:'", "MsgBox('Steps failed:'", 1)
    if what == 'stock finish text':
        return text.replace('FinishedLabel=SD Core Solo is installed.%nStart it from the Start menu: SD Core Solo.\n', '', 1)
    if what == 'wrong shortcut':
        return text.replace('Start it from the Start menu: SD Core Solo.', 'Start it from the Start menu: SD Core.', 1)
    if what == 'no icon-less text':
        return text.replace('FinishedLabelNoIcons=SD Core Solo is installed.\n', '', 1)
    if what == 'no admin test':
        return text.replace('  if not IsAdmin then\n', '  if False then\n', 1)
    if what == 'elevated only':
        return text.replace('  if not IsAdmin then\n', '  if not IsAdminInstallMode then\n', 1)
    if what == 'admin test late':
        t = text.replace('  if not IsAdmin then\n', '  if False then\n', 1)
        return t.replace('  GlobalWasFound := FileExists(SoloRoot', '  if not IsAdmin then\n  begin\n    Result := False;\n    Exit;\n  end;\n  GlobalWasFound := FileExists(SoloRoot', 1)
    if what == 'blocking box':
        return text.replace("    SuppressibleMsgBox('SD Core Solo was not installed.' + #13#10#13#10 + 'Sign in with", "    MsgBox('SD Core Solo was not installed.' + #13#10#13#10 + 'Sign in with", 1)
    if what == 'no fit':
        return text.replace('  if CurPageID = wpFinished then\n    WizardForm.FinishedLabel.AdjustHeight;\n', '', 1)
    if what == 'fit too early':
        t = text.replace('  if CurPageID = wpFinished then\n    WizardForm.FinishedLabel.AdjustHeight;\n', '', 1)
        return t.replace('  { A control file with no global password leaves this computer NOT managed -',
                         '  if CurPageID = wpFinished then\n    WizardForm.FinishedLabel.AdjustHeight;\n  { A control file with no global password leaves this computer NOT managed -', 1)
    raise ValueError(what)


def main():
    if not os.path.exists(SOLO):
        print('NO TREE: ' + SOLO + ' missing')
        return 2
    with open(SOLO, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    for kind, name in (('procedure', 'CurPageChanged'), ('procedure', 'CurStepChanged')):
        if not body(text, kind, name):
            print('NO ROUTINE: ' + kind + ' ' + name + ' not found in sd-solo.iss - the guard has nothing to look at')
            return 2

    print('sd-solo.iss: ' + SOLO)
    bad = violations(text)
    check('the installer carries a failed step to the finish page, and a clean install leaves it alone', not bad,
          '; '.join(bad))

    print('--- mutants: each must be flagged')
    for what, expect in (
            ('no assignment', 'exactly once'),
            ('declared late', 'AFTER CurPageChanged'),
            ('no empty test', "has no 'if (CurPageID = wpFinished)"),
            ('text only', 'heading is not changed'),
            ('no log path', 'install-summary.log'),
            ('after the appends', 'AFTER the sentences'),
            ('dialog gone', 'dialog is gone'),
            ('no fit', 'is not fitted'),
            ('fit too early', 'fitted BEFORE'),
            ('stock finish text', 'FinishedLabel is not a plain result line'),
            ('wrong shortcut', 'does not name the Start menu shortcut'),
            ('no icon-less text', 'FinishedLabelNoIcons'),
            ('no admin test', 'has no "if not IsAdmin'),
            ('elevated only', 'has no "if not IsAdmin'),
            ('admin test late', 'comes AFTER'),
            ('blocking box', 'suppressible box')):
        m = mutate(text, what)
        control = m != text
        check('CONTROL: the mutant "' + what + '" differs from the real file', control)
        v = violations(m)
        check('MUTANT "' + what + '" is flagged (' + expect + ')', any(expect in x for x in v),
              'violations seen: ' + ('; '.join(v) if v else 'none'))

    print('')
    print('finishfail units: %d passed, %d failed' % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
