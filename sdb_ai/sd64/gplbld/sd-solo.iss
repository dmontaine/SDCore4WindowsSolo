; sd-solo.iss - Inno Setup script for SD Core Solo.  SOLO 8.
;
; Build (MSYS2 bash, from sdb_ai/sd64):
;   python3 gplbld/stage.py --stage ../../stage --force --bootstrap
;   "<Inno Setup 6>\ISCC.exe" /DStage=..\..\stage gplbld\sd-solo.iss
;
; A PERSONAL, PER-USER INSTALL (owner's rulings, PROJECT_STATUS.md "WHAT SD CORE
; SOLO IS").  PrivilegesRequired=lowest: the whole tree goes to
; %USERPROFILE%\SDCoreSolo (ruling 1), copied from <stage>\SDCoreSolo, which
; holds no path - sd.exe finds its tree from its own location (SOLO 2).  The
; machine-wide work is ONE UAC prompt at the end, solo-machine.ps1 through
; ShellExec('runas') - the shape SOLO 1 measured with probe-solo-installer.iss.
;
; ORDER AT ssPostInstall, and why:
;   1. solo-setup.ps1, unelevated: sd -start, the account (ruling 10), the
;      administrator password and the global one when one was given (rulings
;      12, 15; SOLO 36: it may be left blank); on an upgrade (a data tree already existed), UPDATE.ACCOUNTS
;      ALL - an upgrade replaces NEWVOC but rebuilds no account's own live
;      VOC, so without this a release that adds a verb ships it to nobody
;      (SOLO 9); sd -stop.  Sessions need a started SD; the stop hands SD over
;      to the task.
;   2. PATH, the user's own (HKCU).
;   3. solo-machine.ps1, elevated: the S4U startup task, registered and started
;      (SOLO 3, ruling 2); API firewall; and, wherever OpenSSH is found, SOLO'S
;      OWN SSH SERVER (SOLO 28, the owner's ruling of 2 Oct 2026): a second S4U
;      startup task running solo-sshd.ps1 as this user, on port 4251, fixed, and
;      its firewall rule - not a choice.  It replaces the old route, a
;      "Match User" block in the SYSTEM sshd_config, which this step now takes
;      OUT.  Solo and the full product can be installed at the same time: the
;      refusal that used to stop this installer when the full product was
;      present went with that route (the owner, 2 Oct 2026: they are meant to
;      coexist), and ssh is no longer shared - Solo's is on 4251, the full
;      product's on 22.
;
; RULING 17 (25 Sep 2026): optional installs of the packages the release puts
; beside this file - <src>\python\python-3*-amd64.exe, per-user and unelevated
; (step 0), and <src>\ssh-server\*.msi, inside the elevated step before its ssh
; work (solo-machine.ps1 -SshMsi).  Offered only when the package is there and
; nothing equivalent is installed.  The uninstaller leaves both alone: they are
; separate products with their own entries in Apps.
;
; SOLO 37 (6 Oct 2026): THE UNINSTALLER ASKS KEEP OR DELETE (5.9.1's opt-in data
; removal, built).  Keep leaves the account's files and sd.conf with a stamp and
; removes the rest; a new install over that folder offers them back (see the
; comments at CurStepChanged, PrepareToInstall and OfferDataRemoval).
;
; WHAT IS NOT HERE YET (SOLO 8 in PROJECT_STATUS.md): ruling 13's deletion
; of the gpl.bp source at the end of install, and dropping the multi-user
; scripts from stage.py's ship list (they are copied and never run).
;
; DO NOT MERGE WITH sd.iss.  sd.iss is the multi-user product and still builds
; it; this file shares its generated upgrade.iss and nothing else.

#ifndef Stage
  #define Stage "..\..\stage"
#endif
#ifndef AppVer
  #define AppVer "WS1.1-3"
#endif
; 28 Sep 26 - ruling 37: "SD Core Solo for Windows", WS1.1-0.  AppId below is
; unchanged, so an S1.1-0 install is still recognised and upgraded.
; 29 Sep 26 - first release is WS1.1-1 (no 1.1-0 was released), owner's ruling.
; 30 Sep 26 - WS1.1-2: managed-mode ssh key install (request 49) and first-use
; certificate pinning in the client library (SOLO 24).
#define AppName      "SD Core Solo for Windows"
#define AppPublisher "String Database"
#define SoloDir      "{%USERPROFILE}\SDCoreSolo"
; upgrade.iss names the data root {#DataDir}; in Solo it is the install folder.
#define DataDir      "{app}"

; A STAGE THAT HAS BEEN PROBED CARRIES TEST CREDENTIALS AND A TEST ACCOUNT
; (probe-solo-stage.py sets passwords and makes the builder's own account in
; it).  Shipping either would give every install somebody else's password, so
; the build refuses.  stage.py --force makes a clean one.  $STORED (26 Sep 26,
; SOLO 15 piece 4) is the account password DPAPI-kept for one-shot commands.
#if FileExists(AddBackslash(Stage) + "SDCoreSolo\sdsys\$cred\$ADMIN") || \
    FileExists(AddBackslash(Stage) + "SDCoreSolo\sdsys\$cred\$GLOBAL") || \
    FileExists(AddBackslash(Stage) + "SDCoreSolo\sdsys\$cred\$STORED")
  #error The stage holds a test password in sdsys\$cred - run stage.py --force --bootstrap first
#endif
; ISPP's documented loop: FindNext returns found-or-not, not a new handle.
#define UserEntries 0
#define FindHandle 0
#define FindResult 0
#sub CountUserEntry
  #if FindGetFileName(FindHandle) != "." && FindGetFileName(FindHandle) != ".."
    #expr UserEntries = UserEntries + 1
  #endif
#endsub
#for {FindHandle = FindResult = FindFirst(AddBackslash(Stage) + "SDCoreSolo\user_accounts\*", faAnyFile); FindResult; FindResult = FindNext(FindHandle)} CountUserEntry
#if FindHandle
  #expr FindClose(FindHandle)
#endif
#if UserEntries > 0
  #error The stage holds an account in user_accounts - run stage.py --force --bootstrap first
#endif

[Setup]
AppId={{5E0C3A92-7B14-4D2F-A8C6-2F9D1B7E4A63}
AppName={#AppName}
AppVersion={#AppVer}
AppVerName={#AppName} {#AppVer}
AppPublisher={#AppPublisher}
PrivilegesRequired=lowest
DefaultDirName={#SoloDir}
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
OutputBaseFilename=sd-solo-setup-{#AppVer}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Windows 10 and 11 - sd.iss "MinVersion" records the owner's ruling.
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
SetupLogging=yes
UninstallDisplayName={#AppName} {#AppVer}

[Tasks]
; 27 Sep 26 - RULING 24: NO "Add to PATH" BOX AND NO "Install Python" BOX.  The
; owner: "always install python in both modes ... add to path is always true in
; both modes".  PATH is always added (CurStepChanged); Python is installed
; whenever no Python 3.13+ is registered.
; 06 Oct 26 - SOLO 39: THE FINISH PAGE SAYS WHAT DID NOT COMPLETE.  After a failed step the dialog said "These steps
; did not complete" and the page behind it still said "Setup has finished installing ... on your computer" (seen on
; a standard account, SOLO 38).  StepsNotCompleted carries the dialog's list to CurPageChanged, which puts it, the
; log path and "Click Finish" on the page under the heading "Setup finished with problems", and fits the label's
; height after the last sentence (the first try lost its last line, as the SOLO 36/37 sentences would have).  A clean
; install is untouched.  Guard: test-finishfail-units.py.
; 06 Oct 26 - SOLO 36 (owner: one mode, the global password optional): NOTHING IS FORCED ANY MORE.  Ruling
; 22 made the API and ssh on and open in managed mode; now both are a choice in every install, on this page
; or, for a box the control file answers (api=, ssh=), there: a box the file answers is not shown
; (its Check function), and the page is skipped when the file answers both.  ssh is a real choice too
; (the owner, 6 Oct, reversing part of SOLO 28's "not a choice"): "Provide Solo's ssh server" starts
; ticked where an OpenSSH server is already installed (what the install did before) and the install-the-
; package box below starts unticked, as it always did.
; 06 Oct 26 - THE PARENT BOXES WERE NOT TICKABLE ON THEIR OWN (SOLO 34).  Found by the owner in a fresh VM:
; clicking "Let other computers reach it" ticked both boxes, clicking "Provide the SD Core API" alone did
; nothing - so "API on, other computers off" could not be chosen, though solo-machine.ps1 has the path for
; it (-Api without -ApiNetwork gives api-firewall.ps1 -Restrict).  Inno's own rule, read in the full
; product's sd.iss (the comment before its [Tasks] group 2): a task with children is unchecked
; automatically when none of its children is checked unless it carries checkablealone, so the parent
; cannot be ticked alone.  The full product has the flag on its parents; Solo's two did not.
; "unchecked" stays, or the flag would make the box tick by default.
Name: "api"; Description: "Provide the SD Core API (port 4249)"; Flags: unchecked checkablealone; Check: ApiAsked
Name: "api\network"; Description: "Let other computers reach it"; Flags: unchecked dontinheritcheck; Check: ApiAsked
; 06 Oct 26 - SOLO 36.  Was one box, "Let other computers reach Solo's ssh port (4251)", with Solo's sshd set
; up whenever an OpenSSH server was found (SOLO 28).  Now a parent that turns Solo's sshd on, ticked by
; default (so test-isstasks-units.py does not list it among the opt-in parents), and the same child as the API.
Name: "ssh"; Description: "Provide Solo's ssh server (port 4251)"; Flags: checkablealone; Check: SshAskedFound
Name: "ssh\network"; Description: "Let other computers reach it"; Flags: unchecked dontinheritcheck; Check: SshAskedFound
; 25 Sep 26 - RULING 17: the release carries Microsoft's OpenSSH MSI and
; python.org's Python .exe beside this installer (ssh-server\, python\) - both
; mandatory since ruling 23.  The MSI is installed only when no sshd already is
; (optional in every install since SOLO 36; it was forced in managed mode, ruling 22).  Read from {src},
; never copied: the release is also a read-only USB stick (ruling 9).
; 06 Oct 26 (SOLO 34) - checkablealone as for "api" above, so the server can be installed without opening it to
; the network.  "unchecked" is NEW and is not optional: until now this box had no "unchecked" and showed
; unticked only because its child was unticked (the same automatic rule); with checkablealone it would
; have started TICKED and installed OpenSSH on every standalone install.
Name: "installssh"; Description: "Install the OpenSSH server"; Flags: unchecked checkablealone; Check: SshAskedMsi
Name: "installssh\network"; Description: "Let other computers reach it"; \
    Flags: unchecked dontinheritcheck; Check: SshAskedMsi
; 25 Sep 26 - NO BOX FOR "ssh lands in SD".  Ruling 5 makes it the product, not
; a choice; the box that was here ("Start SD Core Solo when I sign in over
; ssh") read to the owner as starting the SERVER on sign-in, which it never
; did - SD starts at boot from the task.  When Solo's sshd is on it is set up and
; started at boot (solo-machine.ps1, SOLO 28); since SOLO 36 whether it is on is
; the "ssh" / "installssh" box above, or the control file's ssh=.

[Dirs]
Name: "{app}\user_accounts"; Flags: uninsneveruninstall
Name: "{app}\group_accounts"; Flags: uninsneveruninstall
; The API's TLS identity (api.pem, made by sd on the first connection).  sd
; never creates this folder itself (sd_tlssrv.c); it inherits the profile's
; ACL - the user, SYSTEM, Administrators - which win32_owner_only() accepts.
; Kept at uninstall so a reinstall keeps the same server key.
Name: "{app}\sd-tls"; Flags: uninsneveruninstall
; 28 Sep 26 - where !ps_script/!ps_script_out write the script they run
; (gpl.bp/ps_scripto).  They fail closed with status -1 when it is absent, and
; nothing else makes it: the multi-user sd.iss did, through secure-psdir.ps1,
; which Solo does not ship.  APPEND.SD.PATH answered "Could not SHOW the system
; PATH (status -1)" on every Solo install.  The profile's inherited ACL (the
; user, SYSTEM, Administrators) is the right one here - there is no other SD
; user to keep out.  [Dirs] runs on upgrades too, so an existing tree gains it.
Name: "{app}\sdsys\pstmp"; Flags: uninsneveruninstall
; 28 Sep 26 - ruling 33: the SD Core server's compiled programs (managed
; mode), which SYNC.GLOBAL.CATALOG puts in the global catalogue.  Starts empty
; (owner: the server fills it after installing).  [Dirs] only ever creates, and
; no stage.py list names it, so an upgrade keeps what the server put there.
Name: "{app}\sdsys\global.bp.out"; Flags: uninsneveruninstall
; 28 Sep 26 - rulings 34 and 36: the verbs denied to the local user (record
; denied.verbs), set from the control file and changed by DENY.VERBS.  Kept
; like global.bp.out.
Name: "{app}\sdsys\solo.policy"; Flags: uninsneveruninstall

[InstallDelete]
; 01 Oct 26 - the server is sd-solo.exe now.  An install made before the rename
; has it as sd.exe (plain "sd" belongs to the full product) and a launcher,
; sd-solo.cmd; either left behind would start the old program by name.
Type: files; Name: "{app}\usr\bin\sd.exe"
Type: files; Name: "{app}\usr\bin\sd-solo.cmd"

[Files]
; The programs and scripts.  sdsys, the account folders and sd.conf are laid
; down by the entries below, which know about upgrades.
Source: "{#Stage}\SDCoreSolo\*"; DestDir: "{app}"; \
    Excludes: "\sdsys\*,\user_accounts\*,\group_accounts\*,\sd.conf,\sd-standalone.conf"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; The data tree, whole, on a first install - sd.iss's DataTreeAbsent entry.  On
; an existing tree the generated upgrade.iss below replaces the shipped half
; and keeps the user's own.  Kept at uninstall (5.9.1).
Source: "{#Stage}\SDCoreSolo\sdsys\*"; DestDir: "{app}\sdsys"; \
    Flags: recursesubdirs createallsubdirs uninsneveruninstall; Check: DataTreeAbsent

; sd.conf: ALWAYS the one with APIPORT commented out (no listener).  6 Oct 26 - SOLO 33,
; the owner's choice of option 1.  It used to be the APIPORT variant when the API box was
; ticked, and then the unelevated solo-setup.ps1 step started SD with the listener on, in
; the user's session, BEFORE any firewall rule existed: Windows showed its "allow this app?"
; alert behind the consent prompt, and an Allow left two sdwind.exe rules open to every
; address on Public.  Now that first start listens on nothing; solo-machine.ps1 (elevated)
; makes the API firewall rule and then runs solo-api-listener.ps1 -On, and only then
; starts the startup task, whose SD runs in session 0 and cannot show an alert.  So the API
; box decides the listener through solo-machine.ps1, not through which file is copied here.
; Never overwritten, never uninstalled.
Source: "{#Stage}\SDCoreSolo\sd-standalone.conf"; DestDir: "{app}"; DestName: "sd.conf"; \
    Flags: onlyifdoesntexist uninsneveruninstall

#include AddBackslash(Stage) + "upgrade.iss"

[Code]
const
  SoloKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{5E0C3A92-7B14-4D2F-A8C6-2F9D1B7E4A63}_is1';

var
  { Sampled ONCE in InitializeSetup: a live DirExists is changed by the first
    file this installer writes (sd.iss records the ~3,260 files that cost). }
  DataTreeWasAbsent: Boolean;
  { Solo's own uninstall key: present means an UPGRADE of a live install, which
    skips every page and re-runs only the startup task.  Absent with a data
    tree means a reinstall over kept data: the tasks are asked again, the
    passwords are not (the tree already has them - ruling 15). }
  SoloWasInstalled: Boolean;
  SshServerWasFound: Boolean;
  { Ruling 17: the packages beside the installer ('' when absent), and whether
    a usable Python is already registered.  Sampled once, like the rest. }
  SshMsiPath, PythonExePath: String;
  PythonWasFound: Boolean;
  { Ruling 15: a computer is managed if and only if it has a global password.
    Read from the tree when the passwords are not asked (upgrade, or a kept
    tree reinstalled). }
  GlobalWasFound: Boolean;
  { SOLO 18: the optional control file beside the installer, new trees only.
    SOLO 36: its presence no longer means anything but its own answers.  A
    password it gives is used only if it passes the pages' own checks; anything
    missing or refused is asked for - except the global password, where blank
    or absent means "none" and nothing is asked. }
  UseControl, CfAdminOk, CfGlobalOk: Boolean;
  CfAdmin, CfGlobal: String;
  { 28 Sep 26 - ruling 34: the control file's deny-verbs line, as written. }
  CfDeny: String;
  { 06 Oct 26 - SOLO 36: the control file's api= and ssh=, 'off', 'local' or
    'open'; '' when not given or not one of those (then the Tasks page asks). }
  CfApi, CfSsh: String;
  AdminPage, GlobalPage, AccountPage: TInputQueryWizardPage;
  { 06 Oct 26 - SOLO 37 (owner: removal and reinstall work the same on both
    ports; the data stays in place).  The uninstaller's Keep leaves only the
    account's files and sd.conf, with a stamp (.sdcore-kept).  A new install
    over such a folder (KeptWasFound) offers them back; either answer moves the
    old folder aside to KeptFolder ('' until then), and Yes then copies the
    account's files and sd.conf into the new tree (solo-setup.ps1 -ReloadFrom).
    CfReload is the control file's reload-data= ('yes', 'no' or ''). }
  KeptWasFound: Boolean;
  ReloadPage: TInputOptionWizardPage;
  KeptFolder, CfReload: String;
  { 06 Oct 26 - SOLO 39.  The steps CurStepChanged found not completed, one per line as the
    dialog lists them ('' when all passed).  The finish page reads it: it said "Setup has finished
    installing ..." after a failed step, which the dialog before it contradicted.  Declared here
    because CurPageChanged comes before CurStepChanged and Pascal needs the name first. }
  StepsNotCompleted: String;

function SetEnvironmentVariable(lpName: String; lpValue: String): BOOL;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

function MoveFileW(lpExistingFileName: String; lpNewFileName: String): BOOL;
  external 'MoveFileW@kernel32.dll stdcall';

{ RELEASE_1.1 110 (sd.iss UseWindowsPowerShellModules): a PowerShell 7
  PSModulePath breaks Windows PowerShell's own modules in every child. }
procedure UseWindowsPowerShellModules;
begin
  SetEnvironmentVariable('PSModulePath',
    ExpandConstant('{commonpf64}\WindowsPowerShell\Modules;{sys}\WindowsPowerShell\v1.0\Modules'));
end;

(* {sys} STARTS THE 32-BIT POWERSHELL, AND {sysnative} CANNOT BE USED INSTEAD.
   Measured 25 Sep 2026 with a probe installer in 64-bit mode: ShellExec 'open'
   of {sys}\...\powershell.exe gave a 32-bit PowerShell that cannot see
   System32\OpenSSH\sshd.exe (the owner's first install: "sshd.exe: none
   found", sshd -t skipped); {sysnative} gave 64-bit.  But under 'runas' the
   path is resolved by the elevation service, which is 64-bit and has no
   Sysnative: the owner's second install failed to start with code 3 (path not
   found).  So this stays {sys}, and solo-machine.ps1 re-launches itself in the
   64-bit PowerShell through Sysnative, which a 32-bit process CAN see. *)
function PowerShellExe: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

function SoloRoot: String;
begin
  Result := ExpandConstant('{%USERPROFILE}') + '\SDCoreSolo';
end;

function ForUser: String;
begin
  Result := GetEnv('USERDOMAIN') + '\' + GetUserNameString;
end;

(* The first file matching Pattern in {src}\Dir, or ''.  Written as a
   paren-star comment because a brace comment ends at the first closing
   brace, and the source-folder constant contains one. *)
function FindBeside(Dir, Pattern: String): String;
var
  F: TFindRec;
begin
  Result := '';
  if FindFirst(ExpandConstant('{src}\') + Dir + '\' + Pattern, F) then
  begin
    Result := ExpandConstant('{src}\') + Dir + '\' + F.Name;
    FindClose(F);
  end;
end;

{ A 64-bit Python 3.13 or later registered under Root (PEP 514) - the helper's
  floor (build-sdpy.ps1: stable ABI, 3.13).  Key names are "3.14", "3.13-32". }
function PythonInHive(Root: Integer): Boolean;
var
  Names: TArrayOfString;
  I, Dot, Minor: Integer;
  N: String;
begin
  Result := False;
  if not RegGetSubkeyNames(Root, 'Software\Python\PythonCore', Names) then
    Exit;
  for I := 0 to GetArrayLength(Names) - 1 do
  begin
    N := Names[I];
    Dot := Pos('.', N);
    if (Copy(N, 1, 2) = '3.') and (Pos('-32', N) = 0) and (Dot = 2) then
    begin
      Minor := StrToIntDef(Copy(N, 3, Length(N) - 2), 0);
      if Minor >= 13 then
      begin
        Log('SD Core Solo: Python ' + N + ' already registered');
        Result := True;
      end;
    end;
  end;
end;

{ Letters, digits and punctuation: solo-setup.ps1 sends the password to sd's
  standard input as ASCII bytes, and solo_password refuses anything outside
  33-126 (the byte-order-mark defect, PROJECT_STATUS.md SOLO 8). }
{ 25 Sep 26 - THE PASSWORD RULE, gpl.bp/pw_complex arm for arm: at least 8
  characters, a lower-case letter, an upper-case letter, a digit and a symbol.
  Every prompt that sets a password runs it (test-pwcomplex-units.ps1, which
  names this function); the refusal is message 10920 word for word.
  27 Sep 26 - moved above InitializeSetup so the control file's passwords
  (SOLO 18) are checked by the same code as the pages'. }
function PasswordComplex(P: String): Boolean;
var
  I, C: Integer;
  Lo, Up, Dg, Sy: Boolean;
begin
  Result := False;
  if Length(P) < 8 then
    Exit;
  Lo := False; Up := False; Dg := False; Sy := False;
  for I := 1 to Length(P) do
  begin
    C := Ord(P[I]);
    if (C >= 97) and (C <= 122) then
      Lo := True
    else if (C >= 65) and (C <= 90) then
      Up := True
    else if (C >= 48) and (C <= 57) then
      Dg := True
    else if (C >= 32) and (C <= 126) then
      Sy := True
    else
      Exit;
  end;
  Result := Lo and Up and Dg and Sy;
end;

function PasswordProblem(A, B: String): String;
var
  I: Integer;
begin
  Result := '';
  if A = '' then
    Result := 'Enter a password.'
  else if A <> B then
    Result := 'The passwords do not match.'
  else
  begin
    for I := 1 to Length(A) do
      if (Ord(A[I]) < 33) or (Ord(A[I]) > 126) then
      begin
        Result := 'Use letters, digits and punctuation only.';
        Exit;
      end;
    if not PasswordComplex(A) then
      Result := 'A password needs at least 8 characters, with a lower-case letter, an upper-case letter, a digit and a symbol.';
  end;
end;

{ How a control-file password fared, for the log - never the password itself. }
function PasswordFate(Given: String; Problem: String): String;
begin
  if Given = '' then
    Result := 'missing, asked for'
  else if Problem = '' then
    Result := 'given, accepted'
  else
    Result := 'given, refused (' + Problem + '), asked for';
end;

{ SOLO 18: the control file's answers, read and checked once.  Passwords are
  never logged - only whether each was given and whether it was accepted. }
procedure LoadControlFile;
var
  F, P: String;
begin
  F := ExpandConstant('{src}\sd-solo-setup.conf');
  UseControl := DataTreeWasAbsent and FileExists(F);
  CfAdminOk := False;
  CfGlobalOk := False;
  if not UseControl then
  begin
    if FileExists(F) then
      Log('SD Core Solo: control file ' + F + ' IGNORED - this computer already has a data tree');
    Exit;
  end;
  CfAdmin := Trim(GetIniString('install', 'admin-password', '', F));
  CfGlobal := Trim(GetIniString('install', 'global-password', '', F));
  P := PasswordProblem(CfAdmin, CfAdmin);
  CfAdminOk := P = '';
  Log('SD Core Solo: control file ' + F + '; admin-password ' + PasswordFate(CfAdmin, P));
  { 06 Oct 26 - SOLO 36: a blank or absent global-password is the answer "none": this computer will NOT
    be managed, nothing is asked, and the log, install-summary.log and the finish page say so. }
  if CfGlobal = '' then
  begin
    CfGlobalOk := False;
    Log('SD Core Solo: control file gives no global password - this computer will NOT be managed by an SD Core server');
  end
  else
  begin
    P := PasswordProblem(CfGlobal, CfGlobal);
    if (P = '') and (CfGlobal = CfAdmin) then
      P := 'Use a password different from the administrator password.';
    CfGlobalOk := P = '';
    Log('SD Core Solo: control file global-password ' + PasswordFate(CfGlobal, P));
  end;
  { SOLO 36: api= and ssh=.  Anything but off, local or open is not an answer: the Tasks page asks. }
  CfApi := Lowercase(Trim(GetIniString('install', 'api', '', F)));
  if (CfApi <> 'off') and (CfApi <> 'local') and (CfApi <> 'open') then
  begin
    if CfApi <> '' then
      Log('SD Core Solo: control file api "' + CfApi + '" is not off, local or open - asked for');
    CfApi := '';
  end;
  CfSsh := Lowercase(Trim(GetIniString('install', 'ssh', '', F)));
  if (CfSsh <> 'off') and (CfSsh <> 'local') and (CfSsh <> 'open') then
  begin
    if CfSsh <> '' then
      Log('SD Core Solo: control file ssh "' + CfSsh + '" is not off, local or open - asked for');
    CfSsh := '';
  end;
  Log('SD Core Solo: control file api "' + CfApi + '" ssh "' + CfSsh + '"');
  { SOLO 37: reload-data= answers the saved-data question: yes or no.  It does nothing where there is no
    kept data, so one file can say it for every computer.  Anything else is not an answer. }
  CfReload := Lowercase(Trim(GetIniString('install', 'reload-data', '', F)));
  if (CfReload <> 'yes') and (CfReload <> 'no') then
  begin
    if CfReload <> '' then
      Log('SD Core Solo: control file reload-data "' + CfReload + '" is not yes or no - ignored');
    CfReload := '';
  end;
  Log('SD Core Solo: control file reload-data "' + CfReload + '"');
  { 28 Sep 26 - ruling 34: verbs denied to the local user.  Not a secret, so
    logged whole; DENY.VERBS (run by solo-setup) checks each name. }
  CfDeny := Trim(GetIniString('install', 'deny-verbs', '', F));
  Log('SD Core Solo: control file deny-verbs "' + CfDeny + '"');
end;

function InitializeSetup: Boolean;
var
  Missing: String;
begin
  UseWindowsPowerShellModules;
  { 2 Oct 26 - SOLO 28.  THERE IS NO REFUSAL HERE ANY MORE.  This used to stop with "SD Core is installed
    on this computer. Uninstall it first." when the multi-user product's uninstall key or its sd.exe
    was present.  The reasons recorded for it - shared pipe and program names, semaphores - were gone by
    the 1-2 Oct work (API ports 4247/4249, sd and sd-solo, each product's own shared-memory and
    semaphore names, its own firewall rule names), the one that was left was ssh, and Solo's ssh is its
    own sshd on its own port now.  The owner: the two products are meant to be installed at the same
    time.  NOT YET WITNESSED: both running together on one computer. }
  DataTreeWasAbsent := not DirExists(SoloRoot + '\sdsys');
  SoloWasInstalled := RegKeyExists(HKCU, SoloKey);
  SshServerWasFound := FileExists(ExpandConstant('{sys}\OpenSSH\sshd.exe')) or
                       FileExists(ExpandConstant('{commonpf64}\OpenSSH\sshd.exe'));
  { SOLO 28: the old "an ssh port already open starts ticked" detection (ssh-firewall.ps1 -ScopeFile
    against Microsoft's rule for port 22) is gone with the system-sshd route - Solo's port is its own,
    4251, and its rule is Solo's (solo-ssh-firewall.ps1), so there is nothing already open to find. }
  SshMsiPath := FindBeside('ssh-server', '*.msi');
  PythonExePath := FindBeside('python', 'python-3*-amd64.exe');
  { 27 Sep 26 - OWNER'S RULING: "installation package must always have the SSH
    MSI and Python exe available, otherwise it is an invalid installation
    package."  Refused in every mode, before anything is written.  Installing
    them stays optional (ruling 17; SOLO 36: managed mode needs nothing). }
  if (SshMsiPath = '') or (PythonExePath = '') then
  begin
    Missing := '';
    if SshMsiPath = '' then Missing := Missing + 'ssh-server\*.msi' + #13#10;
    if PythonExePath = '' then Missing := Missing + 'python\python-3*-amd64.exe' + #13#10;
    MsgBox('Invalid installation package. Missing beside this installer:' + #13#10 + #13#10 + Missing, mbError, MB_OK);
    Result := False;
    Exit;
  end;
  GlobalWasFound := FileExists(SoloRoot + '\sdsys\$cred\$GLOBAL');
  { SOLO 37: kept data is what the uninstaller's Keep leaves - no sdsys, its stamp, and the account.  A tree
    that still has sdsys (an earlier release's uninstall, or one copied from another Windows user) is NOT
    kept data: it is reinstalled over as before. }
  KeptWasFound := DataTreeWasAbsent and FileExists(SoloRoot + '\.sdcore-kept') and
                  DirExists(SoloRoot + '\user_accounts\sduser');
  LoadControlFile;
  PythonWasFound := PythonInHive(HKCU) or PythonInHive(HKLM64) or PythonInHive(HKLM32);
  Log('SD Core Solo: beside the installer: msi="' + SshMsiPath + '" python="' +
      PythonExePath + '"; Python 3.13+ already registered=' + IntToStr(Ord(PythonWasFound)));
  Log('SD Core Solo: data tree absent=' + IntToStr(Ord(DataTreeWasAbsent)) +
      ' installed=' + IntToStr(Ord(SoloWasInstalled)) +
      ' sshd=' + IntToStr(Ord(SshServerWasFound)) +
      ' global=' + IntToStr(Ord(GlobalWasFound)) +
      ' keptdata=' + IntToStr(Ord(KeptWasFound)));
  Result := True;
end;

function DataTreeAbsent: Boolean;
begin
  Result := DataTreeWasAbsent;
end;

function DataTreeUpgrade: Boolean;
begin
  Result := not DataTreeWasAbsent;
end;

{ 06 Oct 26 - SOLO 37.  Kept data is a folder the uninstaller's Keep left: no
  sdsys (so the install is a NEW tree, every password asked), the stamp, and the
  account.  Yes reloads it, No starts clean; both move the old folder aside, so
  nothing is ever deleted.  The answer is read from the page, so going Back and
  changing it works. }
function ReloadChosen: Boolean;
begin
  Result := KeptWasFound and (ReloadPage.SelectedValueIndex = 0);
end;

function SshMsiOffered: Boolean;
begin
  Result := (SshMsiPath <> '') and not SshServerWasFound;
end;

function PythonExeOffered: Boolean;
begin
  Result := (PythonExePath <> '') and not PythonWasFound;
end;

{ 06 Oct 26 - SOLO 36.  The control file's api= and ssh= answer a choice; a box
  it answers is not shown on the Tasks page (these are the boxes' Check
  functions), and the page is skipped when it answers both. }
function ApiAnswered: Boolean;
begin
  Result := UseControl and (CfApi <> '');
end;

function SshAnswered: Boolean;
begin
  Result := UseControl and (CfSsh <> '');
end;

function ApiAsked: Boolean;
begin
  Result := not ApiAnswered;
end;

{ "Provide Solo's ssh server" is offered where an OpenSSH server is already
  installed; where only the MSI is offered, "Install the OpenSSH server" is. }
function SshAskedFound: Boolean;
begin
  Result := SshServerWasFound and not SshAnswered;
end;

function SshAskedMsi: Boolean;
begin
  Result := SshMsiOffered and not SshAnswered;
end;

{ A computer is managed if and only if it has a global password (ruling 15).
  On a new tree that is whether the Global page holds one - a control file's
  accepted one is already in it; on an existing tree, the tree's own $GLOBAL.
  SOLO 36: there is no Mode page.  SOLO 37: kept data has no $GLOBAL (the
  uninstaller removes the passwords), so a reinstall over it is a new tree that
  asks for one - the way to add one later, or to drop one. }
function Managed: Boolean;
begin
  if DataTreeWasAbsent then
    Result := GlobalPage.Values[0] <> ''
  else
    Result := GlobalWasFound;
end;

{ 06 Oct 26 - SOLO 36: each of these is its box, or the control file's answer.
  It was the box OR managed mode (the owner's ruling of 27 Sep, ruling 22),
  which is withdrawn: the API and ssh are a choice in every install. }
function ApiWanted: Boolean;
begin
  if ApiAnswered then
    Result := CfApi <> 'off'
  else
    Result := WizardIsTaskSelected('api');
end;

function ApiNetworkWanted: Boolean;
begin
  if ApiAnswered then
    Result := CfApi = 'open'
  else
    Result := WizardIsTaskSelected('api\network');
end;

{ Solo's own sshd on 4251 is set up (SOLO 28), and Microsoft's OpenSSH package
  installed first when none is there. }
function SshWanted: Boolean;
begin
  if SshAnswered then
    Result := CfSsh <> 'off'
  else if SshServerWasFound then
    Result := WizardIsTaskSelected('ssh')
  else
    Result := WizardIsTaskSelected('installssh');
end;

{ Each branch asks only about the boxes that are on the page: the earlier code
  never asked WizardIsTaskSelected about a box its Check had hidden either. }
function SshOpenWanted: Boolean;
begin
  if SshAnswered then
    Result := CfSsh = 'open'
  else if SshServerWasFound then
    Result := WizardIsTaskSelected('ssh\network')
  else
    Result := WizardIsTaskSelected('installssh\network');
end;

procedure InitializeWizard;
begin
  { 06 Oct 26 - SOLO 36: THE MODE PAGE IS GONE (owner: "remove the standalone
    version and just make entry of the global password ... optional").  A
    computer is managed if and only if it has a global password.

    28 Sep 26 - THE ORDER IS ACCOUNT, ADMINISTRATOR, GLOBAL (owner: "account
    password, admin password, and if a managed client global password").  It
    was administrator, global, account.  The comparisons follow the order: the
    global page, now last, is checked against both earlier ones.

    25 Sep 26 - rulings 18 and 21: THE ACCOUNT PASSWORD.  Every session asks
    for it - local, ssh, API and one-shot - so it is asked on every new tree,
    whether or not the API box is ticked (it was the API password, after the
    tasks page, until the owner made it global).

    06 Oct 26 - SOLO 37: THE FIRST PAGE AFTER THE WELCOME is the reload
    question, shown only when the folder holds kept data (the same words as SD
    Core for Linux Solo).  Yes is the default.  Either answer moves the old
    folder aside, never deleting it; the passwords are asked either way. }
  ReloadPage := CreateInputOptionPage(wpWelcome, 'Saved data', 'Saved data was found: ' + SoloRoot,
    'Reload your saved data and configuration into this new install?', True, False);
  ReloadPage.Add('Yes - reload them');
  ReloadPage.Add('No - start clean; the saved data is moved aside, not deleted');
  ReloadPage.SelectedValueIndex := 0;
  { reload-data= in the control file answers it. }
  if UseControl and (CfReload = 'no') then
    ReloadPage.SelectedValueIndex := 1;

  AccountPage := CreateInputQueryPage(ReloadPage.ID, 'Account password',
    'SD Core Solo for Windows asks for this password whenever it is used.', '');
  AccountPage.Add('Password:', True);
  AccountPage.Add('Confirm password:', True);

  AdminPage := CreateInputQueryPage(AccountPage.ID, 'Administrator password',
    'This password unlocks the administrator commands.', '');
  AdminPage.Add('Password:', True);
  AdminPage.Add('Confirm password:', True);

  { SOLO 36: asked on every new install; both boxes blank is the answer "no
    global password", so this computer is not managed (the same sentence as
    SD Core for Linux Solo's prompt). }
  GlobalPage := CreateInputQueryPage(AdminPage.ID, 'Global password',
    'Leave blank if no SD Core server manages this computer.', '');
  GlobalPage.Add('Password:', True);
  GlobalPage.Add('Confirm password:', True);

  { SOLO 18: the control file's accepted answers fill their pages, which are
    then skipped; a page it did not answer is shown empty. }
  if UseControl then
  begin
    if CfAdminOk then
    begin
      AdminPage.Values[0] := CfAdmin;
      AdminPage.Values[1] := CfAdmin;
    end;
    if CfGlobalOk then
    begin
      GlobalPage.Values[0] := CfGlobal;
      GlobalPage.Values[1] := CfGlobal;
    end;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  { SOLO 37: asked only where kept data was found, and not when the control file
    answers it (reload-data=) or answers everything else too (an unattended
    install, where "no answer" means yes, as on Linux). }
  if PageID = ReloadPage.ID then
    Result := (not KeptWasFound) or (UseControl and ((CfReload <> '') or (CfAdminOk and CfGlobalOk)))
  else if PageID = AdminPage.ID then
    Result := (not DataTreeWasAbsent) or (UseControl and CfAdminOk)
  { SOLO 36: the global password is asked on every new tree.  A control file
    settles it when it gives an accepted one or none at all (blank or absent);
    one the rules refuse is asked for. }
  else if PageID = GlobalPage.ID then
    Result := (not DataTreeWasAbsent) or (UseControl and ((CfGlobal = '') or CfGlobalOk))
  { SOLO 18: not with a control file that gives a global password - the
    owner's ruling is that the user sets the account password at the first
    login, at the console, and that route needs a $GLOBAL.  SOLO 36: with no
    global password (a file with none, a refused one, or no file) the account
    password is asked here, on every route. }
  else if PageID = AccountPage.ID then
    Result := (not DataTreeWasAbsent) or (UseControl and CfGlobalOk)
  { SOLO 36: the page asks the API and ssh in every install; skipped on an
    upgrade, and when the control file answers both. }
  else if PageID = wpSelectTasks then
    Result := SoloWasInstalled or (ApiAnswered and SshAnswered)
  else if PageID = wpReady then
    Result := UseControl and CfAdminOk and CfGlobalOk;
end;

{ 27 Sep 26 - the greyed "forced" boxes (ShowForcedTasks) went with ruling 24.
  2 Oct 26 - SOLO 28: CurPageChanged went too.  It ticked the ssh box when
  Microsoft's port-22 rule was already open; Solo's port is its own now and
  there is no such rule to find.  06 Oct 26 - SOLO 36: CurPageChanged is back
  for one sentence on the finish page. }
procedure CurPageChanged(CurPageID: Integer);
begin
  { SOLO 39: a step that did not complete is a result, so the finish page says so instead of "Setup has
    finished installing".  Same words as the dialog that preceded it; first, so the sentences below are
    added to this text. }
  if (CurPageID = wpFinished) and (StepsNotCompleted <> '') then
  begin
    WizardForm.FinishedHeadingLabel.Caption := 'Setup finished with problems';
    WizardForm.FinishedLabel.Caption := 'These steps did not complete:' + #13#10 + StepsNotCompleted + #13#10 +
      'Details: ' + ExpandConstant('{app}\install-summary.log') + #13#10#13#10 + 'Click Finish to exit Setup.';
  end;
  { A control file with no global password leaves this computer NOT managed -
    also what a typo in the key name, or an old file, ends in.  Said once, as
    SD Core for Linux Solo says it; no dialog. }
  if (CurPageID = wpFinished) and UseControl and (CfGlobal = '') then
    WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
      'The control file gives no global password, so this computer will NOT be managed by an SD Core server.';
  { SOLO 37: where the old folder went.  It stays until the user deletes it. }
  if (CurPageID = wpFinished) and (KeptFolder <> '') then
  begin
    if ReloadChosen then
      WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
        'Your saved data and configuration were reloaded. The previous folder is kept as ' + KeptFolder +
        '; delete it when you are satisfied.'
    else
      WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
        'Your saved data was moved to ' + KeptFolder + '. Nothing was deleted.';
  end;
  { SOLO 39: the label is only as tall as Inno's short default text needs, so whatever is added above is cut off
    at the bottom - the failure text lost its last line on the first try (seen in the guest), and the two
    sentences above would be clipped the same way.  Fitted once, after the last of them. }
  if CurPageID = wpFinished then
    WizardForm.FinishedLabel.AdjustHeight;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Problem: String;
begin
  Result := True;
  Problem := '';
  if CurPageID = AdminPage.ID then
    Problem := PasswordProblem(AdminPage.Values[0], AdminPage.Values[1])
  else if CurPageID = GlobalPage.ID then
  begin
    { SOLO 36: both boxes blank is the answer "no global password" - not
      managed.  Anything else is a password and keeps every rule. }
    if (GlobalPage.Values[0] = '') and (GlobalPage.Values[1] = '') then
      Exit;
    if (GlobalPage.Values[0] = '') or (GlobalPage.Values[1] = '') then
      Problem := 'The passwords do not match.'
    else
      Problem := PasswordProblem(GlobalPage.Values[0], GlobalPage.Values[1]);
    if (Problem = '') and (GlobalPage.Values[0] = AdminPage.Values[0]) then
      Problem := 'Use a password different from the administrator password.';
    { Ruling 19: one login name, two passwords, the user's checked first - an
      equal global password would land the master in an ordinary session.
      Checked here since 28 Sep 26: the global page now comes after the
      account page.  Unchanged in the control-file path, where the global
      password comes from the file and no account password is asked. }
    if (Problem = '') and (GlobalPage.Values[0] = AccountPage.Values[0]) then
      Problem := 'Use a password different from the account password.';
  end
  else if CurPageID = AccountPage.ID then
    Problem := PasswordProblem(AccountPage.Values[0], AccountPage.Values[1]);
  if Problem <> '' then
  begin
    MsgBox(Problem, mbError, MB_OK);
    Result := False;
  end;
end;

{ An upgrade replaces sd.exe, so a running SD is stopped first. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  SdExe: String;
begin
  Result := '';
  SdExe := SoloRoot + '\usr\bin\sd-solo.exe';
  { An install from before the rename has the server as sd.exe. }
  if (not FileExists(SdExe)) and FileExists(SoloRoot + '\usr\bin\sd.exe') then
    SdExe := SoloRoot + '\usr\bin\sd.exe';
  if FileExists(SdExe) then
  begin
    Exec(SdExe, '-stop', SoloRoot + '\usr\bin', SW_HIDE, ewWaitUntilTerminated, Code);
    Log('SD Core Solo: sd -stop before copying, exit ' + IntToStr(Code));
  end;
  { 06 Oct 26 - SOLO 37: kept data is moved aside, whichever way the user answered - "yes" copies what it
    needs back from there (solo-setup.ps1 -ReloadFrom), "no" leaves it.  It is never deleted (the owner's
    rule for every question here).  A move that fails stops the install before anything is written, with
    the reason, rather than installing over the data. }
  if KeptWasFound then
  begin
    KeptFolder := SoloRoot + '.kept-' + GetDateTimeString('yyyymmdd-hhnnss', '-', ':');
    if DirExists(KeptFolder) or FileExists(KeptFolder) then
    begin
      Result := 'Cannot set the saved data aside: ' + KeptFolder + ' already exists.';
      KeptFolder := '';
      Exit;
    end;
    if not MoveFileW(SoloRoot, KeptFolder) then
    begin
      Result := 'Cannot set the saved data aside: ' + SoloRoot + ' could not be moved to ' + KeptFolder +
                ' (error ' + IntToStr(DLLGetLastError) + '). Close anything using it and run the installer again.';
      Log('SD Core Solo: ' + Result);
      KeptFolder := '';
      Exit;
    end;
    Log('SD Core Solo: saved data moved to ' + KeptFolder);
  end;
end;

procedure AppendSummary(Title, ReportPath: String);
var
  Report: AnsiString;
begin
  if not LoadStringFromFile(ReportPath, Report) then
    Report := '(no report at ' + ReportPath + ')';
  SaveStringToFile(ExpandConstant('{app}\install-summary.log'),
    '=== ' + Title + ' ' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') + #13#10 +
    String(Report) + #13#10, True);
  Log('SD Core Solo: ' + Title + #13#10 + String(Report));
end;

procedure AddToUserPath(Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
    Paths := '';
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0 then
    Exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then
    Paths := Paths + ';';
  RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Paths + Dir);
end;

procedure RemoveFromUserPath(Dir: String);
var
  Paths: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
    Exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then
    Exit;
  Delete(Paths, P, Length(Dir) + 1);
  RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Copy(Paths, 2, Length(Paths) - 2));
end;

var
  LastMachineReport: String;

{ 06 Oct 26 (SOLO 31).  The names of the machine-step sections that failed, from the report's own
  "FAILED STEPS : a, b" line (solo-machine.ps1), or '' when there is no such line.  The dialog used
  to say "startup task, firewall and ssh" for any failure, including one check failing while all
  three had worked. }
function MachineFailedSteps: String;
var
  Text: AnsiString;
  S: String;
  P, E: Integer;
begin
  Result := '';
  if (LastMachineReport = '') or not LoadStringFromFile(LastMachineReport, Text) then
    Exit;
  S := String(Text);
  P := Pos('FAILED STEPS : ', S);
  if P = 0 then
    Exit;
  S := Copy(S, P + Length('FAILED STEPS : '), Length(S));
  E := Pos(#13, S);
  if E = 0 then
    E := Pos(#10, S);
  if E > 0 then
    S := Copy(S, 1, E - 1);
  Result := Trim(S);
end;

function RunMachineStep(Action, Extra: String): Integer;
var
  Params, ResultPath: String;
  Code: Integer;
begin
  ResultPath := ExpandConstant('{tmp}\solo-machine.txt');
  LastMachineReport := ResultPath;
  DeleteFile(ResultPath);
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}') +
            '\solo-machine.ps1" -Action ' + Action + ' -ForUser "' + ForUser +
            '" -AppDir "' + ExpandConstant('{app}') + '" -Result "' + ResultPath + '"' + Extra;
  Log('SD Core Solo: runas ' + PowerShellExe + ' ' + Params);
  if not ShellExec('runas', PowerShellExe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
  begin
    Log('SD Core Solo: the elevated step did not start, code ' + IntToStr(Code));
    Result := -1;
  end
  else
    Result := Code;
  AppendSummary('solo-machine ' + Action + ' (exit ' + IntToStr(Result) + ')', ResultPath);
end;

function YesNo(B: Boolean): String;
begin
  if B then
    Result := 'yes'
  else
    Result := 'no';
end;

{ 06 Oct 26 - SOLO 36: what the installer decided, before any step runs, in
  install-summary.log.  Never a password.  The one fact an administrator may
  not have meant - no global password, so not managed - is said in words. }
procedure AppendChoices;
var
  S: String;
begin
  S := '=== installer choices ' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') + #13#10 +
       'new tree       : ' + YesNo(DataTreeWasAbsent) + #13#10 +
       'control file   : ' + YesNo(UseControl) + #13#10 +
       'managed        : ' + YesNo(Managed);
  if not DataTreeWasAbsent then
    S := S + ' (read from the tree; an upgrade never adds, changes or removes the global password)'
  else if Managed then
    S := S + ' (a global password was given)'
  else
    S := S + ' (no global password: this computer is NOT managed by an SD Core server)';
  S := S + #13#10;
  { SOLO 37: what happened to kept data - the answer, and where the old folder is. }
  if KeptFolder <> '' then
  begin
    if ReloadChosen then
      S := S + 'saved data     : RELOAD - the kept data and sd.conf go into the new tree; the old folder is ' + KeptFolder + #13#10
    else
      S := S + 'saved data     : START CLEAN - the kept data was moved to ' + KeptFolder + ', not reloaded' + #13#10;
  end;
  if SoloWasInstalled then
    S := S + 'api and ssh    : not asked on an upgrade; the install keeps what it has' + #13#10
  else
    S := S + 'api            : ' + YesNo(ApiWanted) + '   reachable from other computers: ' + YesNo(ApiNetworkWanted) + #13#10 +
             'ssh            : ' + YesNo(SshWanted) + '   reachable from other computers: ' + YesNo(SshOpenWanted) +
             '   OpenSSH package to install: ' + YesNo(SshWanted and not SshServerWasFound) + #13#10;
  SaveStringToFile(ExpandConstant('{app}\install-summary.log'), S + #13#10, True);
  Log('SD Core Solo: ' + S);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Params, ReportPath, Extra, Failed: String;
  Code: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Failed := '';
  AppendChoices;

  { 0. Python, per-user, unelevated (ruling 17).  InstallLauncherAllUsers=0, or
    the launcher alone would want elevation.  PrependPath=1: the helper finds
    python3.dll by PATH (SOLO 14).  Judged by the exit code AND by a Python
    3.13+ being registered afterwards.
    27 Sep 26 - RULING 24: "always install python in both modes" - no box, and
    on upgrades too: whenever no Python 3.13+ is registered (PythonExeOffered;
    the .exe is always beside the installer, ruling 23).  A usable Python
    already registered is left alone. }
  if PythonExeOffered then
  begin
    ReportPath := ExpandConstant('{app}\python-install.log');
    Params := '/quiet InstallAllUsers=0 InstallLauncherAllUsers=0 PrependPath=1 ' +
              'Include_test=0 /log "' + ReportPath + '"';
    Log('SD Core Solo: ' + PythonExePath + ' ' + Params);
    if not Exec(PythonExePath, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
      Code := -1;
    SaveStringToFile(ExpandConstant('{tmp}\python.txt'),
      'installer : ' + PythonExePath + #13#10 +
      'arguments : ' + Params + #13#10 +
      'exit      : ' + IntToStr(Code) + #13#10 +
      'registered afterwards (HKCU PythonCore 3.13+): ' + IntToStr(Ord(PythonInHive(HKCU))) + #13#10 +
      'its own log: ' + ReportPath + #13#10, False);
    AppendSummary('python (exit ' + IntToStr(Code) + ')', ExpandConstant('{tmp}\python.txt'));
    if (Code <> 0) or not PythonInHive(HKCU) then
      Failed := Failed + '  Python' + #13#10;
  end;

  { 1. The account and, on a new tree, the passwords - unelevated. }
  ReportPath := ExpandConstant('{tmp}\solo-setup.txt');
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}') +
            '\solo-setup.ps1" -AppDir "' + ExpandConstant('{app}') + '" -User "' +
            GetUserNameString + '" -Report "' + ReportPath + '"';
  if DataTreeWasAbsent then
  begin
    Params := Params + ' -Passwords';
    { SOLO 37: reload the kept data (moved aside by PrepareToInstall) into this new tree. }
    if ReloadChosen and (KeptFolder <> '') then
      Params := Params + ' -ReloadFrom "' + KeptFolder + '"';
    SetEnvironmentVariable('SD_SOLO_ADMIN_PW', AdminPage.Values[0]);
    if Managed then
    begin
      Params := Params + ' -Global';
      SetEnvironmentVariable('SD_SOLO_GLOBAL_PW', GlobalPage.Values[0]);
    end;
    SetEnvironmentVariable('SD_SOLO_ACCOUNT_PW', AccountPage.Values[0]);
    { 28 Sep 26 - ruling 34: the control file's deny-verbs, on a new tree only
      (an existing tree keeps its list; the server changes it with DENY.VERBS). }
    if UseControl and (CfDeny <> '') then
      SetEnvironmentVariable('SD_SOLO_DENY_VERBS', CfDeny);
  end
  else
    { A data tree already existed: its one account's live VOC predates
      whatever NEWVOC this release ships (upgrade, or a kept tree reinstalled
      over, or a tree moved from another Windows user - all three leave an
      account whose VOC was never rebuilt from the new templates). }
    Params := Params + ' -Upgrade';
  if not Exec(PowerShellExe, Params, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  SetEnvironmentVariable('SD_SOLO_ADMIN_PW', '');
  SetEnvironmentVariable('SD_SOLO_GLOBAL_PW', '');
  SetEnvironmentVariable('SD_SOLO_ACCOUNT_PW', '');
  SetEnvironmentVariable('SD_SOLO_DENY_VERBS', '');
  AppendSummary('solo-setup (exit ' + IntToStr(Code) + ')', ReportPath);
  if Code <> 0 then
    Failed := Failed + '  account and passwords' + #13#10;

  { 2. PATH - always, both modes (ruling 24). }
  AddToUserPath(ExpandConstant('{app}\usr\bin'));

  { 3. The one elevated step. }
  if SoloWasInstalled then
  begin
    { 06 Oct 26 - SOLO 36: an upgrade asks nothing and keeps the API and ssh as they are.  It used to
      pass -Managed so that solo-machine.ps1 opened Solo's ssh port for a managed computer with no rule
      for it; that fallback is gone (a managed computer's user may have chosen otherwise). }
    Code := RunMachineStep('Upgrade', '');
  end
  else
  begin
    { 06 Oct 26 - SOLO 36: each choice is its box, or the control file's answer; nothing is forced. }
    Extra := '';
    if ApiWanted then
      Extra := Extra + ' -Api';
    if ApiNetworkWanted then
      Extra := Extra + ' -ApiNetwork';
    { Solo's ssh is its OWN sshd on port 4251 (SOLO 28), set up only when it is wanted (SOLO 36), from an
      OpenSSH server already installed or from the MSI beside the installer.  Its firewall rule
      (solo-ssh-firewall.ps1) is open to other computers or this-computer-only - the same shape as the
      API's.  "leave" means no Solo sshd and no package. }
    if SshWanted then
    begin
      if not SshServerWasFound then
        Extra := Extra + ' -SshMsi "' + SshMsiPath + '"';
      if SshOpenWanted then
        Extra := Extra + ' -SshScope open'
      else
        Extra := Extra + ' -SshScope restrict';
      Extra := Extra + ' -SshIntoSd';
    end
    else
      Extra := Extra + ' -SshScope leave';
    Code := RunMachineStep('Install', Extra);
  end;
  { 06 Oct 26 (SOLO 31): name only the sections that failed.  Exit 2 is the script REFUSING (nothing
    changed) and -1 is it not starting: those are "not run".  Any other failure with no names in the
    report keeps the old three-step wording rather than saying nothing. }
  if (Code = -1) or (Code = 2) then
    Failed := Failed + '  startup task, firewall and ssh (not run)' + #13#10
  else if Code <> 0 then
  begin
    if MachineFailedSteps <> '' then
      Failed := Failed + '  ' + MachineFailedSteps + #13#10
    else
      Failed := Failed + '  startup task, firewall and ssh' + #13#10;
  end;

  StepsNotCompleted := Failed;
  if Failed <> '' then
  begin
    Log('SD Core Solo: steps not completed: ' + Failed);
    MsgBox('These steps did not complete:' + #13#10 + Failed + #13#10 +
           'Details: ' + ExpandConstant('{app}\install-summary.log'), mbError, MB_OK);
  end;
end;

function InitializeUninstall: Boolean;
begin
  UseWindowsPowerShellModules;
  Result := True;
end;

{ 06 Oct 26 - SOLO 37 (owner: uninstall asks about keeping the data AND the
  configuration, and removal and reinstall work the same on both ports - SD Core
  for Linux Solo's way).  PROJECT_STATUS 5.9.1's rule, built here for the first
  time: the default keeps the user's data, the question names what Delete
  destroys and where, and a SILENT uninstall never deletes it.  KEEP leaves the
  account's files and sd.conf in place and removes everything else - the
  passwords, the audit trail, the deny list, GLOBAL.BP.OUT, the TLS key, the ssh
  pieces - with a stamp (.sdcore-kept) so a new install can tell kept data from
  any other folder.  DELETE removes the whole folder.  Keep and Delete are command
  links, Keep first so it is the focused one (the multi-user sd.iss KeepOrDelete
  measured that Escape does nothing and that the order is forced by focus
  following Labels[0]).  It returns "the user chose Delete". }
function KeepOrDelete(const Instruction, Text: String): Boolean;
var
  Labels: TArrayOfString;
begin
  SetArrayLength(Labels, 2);
  Labels[0] := 'Keep';
  Labels[1] := 'Delete';
  Result := TaskDialogMsgBox(Instruction, Text, mbConfirmation, MB_YESNO, Labels, 0) = IDNO;
end;

{ Everything inside Root except the uninstaller's own files (unins*, which Setup
  removes after this returns) and the names in KeepDirs and KeepFiles (each is
  '|name|name|', lower case).  A reparse point (a junction, a symbolic link) is
  never followed and never deleted: it makes the result False. }
function RemoveFolderContents(const Root, KeepDirs, KeepFiles: String): Boolean;
var
  FR: TFindRec;
  Full, Tag: String;
  IsDirectory, Keep: Boolean;
begin
  Result := True;
  if FindFirst(AddBackslash(Root) + '*', FR) then
  begin
    try
      repeat
        if (FR.Name <> '.') and (FR.Name <> '..') then
        begin
          Full := AddBackslash(Root) + FR.Name;
          IsDirectory := (FR.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0;
          Tag := '|' + Lowercase(FR.Name) + '|';
          if IsDirectory then
            Keep := Pos(Tag, KeepDirs) > 0
          else
            Keep := (Pos(Tag, KeepFiles) > 0) or (CompareText(Copy(FR.Name, 1, 5), 'unins') = 0);
          if not Keep then
          begin
            if (FR.Attributes and $400) <> 0 then
              Result := False
            else if IsDirectory then
            begin
              if not DelTree(Full, True, True, True) then
                Result := False;
            end
            else if not DeleteFile(Full) then
              Result := False;
          end;
        end;
      until not FindNext(FR);
    finally
      FindClose(FR);
    end;
  end;
end;

{ KEEP: the account's files and sd.conf stay; everything else goes; the stamp is
  written last, and only when there is an account to keep. }
function KeepDataOnly(const Root: String): Boolean;
begin
  Result := RemoveFolderContents(Root, '|user_accounts|', '|sd.conf|.sdcore-kept|');
  if DirExists(Root + '\user_accounts') then
    if not RemoveFolderContents(Root + '\user_accounts', '|sduser|', '|') then
      Result := False;
  if DirExists(Root + '\user_accounts\sduser') then
    SaveStringToFile(Root + '\.sdcore-kept',
      'SD Core Solo for Windows {#AppVer} - kept data' + #13#10 +
      'kept ' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') + #13#10, False);
end;

procedure OfferDataRemoval;
var
  Root: String;
  ChoseDelete: Boolean;
begin
  Root := ExpandConstant('{app}');
  { A SILENT UNINSTALL NEVER DELETES THE USER'S DATA: there is nobody to answer, so it is Keep.  Written
    as two statements, not "UninstallSilent or not KeepOrDelete(...)": Pascal Script does not promise to
    skip the right-hand side, and a dialog in a silent uninstall is the failure this exists to prevent. }
  ChoseDelete := False;
  if not UninstallSilent then
    ChoseDelete := KeepOrDelete('Keep or delete your SD Core Solo data and configuration?',
      Root + #13#10#13#10 +
      'Keep leaves your account sduser with its data, and sd.conf, in this folder. A new installation ' +
      'offers them back.' + #13#10#13#10 +
      'Keep removes these: every password, the audit trail, the list of denied commands, GLOBAL.BP.OUT, ' +
      'the API''s TLS key, your ssh key file, the system files and the install logs.' + #13#10#13#10 +
      'Delete removes the whole folder, for good.');
  if not ChoseDelete then
  begin
    if KeepDataOnly(Root) then
    begin
      Log('SD Core Solo: the account and sd.conf are kept in ' + Root);
      if not UninstallSilent then
        MsgBox('Your account and sd.conf were kept in ' + Root + '.' + #13#10#13#10 +
               'A new installation offers them back. Deleting the folder removes them for good.',
               mbInformation, MB_OK);
    end
    else
      MsgBox('Some of ' + Root + ' could not be removed. The account and sd.conf were left in place.',
             mbError, MB_OK);
    Exit;
  end;
  if RemoveFolderContents(Root, '|', '|') then
    MsgBox('Your SD Core Solo data and configuration were deleted from ' + Root + '.', mbInformation, MB_OK)
  else
    MsgBox('Some of ' + Root + ' could not be deleted. Delete the folder yourself.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  { After Setup has removed what it installed, so what is left is the data. }
  if CurUninstallStep = usPostUninstall then
    OfferDataRemoval;
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{app}\usr\bin\sd-solo.exe'), '-stop', ExpandConstant('{app}\usr\bin'),
         SW_HIDE, ewWaitUntilTerminated, Code);
    Log('SD Core Solo: sd -stop, exit ' + IntToStr(Code));
    if RunMachineStep('Remove', '') <> 0 then
      MsgBox('The startup task, firewall rule or ssh setting could not be removed.' + #13#10 +
             'Details: ' + ExpandConstant('{app}\install-summary.log'), mbError, MB_OK);
    RemoveFromUserPath(ExpandConstant('{app}\usr\bin'));
  end;
end;
