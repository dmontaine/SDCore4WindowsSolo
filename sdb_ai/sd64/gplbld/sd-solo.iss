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
;      administrator password and, managed mode only, the global one (rulings
;      12, 15), sd -stop.  Sessions need a started SD; the stop hands SD over
;      to the task.
;   2. PATH, the user's own (HKCU).
;   3. solo-machine.ps1, elevated: the S4U startup task, registered and started
;      (SOLO 3, ruling 2); API firewall; ssh firewall scope (ruling 8); and,
;      wherever OpenSSH is found, the sshd_config block that lands this user in
;      SD (ruling 5) with sshd set to start at boot - not a choice.
;
; WHAT IS NOT HERE YET (SOLO 8 in PROJECT_STATUS.md): the opt-in data removal
; at uninstall (5.9.1 - the data is always kept for now), ruling 13's deletion
; of the gpl.bp source at the end of install, and dropping the multi-user
; scripts from stage.py's ship list (they are copied and never run).
;
; DO NOT MERGE WITH sd.iss.  sd.iss is the multi-user product and still builds
; it; this file shares its generated upgrade.iss and nothing else.

#ifndef Stage
  #define Stage "..\..\stage"
#endif
#ifndef AppVer
  #define AppVer "S1.1-0"
#endif
#define AppName      "SD Core Solo"
#define AppPublisher "String Database"
#define SoloDir      "{%USERPROFILE}\SDCoreSolo"
; upgrade.iss names the data root {#DataDir}; in Solo it is the install folder.
#define DataDir      "{app}"

; A STAGE THAT HAS BEEN PROBED CARRIES TEST CREDENTIALS AND A TEST ACCOUNT
; (probe-solo-stage.py sets passwords and makes the builder's own account in
; it).  Shipping either would give every install somebody else's password, so
; the build refuses.  stage.py --force makes a clean one.
#if FileExists(AddBackslash(Stage) + "SDCoreSolo\sdsys\$cred\$ADMIN") || \
    FileExists(AddBackslash(Stage) + "SDCoreSolo\sdsys\$cred\$GLOBAL")
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
Name: "addtopath"; Description: "Add SD Core Solo to my PATH"
Name: "api"; Description: "Provide the SD Core API (port 4243)"; Flags: unchecked
Name: "api\network"; Description: "Let other computers reach it"; Flags: unchecked dontinheritcheck
Name: "sshnetwork"; Description: "Let other computers reach this computer's ssh server"; \
    Flags: unchecked; Check: SshRulePresent
; 25 Sep 26 - NO BOX FOR "ssh lands in SD".  Ruling 5 makes it the product, not
; a choice; the box that was here ("Start SD Core Solo when I sign in over
; ssh") read to the owner as starting the SERVER on sign-in, which it never
; did - SD starts at boot from the task.  Wherever OpenSSH is found the block
; is written and sshd is set to start at boot (solo-machine.ps1).

[Dirs]
Name: "{app}\user_accounts"; Flags: uninsneveruninstall
Name: "{app}\group_accounts"; Flags: uninsneveruninstall

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

; sd.conf: with APIPORT when the API box is ticked, without it (no listener)
; when it is not - sd.iss's rule, stage.py derives the second from the first.
; Never overwritten, never uninstalled.
Source: "{#Stage}\SDCoreSolo\sd.conf"; DestDir: "{app}"; \
    Flags: onlyifdoesntexist uninsneveruninstall; Check: ApiWanted
Source: "{#Stage}\SDCoreSolo\sd-standalone.conf"; DestDir: "{app}"; DestName: "sd.conf"; \
    Flags: onlyifdoesntexist uninsneveruninstall; Check: not ApiWanted

#include AddBackslash(Stage) + "upgrade.iss"

[Code]
const
  MultiUserKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{9F2B7C41-3D6A-4E58-9B0F-5C7A1E2D8B34}_is1';
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
  SshServerWasFound, SshRuleWasFound, SshRuleWasOpen: Boolean;
  ModePage: TInputOptionWizardPage;
  AdminPage, GlobalPage: TInputQueryWizardPage;

function SetEnvironmentVariable(lpName: String; lpValue: String): BOOL;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

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

function InitializeSetup: Boolean;
var
  ScopeFile: String;
  Scope: AnsiString;
  Code: Integer;
begin
  UseWindowsPowerShellModules;
  if RegKeyExists(HKLM64, MultiUserKey) or
     FileExists(ExpandConstant('{commonpf64}\SD\usr\bin\sd.exe')) then
  begin
    MsgBox('SD Core is installed on this computer. Uninstall it first.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  DataTreeWasAbsent := not DirExists(SoloRoot + '\sdsys');
  SoloWasInstalled := RegKeyExists(HKCU, SoloKey);
  SshServerWasFound := FileExists(ExpandConstant('{sys}\OpenSSH\sshd.exe')) or
                       FileExists(ExpandConstant('{commonpf64}\OpenSSH\sshd.exe'));
  { The box shows the truth: an ssh port already open starts ticked, so leaving
    it alone changes nothing (sd.iss, PRE_RELEASE_FIXES 76). }
  SshRuleWasFound := False;
  SshRuleWasOpen := False;
  if SshServerWasFound and not SoloWasInstalled then
  begin
    ExtractTemporaryFile('ssh-firewall.ps1');
    ScopeFile := ExpandConstant('{tmp}\ssh-scope.txt');
    if Exec(PowerShellExe, '-NoProfile -ExecutionPolicy Bypass -File "' +
            ExpandConstant('{tmp}\ssh-firewall.ps1') + '" -ScopeFile "' + ScopeFile + '"',
            '', SW_HIDE, ewWaitUntilTerminated, Code) and
       LoadStringFromFile(ScopeFile, Scope) then
    begin
      Log('SD Core Solo: ssh firewall scope "' + String(Scope) + '", exit ' + IntToStr(Code));
      SshRuleWasFound := (Trim(String(Scope)) = 'open') or (Trim(String(Scope)) = 'restricted');
      SshRuleWasOpen := Trim(String(Scope)) = 'open';
    end;
  end;
  Log('SD Core Solo: data tree absent=' + IntToStr(Ord(DataTreeWasAbsent)) +
      ' installed=' + IntToStr(Ord(SoloWasInstalled)) +
      ' sshd=' + IntToStr(Ord(SshServerWasFound)) +
      ' sshrule=' + IntToStr(Ord(SshRuleWasFound)) + ' open=' + IntToStr(Ord(SshRuleWasOpen)));
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

function SshServerPresent: Boolean;
begin
  Result := SshServerWasFound;
end;

function SshRulePresent: Boolean;
begin
  Result := SshRuleWasFound;
end;

function ApiWanted: Boolean;
begin
  Result := WizardIsTaskSelected('api');
end;

function Managed: Boolean;
begin
  Result := ModePage.SelectedValueIndex = 1;
end;

procedure InitializeWizard;
begin
  ModePage := CreateInputOptionPage(wpWelcome, 'Mode', 'How will this computer use SD Core Solo?',
    'The mode cannot be changed later without reinstalling.', True, False);
  ModePage.Add('Standalone');
  ModePage.Add('Managed client of an SD Core server');
  ModePage.SelectedValueIndex := 0;

  AdminPage := CreateInputQueryPage(ModePage.ID, 'Administrator password',
    'This password unlocks the administrator commands.', '');
  AdminPage.Add('Password:', True);
  AdminPage.Add('Confirm password:', True);

  GlobalPage := CreateInputQueryPage(AdminPage.ID, 'Global password',
    'The SD Core server uses this password to manage this computer.', '');
  GlobalPage.Add('Password:', True);
  GlobalPage.Add('Confirm password:', True);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if (PageID = ModePage.ID) or (PageID = AdminPage.ID) then
    Result := not DataTreeWasAbsent
  else if PageID = GlobalPage.ID then
    Result := (not DataTreeWasAbsent) or (not Managed)
  else if PageID = wpSelectTasks then
    Result := SoloWasInstalled;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpSelectTasks) and SshRuleWasOpen then
    WizardSelectTasks('sshnetwork');
end;

{ Letters, digits and punctuation: the password reaches sd's standard input
  through .NET, and Windows PowerShell 5.1 cannot set that pipe's encoding. }
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
    for I := 1 to Length(A) do
      if (Ord(A[I]) < 33) or (Ord(A[I]) > 126) then
      begin
        Result := 'Use letters, digits and punctuation only.';
        Exit;
      end;
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
    Problem := PasswordProblem(GlobalPage.Values[0], GlobalPage.Values[1]);
    if (Problem = '') and (GlobalPage.Values[0] = AdminPage.Values[0]) then
      Problem := 'Use a password different from the administrator password.';
  end;
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
  SdExe := SoloRoot + '\usr\bin\sd.exe';
  if FileExists(SdExe) then
  begin
    Exec(SdExe, '-stop', SoloRoot + '\usr\bin', SW_HIDE, ewWaitUntilTerminated, Code);
    Log('SD Core Solo: sd -stop before copying, exit ' + IntToStr(Code));
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

function RunMachineStep(Action, Extra: String): Integer;
var
  Params, ResultPath: String;
  Code: Integer;
begin
  ResultPath := ExpandConstant('{tmp}\solo-machine.txt');
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

procedure CurStepChanged(CurStep: TSetupStep);
var
  Params, ReportPath, Extra, Failed: String;
  Code: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Failed := '';

  { 1. The account and, on a new tree, the passwords - unelevated. }
  ReportPath := ExpandConstant('{tmp}\solo-setup.txt');
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}') +
            '\solo-setup.ps1" -AppDir "' + ExpandConstant('{app}') + '" -User "' +
            GetUserNameString + '" -Report "' + ReportPath + '"';
  if DataTreeWasAbsent then
  begin
    Params := Params + ' -Passwords';
    SetEnvironmentVariable('SD_SOLO_ADMIN_PW', AdminPage.Values[0]);
    if Managed then
    begin
      Params := Params + ' -Global';
      SetEnvironmentVariable('SD_SOLO_GLOBAL_PW', GlobalPage.Values[0]);
    end;
  end;
  if not Exec(PowerShellExe, Params, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  SetEnvironmentVariable('SD_SOLO_ADMIN_PW', '');
  SetEnvironmentVariable('SD_SOLO_GLOBAL_PW', '');
  AppendSummary('solo-setup (exit ' + IntToStr(Code) + ')', ReportPath);
  if Code <> 0 then
    Failed := Failed + '  account and passwords' + #13#10;

  { 2. PATH. }
  if WizardIsTaskSelected('addtopath') then
    AddToUserPath(ExpandConstant('{app}\usr\bin'));

  { 3. The one elevated step. }
  if SoloWasInstalled then
    Code := RunMachineStep('Upgrade', '')
  else
  begin
    Extra := '';
    if WizardIsTaskSelected('api') then
      Extra := Extra + ' -Api';
    if WizardIsTaskSelected('api\network') then
      Extra := Extra + ' -ApiNetwork';
    if not SshRuleWasFound then
      Extra := Extra + ' -SshScope leave'
    else if WizardIsTaskSelected('sshnetwork') then
      Extra := Extra + ' -SshScope open'
    else
      Extra := Extra + ' -SshScope restrict';
    if SshServerWasFound then
      Extra := Extra + ' -SshIntoSd';
    Code := RunMachineStep('Install', Extra);
  end;
  if Code = -1 then
    Failed := Failed + '  startup task, firewall and ssh (not run)' + #13#10
  else if Code <> 0 then
    Failed := Failed + '  startup task, firewall and ssh' + #13#10;

  if Failed <> '' then
    MsgBox('These steps did not complete:' + #13#10 + Failed + #13#10 +
           'Details: ' + ExpandConstant('{app}\install-summary.log'), mbError, MB_OK);
end;

function InitializeUninstall: Boolean;
begin
  UseWindowsPowerShellModules;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{app}\usr\bin\sd.exe'), '-stop', ExpandConstant('{app}\usr\bin'),
         SW_HIDE, ewWaitUntilTerminated, Code);
    Log('SD Core Solo: sd -stop, exit ' + IntToStr(Code));
    if RunMachineStep('Remove', '') <> 0 then
      MsgBox('The startup task, firewall rule or ssh setting could not be removed.' + #13#10 +
             'Details: ' + ExpandConstant('{app}\install-summary.log'), mbError, MB_OK);
    RemoveFromUserPath(ExpandConstant('{app}\usr\bin'));
  end;
end;
