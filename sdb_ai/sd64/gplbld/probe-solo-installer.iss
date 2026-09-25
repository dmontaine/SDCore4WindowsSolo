; probe-solo-installer.iss - SOLO 1(c): can a PER-USER installer (no elevation)
; put Solo in the user's profile and still do the machine-wide jobs behind ONE
; UAC prompt?  A throwaway spike, never shipped.  It installs two scripts into
; %USERPROFILE%\SDCoreSoloSpike\app and, at the end, raises one UAC prompt for
; probe-solo-elevated.ps1, which registers and runs an S4U task FOR THE USER WHO
; RAN THIS INSTALLER, makes and removes a disabled firewall rule, reads the ssh
; configuration's location, cleans up, and writes a report shown here.
;
; Compile: ISCC.exe /O<output dir> probe-solo-installer.iss
; Run it by double-clicking, as the ordinary user - NOT "Run as administrator".

[Setup]
AppId=SDCoreSoloSpike
AppName=SD Core Solo installer spike
AppVersion=0.0-spike
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DefaultDirName={%USERPROFILE}\SDCoreSoloSpike\app
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
Uninstallable=no
OutputBaseFilename=probe-solo-installer
SetupLogging=yes

[Files]
Source: "probe-solo-elevated.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "probe-solo-s4u-payload.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  Ps, Params, ResultPath, UserProfile, ForUser: String;
  Code: Integer;
  Report: AnsiString;
begin
  if CurStep <> ssPostInstall then
    Exit;
  { The installer runs as the real user, so these name THEM - which is why they
    are passed to the elevated step rather than read there. }
  UserProfile := ExpandConstant('{%USERPROFILE}');
  ForUser := GetEnv('USERDOMAIN') + '\' + GetUserNameString;
  ResultPath := UserProfile + '\SDCoreSoloSpike\elevated-result.txt';
  DeleteFile(ResultPath);
  Ps := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}') +
            '\probe-solo-elevated.ps1" -ForUser "' + ForUser + '" -ForProfile "' +
            UserProfile + '" -AppDir "' + ExpandConstant('{app}') + '"';
  Log('SOLO spike: installer runs as ' + ForUser + ', admin=' + IntToStr(Ord(IsAdmin)));
  Log('SOLO spike: runas ' + Ps + ' ' + Params);
  if not ShellExec('runas', Ps, Params, '', SW_SHOWNORMAL, ewWaitUntilTerminated, Code) then
    MsgBox('The elevated step did not start (code ' + IntToStr(Code) +
           '; 1223 means the UAC prompt was declined).', mbError, MB_OK)
  else if LoadStringFromFile(ResultPath, Report) then
    MsgBox('This installer ran as ' + ForUser + ' (administrator token: ' +
           IntToStr(Ord(IsAdmin)) + '). The elevated step exited ' + IntToStr(Code) +
           '. Its report, also in ' + ResultPath + ':' + #13#10#13#10 + String(Report),
           mbInformation, MB_OK)
  else
    MsgBox('The elevated step exited ' + IntToStr(Code) + ' and wrote no report at ' +
           ResultPath, mbError, MB_OK);
end;
