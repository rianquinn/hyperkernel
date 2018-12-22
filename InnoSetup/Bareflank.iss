; -- Example1.iss --
; Install bareflank.efi in the EFI partition, modify boot order to boot bareflank.efi first,
; install visr.inf and bareflank.inf drivers, update path to use executables in the installation
; directory. Reverse during uninstall.

[Setup]
AppName=Bareflank
AppVersion=1.0
DefaultDirName={pf}\Bareflank
DefaultGroupName=Bareflank
UninstallDisplayIcon={app}\RemoveBareflank.exe
Compression=lzma2
SolidCompression=yes
;OutputDir=userdocs:Inno Setup Examples Output
AlwaysRestart=yes
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=InstallBareflank
SetupIconFile=Francois.ico
WizardImageFile=Francois.bmp
WizardSmallImageFile=FrancoisSmall.bmp

[Files]
;Source: "Readme.txt"; DestDir: "{app}"; Flags: isreadme
Source: "bareflank.efi"; DestDir: "P:\EFI\Boot\"
Source: "bfack.exe"; DestDir: "{app}"
Source: "bfexec.exe"; DestDir: "{app}"
Source: "bfm.exe"; DestDir: "{app}"
Source: "cygstdc++-6.dll"; DestDir: "{app}"
Source: "cygwin1.dll"; DestDir: "{app}"
Source: "cyggcc_s-seh-1.dll"; DestDir: "{app}"
Source: "bareflank.inf"; Flags: dontcopy
Source: "bareflank.sys"; Flags: dontcopy
Source: "bareflank.cat"; Flags: dontcopy
Source: "builder.inf"; Flags: dontcopy
Source: "builder.sys"; Flags: dontcopy
Source: "builder.cat"; Flags: dontcopy
Source: "visr.inf"; Flags: dontcopy
Source: "visr.sys"; Flags: dontcopy
Source: "visr.cat"; Flags: dontcopy
Source: "devcon.exe"; DestDir: "{app}"
Source: "RemoveDrivers.bat"; DestDir: "{app}"
Source: "RemovePath.bat"; DestDir: "{app}"
Source: "vmlinux"; DestDir: "{app}"
Source: "vmlinux-hello"; DestDir: "{app}"
Source: "vmlinux-ndvm"; DestDir: "{app}"

[Icons]
;Name: "{group}\My Program"; Filename: "{app}\MyProg.exe"

[Run]

[UninstallRun]
Filename: "{app}\RemovePath.bat"; Flags: runhidden
Filename: "{app}\RemoveDrivers.bat"; Flags: runhidden

; Note: setx can't handle more than than 1024 characters in the path. It will truncate if this is exceeded. This can be bypassed by manually editing the registry
[Code]
function InitializeSetup(): Boolean;
var
  ResultCode: integer;
begin
  Exec('cmd.exe', '/C mountvol P: /S', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: integer;
begin
  if CurStep = ssPostInstall then
  begin
    ExtractTemporaryFile('visr.inf')
    ExtractTemporaryFile('visr.sys')
    ExtractTemporaryFile('visr.cat')
    ExtractTemporaryFile('builder.inf')
    ExtractTemporaryFile('builder.sys')
    ExtractTemporaryFile('builder.cat')
    ExtractTemporaryFile('bareflank.inf')
    ExtractTemporaryFile('bareflank.sys')
    ExtractTemporaryFile('bareflank.cat')
    Exec('cmd.exe', '/C mountvol P: /D', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C bcdedit /set {bootmgr} path \EFI\Boot\bareflank.efi', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C setx /m PATH "%PATH%{app}"'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C pnputil /add-driver "{tmp}\visr.inf"'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\builder""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" install "{tmp}\builder.inf" "ROOT\builder""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\bareflank""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" install "{tmp}\bareflank.inf" "ROOT\bareflank""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec('cmd.exe', '/C mountvol P: /S', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C del P:\EFI\Boot\bareflank.efi', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C mountvol P: /D', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', '/C bcdedit /set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\builder""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('cmd.exe', ExpandConstant('/C ""{app}\devcon.exe" remove "ROOT\bareflank""'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

function UninstallNeedRestart(): Boolean;
begin
  Result := True;
end;
