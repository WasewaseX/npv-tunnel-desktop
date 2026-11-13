; ============================================================================
;  NPV Tunnel - per-user Windows installer (Inno Setup 6)
; ============================================================================
;  Design decisions that matter:
;   * PrivilegesRequired=lowest -> installs into %LOCALAPPDATA%\Programs, so the
;     user sees exactly one SmartScreen prompt and never a UAC prompt.
;   * ChangesAssociations=yes -> Setup tells Explorer the file associations
;     changed so double-click works immediately, no sign-out needed.
;   * The .npvt association is written under HKCU (Software\Classes) and is
;     also registered through the Default Programs "Capabilities" key so it
;     shows up in Settings > Apps > Default apps.
;   * The bundle is the self-contained single-file build, so no .NET runtime
;     or download is required on first run.
; ============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

#define MyAppName "NPV Tunnel"
#define MyAppPublisher "WasewaseX"
#define MyAppExeName "NpvTunnel.exe"
#define MyAppUrl "https://github.com/WasewaseX/npv-tunnel-desktop"
#define ProgId "NPVTunnel.npvt"

[Setup]
AppId={{8A1F6C74-2E5B-4C3D-9A11-5D7C2B0E4F31}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}/issues
AppUpdatesURL={#MyAppUrl}/releases
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
LicenseFile=..\LICENSE
InfoBeforeFile=installer-note.txt
OutputDir=..\dist
OutputBaseFilename=NpvTunnel-{#MyAppVersion}-win-x64-setup
SetupIconFile=..\src\NpvTunnel.App\Assets\npvtunnel.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesAssociations=yes
CloseApplications=yes
RestartApplications=no
MinVersion=10.0
ShowLanguageDialog=no
AllowNoIcons=yes
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "associate"; Description: "Open .npvt files with {#MyAppName} (double-click import)"; GroupDescription: "File associations:"

[Files]
Source: "..\dist\portable\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; ---- .npvt -> NPVTunnel.npvt -------------------------------------------------
Root: HKCU; Subkey: "Software\Classes\.npvt"; ValueType: string; ValueName: ""; ValueData: "{#ProgId}"; Flags: uninsdeletevalue; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\.npvt"; ValueType: string; ValueName: "Content Type"; ValueData: "application/x-npvt"; Flags: uninsdeletevalue; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\.npvt"; ValueType: string; ValueName: "PerceivedType"; ValueData: "text"; Flags: uninsdeletevalue; Tasks: associate

Root: HKCU; Subkey: "Software\Classes\{#ProgId}"; ValueType: string; ValueName: ""; ValueData: "NPV Tunnel configuration"; Flags: uninsdeletekey; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\{#ProgId}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\{#ProgId}\shell\open"; ValueType: string; ValueName: ""; ValueData: "Import into NPV Tunnel"; Tasks: associate
Root: HKCU; Subkey: "Software\Classes\{#ProgId}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: associate

; ---- Default Programs (Settings > Apps > Default apps) -----------------------
Root: HKCU; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}\Capabilities"; ValueType: string; ValueName: "ApplicationName"; ValueData: "{#MyAppName}"; Flags: uninsdeletekey; Tasks: associate
Root: HKCU; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}\Capabilities"; ValueType: string; ValueName: "ApplicationDescription"; ValueData: "Desktop client for VLESS, VMess, Trojan, Shadowsocks, SOCKS and Hysteria2 tunnels."; Tasks: associate
Root: HKCU; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}\Capabilities\FileAssociations"; ValueType: string; ValueName: ".npvt"; ValueData: "{#ProgId}"; Tasks: associate
Root: HKCU; Subkey: "Software\RegisteredApplications"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: "Software\{#MyAppPublisher}\{#MyAppName}\Capabilities"; Flags: uninsdeletevalue; Tasks: associate

; ---- Add/Remove Programs ----------------------------------------------------
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}_is1"; ValueType: string; ValueName: "DisplayIcon"; ValueData: "{app}\{#MyAppExeName}"; Tasks: associate
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}_is1"; ValueType: string; ValueName: "Publisher"; ValueData: "{#MyAppPublisher}"; Tasks: associate

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Start {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
{ Notify Explorer that associations changed so a double-click works right away. }
procedure SHChangeNotify(wEventId: Integer; uFlags: Integer; dwItem1: Integer; dwItem2: Integer);
  external 'SHChangeNotify@shell32.dll stdcall';

procedure DeinitializeSetup();
begin
  SHChangeNotify($08000000, 0, 0, 0);
end;

{ Refuse to run on anything older than Windows 10 build 17763 (Windows 11 first
  release is 22000). Keeps the .NET 8 desktop requirement honest. }
function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  if (Version.Major < 10) then
  begin
    MsgBox('NPV Tunnel requires Windows 10 or later.', mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;
