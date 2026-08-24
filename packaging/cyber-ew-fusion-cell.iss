; Inno Setup script for Cyber-EW Fusion Cell.
; Build after PyInstaller creates dist\Cyber-EW Fusion Cell.exe.

#define MyAppName "Cyber-EW Fusion Cell"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "Cyber-EW Fusion Cell"
#define MyAppExeName "Cyber-EW Fusion Cell.exe"

[Setup]
AppId={{A62D70D0-58E5-4B35-9E48-C4D0478D0162}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Cyber-EW Fusion Cell
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
InfoBeforeFile=INSTALL_READINESS.txt
OutputDir=..\dist\installer
OutputBaseFilename=Cyber-EW-Fusion-Cell-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\config\deployment_profiles.json"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "..\data\signatures\*"; DestDir: "{userappdata}\Cyber-EW Fusion Cell\data\signatures"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\data\threat_intel\*"; DestDir: "{userappdata}\Cyber-EW Fusion Cell\data\threat_intel"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\docs\ENTERPRISE_DEPLOYMENT.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{userappdata}\Cyber-EW Fusion Cell\data\inputs\live"
Name: "{userappdata}\Cyber-EW Fusion Cell\data\outputs"
Name: "{userappdata}\Cyber-EW Fusion Cell\logs"

[Icons]
Name: "{group}\Cyber-EW Fusion Cell"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\Cyber-EW Fusion Cell"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "mode\demo"; Description: "Demo mode - generated telemetry for demos and training"; GroupDescription: "Operation mode:"; Flags: exclusive
Name: "mode\hybrid"; Description: "Hybrid mode - generated telemetry plus live local collectors"; GroupDescription: "Operation mode:"; Flags: exclusive unchecked
Name: "mode\production"; Description: "Production mode - disable generated telemetry and use real inputs only"; GroupDescription: "Operation mode:"; Flags: exclusive unchecked
Name: "collectors\eventlog"; Description: "Enable Windows Event Log and Sysmon collector"; GroupDescription: "Live collectors:"; Flags: checkedonce
Name: "collectors\pcap"; Description: "Enable Npcap live packet capture connector (requires Npcap)"; GroupDescription: "Live collectors:"; Flags: unchecked
Name: "collectors\syslog"; Description: "Prepare local UDP 514 syslog receiver"; GroupDescription: "Live collectors:"; Flags: checkedonce

[Registry]
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "DataDir"; ValueData: "{userappdata}\Cyber-EW Fusion Cell\data"
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "LogDir"; ValueData: "{userappdata}\Cyber-EW Fusion Cell\logs"
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "Profile"; ValueData: "desktop"
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "OperationMode"; ValueData: "demo"; Check: IsTaskSelected('mode\demo')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "OperationMode"; ValueData: "hybrid"; Check: IsTaskSelected('mode\hybrid')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "OperationMode"; ValueData: "production"; Check: IsTaskSelected('mode\production')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnableEventLog"; ValueData: "1"; Check: IsTaskSelected('collectors\eventlog')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnableEventLog"; ValueData: "0"; Check: IsTaskNotSelected('collectors\eventlog')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnablePacketCapture"; ValueData: "1"; Check: IsTaskSelected('collectors\pcap')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnablePacketCapture"; ValueData: "0"; Check: IsTaskNotSelected('collectors\pcap')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "EventLogChannels"; ValueData: "Security,System,Application,Microsoft-Windows-Sysmon/Operational"; Check: IsTaskSelected('collectors\eventlog')
Root: HKCU; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "SyslogPort"; ValueData: "514"; Check: IsTaskSelected('collectors\syslog')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "DataDir"; ValueData: "{userappdata}\Cyber-EW Fusion Cell\data"
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "LogDir"; ValueData: "{userappdata}\Cyber-EW Fusion Cell\logs"
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "Profile"; ValueData: "desktop"
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "OperationMode"; ValueData: "demo"; Check: IsTaskSelected('mode\demo')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "OperationMode"; ValueData: "hybrid"; Check: IsTaskSelected('mode\hybrid')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "OperationMode"; ValueData: "production"; Check: IsTaskSelected('mode\production')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnableEventLog"; ValueData: "1"; Check: IsTaskSelected('collectors\eventlog')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnableEventLog"; ValueData: "0"; Check: IsTaskNotSelected('collectors\eventlog')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnablePacketCapture"; ValueData: "1"; Check: IsTaskSelected('collectors\pcap')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: dword; ValueName: "EnablePacketCapture"; ValueData: "0"; Check: IsTaskNotSelected('collectors\pcap')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "EventLogChannels"; ValueData: "Security,System,Application,Microsoft-Windows-Sysmon/Operational"; Check: IsTaskSelected('collectors\eventlog')
Root: HKLM; Subkey: "Software\CyberEW"; ValueType: string; ValueName: "SyslogPort"; ValueData: "514"; Check: IsTaskSelected('collectors\syslog')

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Cyber-EW Fusion Cell"; Flags: nowait postinstall skipifsilent

[Code]
function IsTaskSelected(TaskName: String): Boolean;
begin
  Result := WizardIsTaskSelected(TaskName);
end;

function IsTaskNotSelected(TaskName: String): Boolean;
begin
  Result := not WizardIsTaskSelected(TaskName);
end;
