[Setup]
AppId=SentinelAI.Desktop
AppName=SentinelAI
AppVersion={#AppVersion}
AppPublisher=SentinelAI contributors
AppPublisherURL=https://sentinelai-site.vercel.app/
DefaultDirName={localappdata}\Programs\SentinelAI
DefaultGroupName=SentinelAI
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.10240
WizardStyle=modern
UninstallDisplayIcon={app}\sentinelai.ico
SetupIconFile=..\..\app\assets\sentinelai.ico
OutputDir={#OutputDirectory}
OutputBaseFilename=SentinelAI-Setup-x64
Compression=lzma2
SolidCompression=yes

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\..\app\assets\sentinelai.ico"; DestDir: "{app}"
Source: "{#WheelDirectory}\{#WheelName}"; Flags: dontcopy
Source: "prepare-runtime.ps1"; Flags: dontcopy
Source: "{tmp}\runtime\*"; DestDir: "{app}\runtime"; ExternalSize: 400000000; Flags: external recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\SentinelAI"; Filename: "{app}\runtime\pythonw.exe"; Parameters: "-I -m app"; WorkingDir: "{app}"; IconFilename: "{app}\sentinelai.ico"
Name: "{autodesktop}\SentinelAI"; Filename: "{app}\runtime\pythonw.exe"; Parameters: "-I -m app"; WorkingDir: "{app}"; IconFilename: "{app}\sentinelai.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\runtime\pythonw.exe"; Parameters: "-I -m app"; WorkingDir: "{app}"; Description: "Launch SentinelAI"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\runtime"

[Code]
var
  DownloadPage: TDownloadWizardPage;
  DownloadsReady: Boolean;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage('Downloading SentinelAI components',
    'Setup downloads the runtime and dependencies before installing.', nil);
  DownloadPage.ShowBaseNameInsteadOfUrl := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID <> wpReady) or DownloadsReady then
    exit;

  DownloadPage.Clear;
  DownloadPage.Add('https://api.nuget.org/v3-flatcontainer/python/3.13.17/python.3.13.17.nupkg',
    'python-runtime.zip', 'DCE409744B088F94C6E37BA41F8100C384C27E029E843237364C602D30D475E5');
#include DownloadsFile
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
      DownloadsReady := True;
    except
      Result := False;
      Log('Download stopped: ' + GetExceptionMessage);
      if not DownloadPage.AbortedByUser then
        SuppressibleMsgBox('Setup could not download its components. ' + GetExceptionMessage,
          mbError, MB_OK, IDOK);
    end;
  finally
    DownloadPage.Hide;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Parameters: String;
  ResultCode: Integer;
begin
  Result := '';
  WizardForm.PreparingLabel.Caption := 'Preparing downloaded components locally. This step uses no network.';
  ExtractTemporaryFile('prepare-runtime.ps1');
  ExtractTemporaryFile('{#WheelName}');
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    ExpandConstant('{tmp}\prepare-runtime.ps1') + '" -Wheel "' +
    ExpandConstant('{tmp}\{#WheelName}') + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := 'Setup could not start PowerShell.'
  else if ResultCode <> 0 then
    Result := 'Setup could not prepare the downloaded components. See ' +
      GetEnv('TEMP') + '\SentinelAI-Setup.log for details.';
end;
