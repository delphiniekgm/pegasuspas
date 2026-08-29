unit main;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SyncObjs, Forms, Controls, Dialogs, StdCtrls, ComCtrls, ExtCtrls,
  config, adb, scanner, report, logging, settingsform, openurl;

type
  TScanThread = class(TThread)
  private
    FScn: TScanner;
    FCfg: TAppConfig;
    FSerial: string;
    FDir: string;
    FWorkDir: string;
    FIsDemo: Boolean;
    FRes: TScanResult;
    FError: string;
    procedure Idle;
  protected
    procedure Execute; override;
  public
    constructor Create(AConfig: TAppConfig; IsDemo: Boolean; const Serial, Dir, WorkDir: string);
    destructor Destroy; override;
    property Res: TScanResult read FRes;
    property Error: string read FError;
  end;

  TMainForm = class(TForm)
  private
    btnScan: TButton;
    btnDemo: TButton;
    btnRefresh: TButton;
    btnExport: TButton;
    btnSettings: TButton;
    btnClear: TButton;
    btnCancel: TButton;
    cmbDevices: TComboBox;
    memoLog: TMemo;
    tree: TTreeView;
    lblStatus: TLabel;
    progress: TProgressBar;
    dlgOpen: TSelectDirectoryDialog;
    dlgSave: TSaveDialog;
    Cfg: TAppConfig;
    LastResult: TScanResult;
    FScanThread: TScanThread;
    FLogQueue: TStringList;
    FLogLock: TCriticalSection;
    logTimer: TTimer;
    FBusy: Boolean;
    procedure BuildUI;
    procedure LogHandler(Level: TLogLevel; const S: string);
    procedure DrainLogQueue(Sender: TObject);
    procedure btnRefreshClick(Sender: TObject);
    procedure btnScanClick(Sender: TObject);
    procedure btnDemoClick(Sender: TObject);
    procedure btnExportClick(Sender: TObject);
    procedure btnSettingsClick(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
    procedure PopulateTree(Res: TScanResult);
    procedure PrepareConfig;
    procedure StartScan(IsDemo: Boolean; const Serial, Dir: string);
    procedure ScanThreadDone(Sender: TObject);
    procedure AutoSaveAndOpen(Res: TScanResult);
    procedure SetBusy(B: Boolean);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

var
  MainForm: TMainForm;

implementation

constructor TMainForm.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  Cfg := TAppConfig.Create;
  Cfg.LoadFromFile(AppRoot + 'config.ini');
  LastResult := nil;
  FScanThread := nil;
  FBusy := False;
  FLogQueue := TStringList.Create;
  FLogLock := TCriticalSection.Create;
  dlgOpen := TSelectDirectoryDialog.Create(Self);
  dlgSave := TSaveDialog.Create(Self);
  dlgSave.Filter := 'HTML report|*.html|JSON report|*.json|Text report|*.txt';
  BuildUI;
  Logger.OnLog := @LogHandler;
  InitLogger(AppRoot, llInfo);
  Caption := 'Pegasus Android Detector';
  Width := 1040;
  Height := 660;
  Position := poScreenCenter;
end;

destructor TMainForm.Destroy;
begin
  if FScanThread <> nil then begin
    FScanThread.OnTerminate := nil;
    FScanThread.Terminate;
    FScanThread := nil;
  end;
  LastResult.Free;
  Cfg.Free;
  FLogLock.Free;
  FLogQueue.Free;
  inherited Destroy;
end;

procedure TMainForm.BuildUI;
var
  TopPanel: TPanel;
begin
  TopPanel := TPanel.Create(Self);
  TopPanel.Parent := Self;
  TopPanel.Align := alTop;
  TopPanel.Height := 48;
  TopPanel.BevelOuter := bvNone;

  cmbDevices := TComboBox.Create(Self);
  cmbDevices.Parent := TopPanel;
  cmbDevices.Left := 8; cmbDevices.Top := 12; cmbDevices.Width := 320;

  btnRefresh := TButton.Create(Self);
  btnRefresh.Parent := TopPanel;
  btnRefresh.Left := 336; btnRefresh.Top := 8; btnRefresh.Width := 90;
  btnRefresh.Caption := 'Refresh';
  btnRefresh.OnClick := @btnRefreshClick;

  btnScan := TButton.Create(Self);
  btnScan.Parent := TopPanel;
  btnScan.Left := 434; btnScan.Top := 8; btnScan.Width := 90;
  btnScan.Caption := 'Scan Device';
  btnScan.OnClick := @btnScanClick;

  btnDemo := TButton.Create(Self);
  btnDemo.Parent := TopPanel;
  btnDemo.Left := 532; btnDemo.Top := 8; btnDemo.Width := 90;
  btnDemo.Caption := 'Scan APKs...';
  btnDemo.OnClick := @btnDemoClick;

  btnClear := TButton.Create(Self);
  btnClear.Parent := TopPanel;
  btnClear.Left := 630; btnClear.Top := 8; btnClear.Width := 90;
  btnClear.Caption := 'Clear...';
  btnClear.OnClick := @btnClearClick;

  btnExport := TButton.Create(Self);
  btnExport.Parent := TopPanel;
  btnExport.Left := 728; btnExport.Top := 8; btnExport.Width := 90;
  btnExport.Caption := 'Export...';
  btnExport.OnClick := @btnExportClick;

  btnSettings := TButton.Create(Self);
  btnSettings.Parent := TopPanel;
  btnSettings.Left := 826; btnSettings.Top := 8; btnSettings.Width := 90;
  btnSettings.Caption := 'Settings...';
  btnSettings.OnClick := @btnSettingsClick;

  btnCancel := TButton.Create(Self);
  btnCancel.Parent := TopPanel;
  btnCancel.Left := 924; btnCancel.Top := 8; btnCancel.Width := 90;
  btnCancel.Caption := 'Cancel';
  btnCancel.OnClick := @btnCancelClick;
  btnCancel.Enabled := False;

  tree := TTreeView.Create(Self);
  tree.Parent := Self;
  tree.Align := alLeft;
  tree.Width := 450;

  memoLog := TMemo.Create(Self);
  memoLog.Parent := Self;
  memoLog.Align := alClient;
  memoLog.ScrollBars := ssAutoBoth;
  memoLog.ReadOnly := True;

  progress := TProgressBar.Create(Self);
  progress.Parent := Self;
  progress.Align := alBottom;
  progress.Height := 18;
  progress.Style := pbstMarquee;
  progress.Visible := False;

  lblStatus := TLabel.Create(Self);
  lblStatus.Parent := Self;
  lblStatus.Align := alBottom;
  lblStatus.Height := 20;
  lblStatus.Caption := 'Ready.';

  logTimer := TTimer.Create(Self);
  logTimer.Interval := 120;
  logTimer.OnTimer := @DrainLogQueue;
end;

procedure TMainForm.LogHandler(Level: TLogLevel; const S: string);
var
  Prefix: string;
begin
  case Level of
    llWarning: Prefix := 'WARNING: ';
    llError:   Prefix := 'ERROR: ';
  else
    Prefix := '';
  end;
  FLogLock.Enter;
  try
    FLogQueue.Add(Prefix + S);
  finally
    FLogLock.Leave;
  end;
end;

procedure TMainForm.DrainLogQueue(Sender: TObject);
var
  i: Integer;
  S: string;
begin
  if FLogQueue.Count = 0 then
    Exit;
  FLogLock.Enter;
  try
    for i := 0 to FLogQueue.Count - 1 do begin
      S := FLogQueue[i];
      memoLog.Lines.Add(S);
      lblStatus.Caption := S;
    end;
    FLogQueue.Clear;
  finally
    FLogLock.Leave;
  end;
end;

procedure TMainForm.PrepareConfig;
begin
  Cfg.AdbPath := LocateAdb(Cfg);
  Cfg.RulesDir := AbsPath(AppRoot, Cfg.RulesDir);
  Cfg.ReportDir := AbsPath(AppRoot, Cfg.ReportDir);
  if Cfg.WorkDir = '' then
    Cfg.WorkDir := AppRoot + 'work';
  Cfg.WorkDir := AbsPath(AppRoot, Cfg.WorkDir);
end;

procedure TMainForm.btnRefreshClick(Sender: TObject);
var
  A: TAdb;
  Devs: TStringList;
  i: Integer;
begin
  Cfg.AdbPath := LocateAdb(Cfg);
  A := TAdb.Create(Cfg.AdbPath, Cfg.TimeoutMs);
  try
    Devs := A.ListDevices;
    try
      cmbDevices.Items.Clear;
      for i := 0 to Devs.Count - 1 do
        cmbDevices.Items.Add(Devs[i]);
      if cmbDevices.Items.Count > 0 then
        cmbDevices.ItemIndex := 0;
    finally
      Devs.Free;
    end;
  finally
    A.Free;
  end;
  memoLog.Lines.Add('Found ' + IntToStr(cmbDevices.Items.Count) + ' device(s).');
end;

procedure TMainForm.btnScanClick(Sender: TObject);
begin
  if Trim(cmbDevices.Text) = '' then begin
    ShowMessage('No device selected. Click Refresh first.');
    Exit;
  end;
  StartScan(False, cmbDevices.Text, '');
end;

procedure TMainForm.btnDemoClick(Sender: TObject);
var
  Dir: string;
begin
  if not dlgOpen.Execute then
    Exit;
  Dir := dlgOpen.FileName;
  StartScan(True, '', Dir);
end;

procedure TMainForm.btnExportClick(Sender: TObject);
var
  Html, Json, Txt: string;
  Dir, Base: string;
begin
  if LastResult = nil then begin
    ShowMessage('Run a scan first.');
    Exit;
  end;
  if not dlgSave.Execute then
    Exit;
  Dir := ExtractFilePath(dlgSave.FileName);
  Base := ChangeFileExt(ExtractFileName(dlgSave.FileName), '');
  try
    SaveReports(LastResult, Dir, Base, Html, Json, Txt);
  except
    on E: Exception do
      Logger.ExceptionLog('failed to export report', E);
  end;
  memoLog.Lines.Add('Reports:');
  memoLog.Lines.Add('  ' + Html);
  memoLog.Lines.Add('  ' + Json);
  memoLog.Lines.Add('  ' + Txt);
end;

procedure TMainForm.btnSettingsClick(Sender: TObject);
var
  F: TSettingsForm;
begin
  F := TSettingsForm.Create(nil);
  try
    F.LoadFromConfig(Cfg);
    if F.ShowModal = mrOk then begin
      F.SaveToConfig(Cfg);
      Cfg.SaveToFile(AppRoot + 'config.ini');
      memoLog.Lines.Add('Settings saved. Max APKs to scan: ' + IntToStr(Cfg.MaxApkPull));
    end;
  finally
    F.Free;
  end;
end;

procedure TMainForm.StartScan(IsDemo: Boolean; const Serial, Dir: string);
begin
  if FScanThread <> nil then
    Exit;
  PrepareConfig;
  memoLog.Lines.Clear;
  FLogQueue.Clear;
  SetBusy(True);
  FScanThread := TScanThread.Create(Cfg, IsDemo, Serial, Dir, Cfg.WorkDir);
  FScanThread.OnTerminate := @ScanThreadDone;
  FScanThread.Start;
end;

procedure TMainForm.ScanThreadDone(Sender: TObject);
var
  Th: TScanThread;
begin
  Th := TScanThread(Sender);
  if Th.Error <> '' then
    memoLog.Lines.Add('Scan error: ' + Th.Error);
  if Th.Res <> nil then begin
    if LastResult <> nil then
      LastResult.Free;
    LastResult := Th.Res;
    PopulateTree(LastResult);
    AutoSaveAndOpen(LastResult);
  end;
  SetBusy(False);
  FScanThread := nil;
end;

procedure TMainForm.AutoSaveAndOpen(Res: TScanResult);
var
  Html, Json, Txt, Base: string;
begin
  Base := 'pegasus_scan_' + FormatDateTime('yyyymmdd_hhnnss', Now);
  try
    SaveReports(Res, Cfg.ReportDir, Base, Html, Json, Txt);
    memoLog.Lines.Add('Report saved: ' + Html);
    if OpenInBrowser(Html) then
      memoLog.Lines.Add('Opened report in browser.')
    else
      memoLog.Lines.Add('Could not open the browser automatically.');
  except
    on E: Exception do
      Logger.ExceptionLog('failed to save/open report', E);
  end;
end;

procedure TMainForm.btnCancelClick(Sender: TObject);
begin
  if FScanThread <> nil then
    FScanThread.Terminate;
end;

procedure TMainForm.btnClearClick(Sender: TObject);
begin
  if FScanThread <> nil then begin
    ShowMessage('Please wait for the current scan to finish.');
    Exit;
  end;
  PrepareConfig;
  if MessageDlg('Clear all downloaded APKs and extracted files in "' + Cfg.WorkDir + '"?',
       mtConfirmation, mbYesNo, 0) <> mrYes then
    Exit;
  if ClearWorkDirectory(Cfg.WorkDir) then
    memoLog.Lines.Add('Cleared working directory: ' + Cfg.WorkDir)
  else
    memoLog.Lines.Add('Working directory is empty or does not exist: ' + Cfg.WorkDir);
end;

procedure TMainForm.SetBusy(B: Boolean);
begin
  FBusy := B;
  btnScan.Enabled := not B;
  btnDemo.Enabled := not B;
  btnRefresh.Enabled := not B;
  btnExport.Enabled := not B;
  btnSettings.Enabled := not B;
  btnClear.Enabled := not B;
  btnCancel.Enabled := B;
  progress.Visible := B;
end;

procedure TMainForm.PopulateTree(Res: TScanResult);
var
  Root, AppNode: TTreeNode;
  i: Integer;
  A: TAppResult;
begin
  tree.Items.Clear;
  Root := tree.Items.Add(nil, 'Device ' + Res.DeviceSerial + ' - ' +
    IntToStr(Res.Apps.Count) + ' apps');
  for i := 0 to Res.Apps.Count - 1 do begin
    A := TAppResult(Res.Apps[i]);
    AppNode := tree.Items.AddChild(Root, Format('%d  %s (%s)',
      [A.Score, A.PackageName, SeverityToString(A.Severity)]));
    tree.Items.AddChild(AppNode, 'SHA-256: ' + A.Sha256);
    if A.MatchedFamilies.Count > 0 then
      tree.Items.AddChild(AppNode, 'Families: ' + A.MatchedFamilies.CommaText);
  end;
  Root.Expanded := True;
end;

constructor TScanThread.Create(AConfig: TAppConfig; IsDemo: Boolean; const Serial, Dir, WorkDir: string);
begin
  inherited Create(True);
  FCfg := TAppConfig.Create;
  FCfg.CopyFrom(AConfig);
  FIsDemo := IsDemo;
  FSerial := Serial;
  FDir := Dir;
  FWorkDir := WorkDir;
  FRes := nil;
  FError := '';
  FScn := nil;
  FreeOnTerminate := True;
end;

destructor TScanThread.Destroy;
begin
  FCfg.Free;
  inherited Destroy;
end;

procedure TScanThread.Idle;
begin
  if Terminated then
    Abort;
end;

procedure TScanThread.Execute;
begin
  try
    FScn := TScanner.Create(FCfg);
    try
      FScn.OnIdle := @Idle;
      if FIsDemo then
        FRes := FScn.ScanApkDirectory(FDir, FWorkDir)
      else
        FRes := FScn.Scan(FSerial, FWorkDir);
    finally
      FScn.Free;
      FScn := nil;
    end;
  except
    on E: EAbort do ;
    on E: Exception do FError := E.Message;
  end;
end;

end.

