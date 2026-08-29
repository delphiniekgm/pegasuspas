unit settingsform;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, Dialogs, config;

type
  TSettingsForm = class(TForm)
  private
    edAdbPath: TEdit;
    edWorkDir: TEdit;
    edReportDir: TEdit;
    edRulesDir: TEdit;
    edMaxApkPull: TEdit;
    edTimeoutMs: TEdit;
    chkSkipSystem: TCheckBox;
    btnOK: TButton;
    btnCancel: TButton;
    dlgDir: TSelectDirectoryDialog;
    dlgFile: TOpenDialog;
    procedure btnAdbBrowseClick(Sender: TObject);
    procedure btnWorkDirBrowseClick(Sender: TObject);
    procedure btnReportDirBrowseClick(Sender: TObject);
    procedure btnRulesDirBrowseClick(Sender: TObject);
    procedure BuildUI;
  public
    constructor Create(AOwner: TComponent); override;
    procedure LoadFromConfig(Cfg: TAppConfig);
    procedure SaveToConfig(Cfg: TAppConfig);
  end;

implementation

constructor TSettingsForm.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  Caption := 'Pegasus scanner settings';
  dlgDir := TSelectDirectoryDialog.Create(Self);
  dlgFile := TOpenDialog.Create(Self);
  dlgFile.Filter := 'adb.exe|adb.exe|All files|*.*';
  BuildUI;
  Position := poMainFormCenter;
  BorderStyle := bsDialog;
end;

procedure TSettingsForm.BuildUI;
var
  Y: Integer;

  procedure AddField(const CaptionText: string; var Edit: TEdit;
    WithBrowse: Boolean; BrowseHandler: TNotifyEvent);
  var
    L: TLabel;
    B: TButton;
  begin
    L := TLabel.Create(Self);
    L.Parent := Self;
    L.Left := 16;
    L.Top := Y + 4;
    L.Caption := CaptionText;

    Edit := TEdit.Create(Self);
    Edit.Parent := Self;
    Edit.Left := 150;
    Edit.Top := Y;
    Edit.Width := 250;

    if WithBrowse then begin
      B := TButton.Create(Self);
      B.Parent := Self;
      B.Left := 410;
      B.Top := Y - 1;
      B.Width := 80;
      B.Caption := 'Browse...';
      B.OnClick := BrowseHandler;
    end;
    Inc(Y, 34);
  end;

begin
  Y := 16;
  AddField('ADB path:', edAdbPath, True, @btnAdbBrowseClick);
  AddField('Working dir:', edWorkDir, True, @btnWorkDirBrowseClick);
  AddField('Report dir:', edReportDir, True, @btnReportDirBrowseClick);
  AddField('Rules dir:', edRulesDir, True, @btnRulesDirBrowseClick);
  AddField('Max APKs:', edMaxApkPull, False, nil);
  AddField('Timeout (ms):', edTimeoutMs, False, nil);

  chkSkipSystem := TCheckBox.Create(Self);
  chkSkipSystem.Parent := Self;
  chkSkipSystem.Left := 150;
  chkSkipSystem.Top := Y;
  chkSkipSystem.Caption := 'Skip system packages';
  chkSkipSystem.Width := 250;
  Inc(Y, 40);

  btnOK := TButton.Create(Self);
  btnOK.Parent := Self;
  btnOK.Left := 300;
  btnOK.Top := Y;
  btnOK.Width := 90;
  btnOK.Caption := 'OK';
  btnOK.ModalResult := mrOk;
  btnOK.Default := True;

  btnCancel := TButton.Create(Self);
  btnCancel.Parent := Self;
  btnCancel.Left := 400;
  btnCancel.Top := Y;
  btnCancel.Width := 90;
  btnCancel.Caption := 'Cancel';
  btnCancel.ModalResult := mrCancel;

  ClientWidth := 520;
  ClientHeight := Y + 50;
end;

procedure TSettingsForm.btnAdbBrowseClick(Sender: TObject);
begin
  if dlgFile.Execute then
    edAdbPath.Text := dlgFile.FileName;
end;

procedure TSettingsForm.btnWorkDirBrowseClick(Sender: TObject);
begin
  if dlgDir.Execute then
    edWorkDir.Text := dlgDir.FileName;
end;

procedure TSettingsForm.btnReportDirBrowseClick(Sender: TObject);
begin
  if dlgDir.Execute then
    edReportDir.Text := dlgDir.FileName;
end;

procedure TSettingsForm.btnRulesDirBrowseClick(Sender: TObject);
begin
  if dlgDir.Execute then
    edRulesDir.Text := dlgDir.FileName;
end;

procedure TSettingsForm.LoadFromConfig(Cfg: TAppConfig);
begin
  edAdbPath.Text := Cfg.AdbPath;
  edWorkDir.Text := Cfg.WorkDir;
  edReportDir.Text := Cfg.ReportDir;
  edRulesDir.Text := Cfg.RulesDir;
  edMaxApkPull.Text := IntToStr(Cfg.MaxApkPull);
  edTimeoutMs.Text := IntToStr(Cfg.TimeoutMs);
  chkSkipSystem.Checked := Cfg.SkipSystemPackages;
end;

procedure TSettingsForm.SaveToConfig(Cfg: TAppConfig);
begin
  Cfg.AdbPath := Trim(edAdbPath.Text);
  Cfg.WorkDir := Trim(edWorkDir.Text);
  Cfg.ReportDir := Trim(edReportDir.Text);
  Cfg.RulesDir := Trim(edRulesDir.Text);
  Cfg.MaxApkPull := StrToIntDef(Trim(edMaxApkPull.Text), Cfg.MaxApkPull);
  Cfg.TimeoutMs := StrToIntDef(Trim(edTimeoutMs.Text), Cfg.TimeoutMs);
  Cfg.SkipSystemPackages := chkSkipSystem.Checked;
end;

end.
