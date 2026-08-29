unit config;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, IniFiles;

type
  TAppConfig = class
  public
    AdbPath: string;
    TimeoutMs: Integer;
    SkipSystemPackages: Boolean;
    MaxApkPull: Integer;
    ExtractStrings: Boolean;
    MinStringLen: Integer;
    ScanMessages: Boolean;
    MessagesMaxRows: Integer;
    RulesDir: string;
    ReportDir: string;
    WorkDir: string;
    constructor Create;
    procedure LoadFromFile(const FileName: string);
    procedure SaveToFile(const FileName: string);
    procedure ApplyDefaults;
    procedure CopyFrom(Src: TAppConfig);
  end;

function AppDir: string;
function AppRoot: string;
function AbsPath(const Base, Rel: string): string;
function LocateAdb(const Cfg: TAppConfig): string;

implementation

function AppDir: string;
begin
  Result := IncludeTrailingPathDelimiter(ExtractFilePath(ExpandFileName(ParamStr(0))));
end;

function AppRoot: string;
var
  D: string;
begin
  D := ExcludeTrailingPathDelimiter(AppDir);
  if LowerCase(ExtractFileName(D)) = 'bin' then
    Result := IncludeTrailingPathDelimiter(ExtractFileDir(D))
  else
    Result := AppDir;
end;

function AbsPath(const Base, Rel: string): string;
begin
  if Rel = '' then
    Result := Base
  else if (Length(Rel) >= 2) and (Rel[2] = ':') then
    Result := Rel
  else if (Length(Rel) >= 1) and ((Rel[1] = '\') or (Rel[1] = '/')) then
    Result := Rel
  else
    Result := IncludeTrailingPathDelimiter(Base) + Rel;
end;

function LocateAdb(const Cfg: TAppConfig): string;
var
  BinAdb: string;
begin
  if (Cfg.AdbPath <> '') and FileExists(Cfg.AdbPath) then
    Exit(Cfg.AdbPath);
  BinAdb := AppRoot + 'bin' + DirectorySeparator + 'adb.exe';
  if FileExists(BinAdb) then
    Exit(BinAdb);
  Result := 'adb';
end;


constructor TAppConfig.Create;
begin
  inherited Create;
  ApplyDefaults;
end;

procedure TAppConfig.ApplyDefaults;
begin
  AdbPath := '';
  TimeoutMs := 30000;
  SkipSystemPackages := True;
  MaxApkPull := 200;
  ExtractStrings := True;
  MinStringLen := 6;
  ScanMessages := False;
  MessagesMaxRows := 5000;
  RulesDir := 'data';
  ReportDir := 'reports';
  WorkDir := '';
end;

procedure TAppConfig.CopyFrom(Src: TAppConfig);
begin
  AdbPath := Src.AdbPath;
  TimeoutMs := Src.TimeoutMs;
  SkipSystemPackages := Src.SkipSystemPackages;
  MaxApkPull := Src.MaxApkPull;
  ExtractStrings := Src.ExtractStrings;
  MinStringLen := Src.MinStringLen;
  ScanMessages := Src.ScanMessages;
  MessagesMaxRows := Src.MessagesMaxRows;
  RulesDir := Src.RulesDir;
  ReportDir := Src.ReportDir;
  WorkDir := Src.WorkDir;
end;

procedure TAppConfig.LoadFromFile(const FileName: string);
var
  Ini: TIniFile;
begin
  ApplyDefaults;
  if not FileExists(FileName) then
    Exit;
  Ini := TIniFile.Create(FileName);
  try
    AdbPath := Ini.ReadString('adb', 'AdbPath', AdbPath);
    TimeoutMs := Ini.ReadInteger('adb', 'TimeoutMs', TimeoutMs);
    SkipSystemPackages := Ini.ReadBool('scan', 'SkipSystemPackages', SkipSystemPackages);
    MaxApkPull := Ini.ReadInteger('scan', 'MaxApkPull', MaxApkPull);
    ExtractStrings := Ini.ReadBool('scan', 'ExtractStrings', ExtractStrings);
    MinStringLen := Ini.ReadInteger('scan', 'MinStringLen', MinStringLen);
    ScanMessages := Ini.ReadBool('scan', 'ScanMessages', ScanMessages);
    MessagesMaxRows := Ini.ReadInteger('scan', 'MessagesMaxRows', MessagesMaxRows);
    RulesDir := Ini.ReadString('paths', 'RulesDir', RulesDir);
    ReportDir := Ini.ReadString('paths', 'ReportDir', ReportDir);
    WorkDir := Ini.ReadString('paths', 'WorkDir', WorkDir);
  finally
    Ini.Free;
  end;
end;

procedure TAppConfig.SaveToFile(const FileName: string);
var
  Ini: TIniFile;
begin
  Ini := TIniFile.Create(FileName);
  try
    Ini.WriteString('adb', 'AdbPath', AdbPath);
    Ini.WriteInteger('adb', 'TimeoutMs', TimeoutMs);
    Ini.WriteBool('scan', 'SkipSystemPackages', SkipSystemPackages);
    Ini.WriteInteger('scan', 'MaxApkPull', MaxApkPull);
    Ini.WriteBool('scan', 'ExtractStrings', ExtractStrings);
    Ini.WriteInteger('scan', 'MinStringLen', MinStringLen);
    Ini.WriteBool('scan', 'ScanMessages', ScanMessages);
    Ini.WriteInteger('scan', 'MessagesMaxRows', MessagesMaxRows);
    Ini.WriteString('paths', 'RulesDir', RulesDir);
    Ini.WriteString('paths', 'ReportDir', ReportDir);
    Ini.WriteString('paths', 'WorkDir', WorkDir);
  finally
    Ini.Free;
  end;
end;

end.
