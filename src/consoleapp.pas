unit consoleapp;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, config, adb, scanner, report, logging, openurl;

function RunConsole(const Args: array of string): Integer;

implementation

type
  TConsoleLogger = class
  public
    procedure Log(Level: TLogLevel; const S: string);
  end;

procedure TConsoleLogger.Log(Level: TLogLevel; const S: string);
begin
  if S = '' then
    Exit;
  case Level of
    llDebug, llInfo: Writeln(S);
    llWarning: Writeln('WARNING: ', S);
    llError: Writeln('ERROR: ', S);
  end;
end;

procedure PrintHelp;
begin
  Writeln('Pegasus Android Detector - console mode');
  Writeln('');
  Writeln('Detects Pegasus / mercenary-spyware indicators on an Android device');
  Writeln('using MVT-sourced STIX2 indicator definitions (data/*.stix2) and');
  Writeln('family-based IoC rule files (data/*.txt).');
  Writeln('');
  Writeln('Usage:');
  Writeln('  pegasus_scanner --console [options]');
  Writeln('  pegasus_cli [options]');
  Writeln('');
  Writeln('Options:');
  Writeln('  -h, --help           Show this help');
  Writeln('  --config FILE        Path to config.ini (default: <exedir>\config.ini)');
  Writeln('  --device SERIAL      ADB device serial (default: first device)');
  Writeln('  --demo DIR           Scan a folder of .apk files instead of a device');
  Writeln('  --all                Include system packages (default: third-party only)');
  Writeln('  --max N              Maximum APKs to pull/scan');
  Writeln('  --report-dir DIR     Output directory for reports');
  Writeln('  --workdir DIR        Working directory for pulled APKs');
end;

function RunConsole(const Args: array of string): Integer;
var
  Cfg: TAppConfig;
  CfgPath, DeviceSerial, DemoDir, BaseName, LogPath: string;
  i: Integer;
  A: string;
  Scn: TScanner;
  Res: TScanResult;
  Devs: TStringList;
  TmpAdb: TAdb;
  CLog: TConsoleLogger;
  Html, Json, Txt: string;
begin
  Result := 0;
  Cfg := TAppConfig.Create;
  Scn := nil;
  Res := nil;
  Devs := nil;
  TmpAdb := nil;
  CLog := nil;
  try
    CfgPath := AppRoot + 'config.ini';
    // First pass: resolve --config so the file is loaded before other overrides.
    i := 0;
    while i <= High(Args) do begin
      if Args[i] = '--config' then begin
        Inc(i);
        if i <= High(Args) then CfgPath := Args[i];
      end;
      Inc(i);
    end;
    Cfg.LoadFromFile(CfgPath);

    DeviceSerial := '';
    DemoDir := '';
    i := 0;
    while i <= High(Args) do begin
      A := Args[i];
      if (A = '-h') or (A = '--help') then begin
        PrintHelp;
        Exit;
      end
      else if A = '--config' then begin
        Inc(i); if i <= High(Args) then CfgPath := Args[i];
      end
      else if A = '--device' then begin
        Inc(i); if i <= High(Args) then DeviceSerial := Args[i];
      end
      else if A = '--demo' then begin
        Inc(i); if i <= High(Args) then DemoDir := Args[i];
      end
      else if (A = '--report-dir') or (A = '--output') then begin
        Inc(i); if i <= High(Args) then Cfg.ReportDir := Args[i];
      end
      else if A = '--workdir' then begin
        Inc(i); if i <= High(Args) then Cfg.WorkDir := Args[i];
      end
      else if A = '--all' then
        Cfg.SkipSystemPackages := False
      else if A = '--max' then begin
        Inc(i); if i <= High(Args) then Cfg.MaxApkPull := StrToIntDef(Args[i], Cfg.MaxApkPull);
      end;
      Inc(i);
    end;

    Cfg.AdbPath := LocateAdb(Cfg);
    Cfg.RulesDir := AbsPath(AppRoot, Cfg.RulesDir);
    Cfg.ReportDir := AbsPath(AppRoot, Cfg.ReportDir);
    if Cfg.WorkDir = '' then
      Cfg.WorkDir := AppRoot + 'work';
    Cfg.WorkDir := AbsPath(AppRoot, Cfg.WorkDir);

    LogPath := InitLogger(AppRoot, llInfo);
    CLog := TConsoleLogger.Create;
    Logger.OnLog := @CLog.Log;
    if LogPath <> '' then
      Writeln('Log file: ' + LogPath);
    Scn := TScanner.Create(Cfg);

    if DemoDir <> '' then begin
      Res := Scn.ScanApkDirectory(DemoDir, Cfg.WorkDir);
    end
    else begin
      TmpAdb := TAdb.Create(Cfg.AdbPath, Cfg.TimeoutMs);
      Devs := TmpAdb.ListDevices;
      if Devs.Count = 0 then begin
        Writeln('No ADB devices found.');
        Writeln('Enable USB debugging on the phone, authorize this PC, then retry.');
        Writeln('Or use: --demo <folder-with-apks>');
        Result := 1;
        Exit;
      end;
      if DeviceSerial = '' then begin
        DeviceSerial := Devs[0];
        Writeln('Using device: ' + DeviceSerial);
      end;
      Res := Scn.Scan(DeviceSerial, Cfg.WorkDir);
    end;

    BaseName := 'pegasus_scan_' + FormatDateTime('yyyymmdd_hhnnss', Now);
    try
      SaveReports(Res, Cfg.ReportDir, BaseName, Html, Json, Txt);
    except
      on E: Exception do
        Logger.ExceptionLog('failed to save reports', E);
    end;
    Writeln('');
    Writeln(GenerateTextReport(Res));
    Writeln('');
    Writeln('Reports written:');
    Writeln('  ' + Html);
    Writeln('  ' + Json);
    Writeln('  ' + Txt);
    if OpenInBrowser(Html) then
      Writeln('Opened report in browser.')
    else
      Writeln('Could not open the browser automatically.');
  finally
    TmpAdb.Free;
    Devs.Free;
    Res.Free;
    Scn.Free;
    CLog.Free;
    Cfg.Free;
  end;
end;

end.

