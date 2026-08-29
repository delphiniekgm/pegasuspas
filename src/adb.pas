unit adb;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Process, logging;

type
  TDevice = record
    Serial: string;
    State: string;
    Model: string;
    AndroidVersion: string;
  end;

  TIdleProc = procedure of object;

  TAdb = class
  private
    FAdbPath: string;
    FTimeoutMs: Integer;
    FOnIdle: TIdleProc;
    function RunCapture(const Args: TStrings; out Output: string): Boolean;
  public
    constructor Create(const AdbPath: string; TimeoutMs: Integer);
    function Run(const Args: array of string; out Output: string): Boolean;
    function Shell(const Serial, Cmd: string; out Output: string): Boolean;
    function Cat(const Serial, RemotePath: string; out Output: string): Boolean;
    function ListDevices: TStringList;
    function GetProp(const Serial, Prop: string): string;
    function DeviceInfo(const Serial: string; out Info: TDevice): Boolean;
    function ListPackages(const Serial: string; ThirdPartyOnly: Boolean): TStringList;
    function GetPackagePath(const Serial, Pkg: string; out Path: string): Boolean;
    function Pull(const Serial, Remote, Local: string): Boolean;
    function DumpsysPackage(const Serial, Pkg: string; out Output: string): Boolean;
    function ReadSms(const Serial: string; out Output: string): Boolean;
    function PullSmsDb(const Serial, LocalDir: string; out LocalPath: string): Boolean;
    property AdbPath: string read FAdbPath;
    property OnIdle: TIdleProc read FOnIdle write FOnIdle;
  end;

implementation

procedure SplitTwo(const S: string; out A, B: string);
var
  P: Integer;
begin
  P := 1;
  while (P <= Length(S)) and (S[P] in [' ', #9]) do Inc(P);
  A := '';
  while (P <= Length(S)) and (not (S[P] in [' ', #9, #13, #10])) do begin
    A := A + S[P];
    Inc(P);
  end;
  while (P <= Length(S)) and (S[P] in [' ', #9]) do Inc(P);
  B := '';
  while (P <= Length(S)) and (not (S[P] in [' ', #9, #13, #10])) do begin
    B := B + S[P];
    Inc(P);
  end;
end;

constructor TAdb.Create(const AdbPath: string; TimeoutMs: Integer);
begin
  inherited Create;
  FAdbPath := AdbPath;
  FTimeoutMs := TimeoutMs;
end;

function TAdb.RunCapture(const Args: TStrings; out Output: string): Boolean;
var
  P: TProcess;
  SS: TStringStream;
  Buf: array[0..8191] of Byte;
  N: Integer;
  StartTime: TDateTime;
  ElapsedMs: Double;
begin
  Output := '';
  Result := False;
  if FAdbPath = '' then begin
    Logger.Warning('adb executable path is empty');
    Exit;
  end;
  P := TProcess.Create(nil);
  SS := TStringStream.Create('');
  try
    P.Executable := FAdbPath;
    P.Parameters.Assign(Args);
    P.Options := [poUsePipes, poStderrToOutPut];
    P.ShowWindow := swoHIDE;
    try
      P.Execute;
      StartTime := Now;
      repeat
        while P.Output.NumBytesAvailable > 0 do begin
          N := P.Output.Read(Buf, SizeOf(Buf));
          if N > 0 then
            SS.Write(Buf, N);
        end;
        if Assigned(FOnIdle) then
          FOnIdle();
        Sleep(5);
        ElapsedMs := (Now - StartTime) * 86400000.0;
      until (not P.Running) or (ElapsedMs > FTimeoutMs);
      while P.Output.NumBytesAvailable > 0 do begin
        N := P.Output.Read(Buf, SizeOf(Buf));
        if N > 0 then
          SS.Write(Buf, N);
      end;
      if P.Running then begin
        Logger.Warning(Format('adb command timed out after %d ms', [FTimeoutMs]));
        P.Terminate(1);
        try
          P.WaitOnExit;
        except
        end;
      end;
      if P.ExitCode <> 0 then
        Logger.Warning(Format('adb exited with code %d', [P.ExitCode]));
      Output := SS.DataString;
      Result := (P.ExitCode = 0);
    except
      on E: EAbort do
        raise;
      on E: Exception do begin
        Result := False;
        Logger.ExceptionLog('adb command failed', E);
      end;
    end;
  finally
    SS.Free;
    P.Free;
  end;
end;

function TAdb.Run(const Args: array of string; out Output: string): Boolean;
var
  L: TStringList;
  i: Integer;
begin
  L := TStringList.Create;
  try
    for i := Low(Args) to High(Args) do
      L.Add(Args[i]);
    Result := RunCapture(L, Output);
  finally
    L.Free;
  end;
end;

function TAdb.Shell(const Serial, Cmd: string; out Output: string): Boolean;
begin
  Result := Run(['-s', Serial, 'shell', Cmd], Output);
end;

function TAdb.Cat(const Serial, RemotePath: string; out Output: string): Boolean;
begin
  Result := Shell(Serial, 'cat ' + RemotePath, Output);
end;

function TAdb.ListDevices: TStringList;
var
  OutS: string;
  Lines: TStringList;
  i: Integer;
  Ser, St: string;
begin
  Result := TStringList.Create;
  if not Run(['devices'], OutS) then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.Text := OutS;
    for i := 1 to Lines.Count - 1 do begin
      if Trim(Lines[i]) = '' then
        Continue;
      SplitTwo(Lines[i], Ser, St);
      if Ser <> '' then
        Result.Add(Ser);
    end;
  finally
    Lines.Free;
  end;
end;

function TAdb.GetProp(const Serial, Prop: string): string;
var
  OutS: string;
begin
  if Shell(Serial, 'getprop ' + Prop, OutS) then
    Result := Trim(OutS)
  else
    Result := '';
end;

function TAdb.DeviceInfo(const Serial: string; out Info: TDevice): Boolean;
var
  OutS: string;
begin
  Info.Serial := Serial;
  Info.Model := GetProp(Serial, 'ro.product.model');
  Info.AndroidVersion := GetProp(Serial, 'ro.build.version.release');
  Info.State := 'device';
  if Shell(Serial, 'getprop ro.build.version.release', OutS) then
    if Trim(OutS) = '' then
      Info.State := 'unknown';
  Result := True;
end;

function TAdb.ListPackages(const Serial: string; ThirdPartyOnly: Boolean): TStringList;
var
  OutS, S: string;
  Lines: TStringList;
  i: Integer;
begin
  Result := TStringList.Create;
  if ThirdPartyOnly then
    S := 'pm list packages -3'
  else
    S := 'pm list packages';
  if not Shell(Serial, S, OutS) then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.Text := OutS;
    for i := 0 to Lines.Count - 1 do begin
      S := Trim(Lines[i]);
      if Pos('package:', S) = 1 then
        Result.Add(Copy(S, 9, MaxInt));
    end;
  finally
    Lines.Free;
  end;
end;

function TAdb.GetPackagePath(const Serial, Pkg: string; out Path: string): Boolean;
var
  OutS, Line: string;
  Lines: TStringList;
  i: Integer;
begin
  Result := False;
  Path := '';
  if not Shell(Serial, 'pm path ' + Pkg, OutS) then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.Text := OutS;
    for i := 0 to Lines.Count - 1 do begin
      Line := Trim(Lines[i]);
      if Pos('package:', Line) = 1 then begin
        Path := Trim(Copy(Line, 9, MaxInt));
        Result := Path <> '';
        Exit;
      end;
    end;
  finally
    Lines.Free;
  end;
end;

function TAdb.Pull(const Serial, Remote, Local: string): Boolean;
var
  OutS: string;
begin
  Result := Run(['-s', Serial, 'pull', Remote, Local], OutS);
end;

function TAdb.DumpsysPackage(const Serial, Pkg: string; out Output: string): Boolean;
begin
  Result := Shell(Serial, 'dumpsys package ' + Pkg, Output);
end;

function TAdb.ReadSms(const Serial: string; out Output: string): Boolean;
begin
  // Projection keeps 'body' last so the caller can parse each row reliably.
  Result := Shell(Serial,
    'content query --uri content://sms --projection address:date:type:body',
    Output);
end;

function TAdb.PullSmsDb(const Serial, LocalDir: string; out LocalPath: string): Boolean;
var
  OutS: string;
begin
  Result := False;
  LocalPath := '';
  if LocalDir = '' then
    Exit;
  if not DirectoryExists(LocalDir) then
    ForceDirectories(LocalDir);
  LocalPath := IncludeTrailingPathDelimiter(LocalDir) + 'mmssms.db';
  Result := Run(['-s', Serial, 'pull',
    '/data/data/com.android.providers.telephony/databases/mmssms.db',
    LocalPath], OutS);
  if (not Result) or (not FileExists(LocalPath)) then
    Result := False;
end;

end.
