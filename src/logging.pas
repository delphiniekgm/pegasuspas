unit logging;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TLogLevel = (llDebug, llInfo, llWarning, llError);

  TLogSink = procedure(Level: TLogLevel; const Msg: string) of object;

  TLogger = class
  private
    FEnabled: Boolean;
    FFilePath: string;
    FMinLevel: TLogLevel;
    FOnLog: TLogSink;
    FFile: Text;
    FFileOpen: Boolean;
    procedure EnsureOpen;
    procedure WriteLine(Level: TLogLevel; const Msg: string);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Init(const FilePath: string; MinLevel: TLogLevel);
    procedure Log(Level: TLogLevel; const Msg: string);
    procedure Debug(const Msg: string);
    procedure Info(const Msg: string);
    procedure Warning(const Msg: string);
    procedure Error(const Msg: string);
    procedure ExceptionLog(const Context: string; E: Exception);
    property Enabled: Boolean read FEnabled write FEnabled;
    property MinLevel: TLogLevel read FMinLevel write FMinLevel;
    property OnLog: TLogSink read FOnLog write FOnLog;
    property FilePath: string read FFilePath;
  end;

function Logger: TLogger;
function InitLogger(const Root: string; MinLevel: TLogLevel): string;
function LogLevelToString(Level: TLogLevel): string;

implementation

var
  GLogger: TLogger;

function LogLevelToString(Level: TLogLevel): string;
begin
  case Level of
    llDebug:   Result := 'DEBUG';
    llInfo:    Result := 'INFO';
    llWarning: Result := 'WARNING';
    llError:   Result := 'ERROR';
  end;
end;

function Logger: TLogger;
begin
  if GLogger = nil then
    GLogger := TLogger.Create;
  Result := GLogger;
end;

function InitLogger(const Root: string; MinLevel: TLogLevel): string;
var
  Dir: string;
begin
  Result := '';
  try
    Dir := IncludeTrailingPathDelimiter(Root) + 'logs';
    if not DirectoryExists(Dir) then
      ForceDirectories(Dir);
    Result := Dir + DirectorySeparator + 'pegasus_' +
              FormatDateTime('yyyymmdd_hhnnss', Now) + '.log';
    Logger.Init(Result, MinLevel);
    Logger.Info('=== Scan session started ===');
  except
    Result := '';
  end;
end;

constructor TLogger.Create;
begin
  inherited Create;
  FEnabled := True;
  FFilePath := '';
  FMinLevel := llInfo;
  FOnLog := nil;
  FFileOpen := False;
end;

destructor TLogger.Destroy;
begin
  if FFileOpen then begin
    try Close(FFile); except end;
    FFileOpen := False;
  end;
  inherited Destroy;
end;

procedure TLogger.Init(const FilePath: string; MinLevel: TLogLevel);
begin
  if FFileOpen then begin
    try Close(FFile); except end;
    FFileOpen := False;
  end;
  FFilePath := FilePath;
  FMinLevel := MinLevel;
end;

procedure TLogger.EnsureOpen;
begin
  if (FFilePath = '') or FFileOpen then
    Exit;
  Assign(FFile, FFilePath);
  try
    if FileExists(FFilePath) then
      Append(FFile)
    else
      Rewrite(FFile);
    FFileOpen := True;
  except
    FFileOpen := False;
  end;
end;

procedure TLogger.WriteLine(Level: TLogLevel; const Msg: string);
begin
  if not FFileOpen then
    Exit;
  try
    WriteLn(FFile, Format('%s [%s] %s',
      [FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now), LogLevelToString(Level), Msg]));
    Flush(FFile);
  except
  end;
end;

procedure TLogger.Log(Level: TLogLevel; const Msg: string);
begin
  if not FEnabled then
    Exit;
  if Level < FMinLevel then
    Exit;
  EnsureOpen;
  WriteLine(Level, Msg);
  if Assigned(FOnLog) then begin
    try
      FOnLog(Level, Msg);
    except
    end;
  end;
end;

procedure TLogger.Debug(const Msg: string);
begin
  Log(llDebug, Msg);
end;

procedure TLogger.Info(const Msg: string);
begin
  Log(llInfo, Msg);
end;

procedure TLogger.Warning(const Msg: string);
begin
  Log(llWarning, Msg);
end;

procedure TLogger.Error(const Msg: string);
begin
  Log(llError, Msg);
end;

procedure TLogger.ExceptionLog(const Context: string; E: Exception);
begin
  if E = nil then
    Error(Context + ': unknown exception')
  else
    Error(Format('%s: %s: %s', [Context, E.ClassName, E.Message]));
end;

end.
