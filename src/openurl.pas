unit openurl;

{$mode objfpc}{$H+}

// Open a local file with the system's default application (the default web
// browser for .html files). Dependency-free (no LCL) so both the GUI and the
// console scanner can use it.

interface

function OpenInBrowser(const FileName: string): Boolean;

implementation

uses
  SysUtils, Classes{$IFNDEF WINDOWS}, Process{$ENDIF}
  {$IFDEF WINDOWS}, Windows, ShellAPI{$ENDIF};

{$IFDEF WINDOWS}
function OpenInBrowser(const FileName: string): Boolean;
var
  WS: UnicodeString;
begin
  Result := False;
  if not FileExists(FileName) then
    Exit;
  WS := UTF8Decode(FileName);
  Result := ShellExecuteW(0, 'open', PWideChar(WS), nil, nil, SW_SHOWNORMAL) > 32;
end;
{$ELSE}
function OpenInBrowser(const FileName: string): Boolean;
var
  P: TProcess;
begin
  Result := False;
  if not FileExists(FileName) then
    Exit;
  P := TProcess.Create(nil);
  try
    {$IFDEF DARWIN}
    P.Executable := 'open';
    {$ELSE}
    P.Executable := 'xdg-open';
    {$ENDIF}
    P.Parameters.Add(FileName);
    P.Options := [poNoConsole];
    P.Execute;
    Result := True;
  finally
    P.Free;
  end;
end;
{$ENDIF}

end.
