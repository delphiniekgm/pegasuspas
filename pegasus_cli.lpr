program pegasus_cli;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, consoleapp;

var
  Args: array of string;
  i: Integer;
begin
  SetLength(Args, ParamCount);
  for i := 0 to ParamCount - 1 do
    Args[i] := ParamStr(i + 1);
  ExitCode := RunConsole(Args);
end.
