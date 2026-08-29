program pegasus_scanner;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, Interfaces, Forms,
  consoleapp,
  main in 'src\main.pas';

var
  i: Integer;
  Args: array of string;
  IsConsole: Boolean;
begin
  IsConsole := False;
  for i := 1 to ParamCount do
    if (ParamStr(i) = '--console') or (ParamStr(i) = '-c') or
       (ParamStr(i) = '--help') or (ParamStr(i) = '-h') then
      IsConsole := True;

  if IsConsole then begin
    SetLength(Args, ParamCount);
    for i := 0 to ParamCount - 1 do
      Args[i] := ParamStr(i + 1);
    ExitCode := RunConsole(Args);
    Exit;
  end;

  RequireDerivedFormResource := False;
  Application.Scaled := True;
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
