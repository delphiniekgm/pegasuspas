unit report;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, scanner;

function GenerateHtmlReport(Res: TScanResult): string;
function GenerateJsonReport(Res: TScanResult): string;
function GenerateTextReport(Res: TScanResult): string;
procedure SaveReports(Res: TScanResult; const Dir, BaseName: string;
  out HtmlPath, JsonPath, TxtPath: string);

implementation

function HtmlEscape(const S: string): string;
var
  i: Integer;
begin
  Result := '';
  for i := 1 to Length(S) do begin
    case S[i] of
      '&': Result := Result + '&amp;';
      '<': Result := Result + '&lt;';
      '>': Result := Result + '&gt;';
      '"': Result := Result + '&quot;';
    else
      Result := Result + S[i];
    end;
  end;
end;

function JsonEscape(const S: string): string;
var
  i: Integer;
  C: Char;
begin
  Result := '';
  for i := 1 to Length(S) do begin
    C := S[i];
    case C of
      '"': Result := Result + '\"';
      '\': Result := Result + '\\';
      #13: Result := Result + '\r';
      #10: Result := Result + '\n';
      #9: Result := Result + '\t';
    else
      if Ord(C) < 32 then
        Result := Result + Format('\u%04x', [Ord(C)])
      else
        Result := Result + C;
    end;
  end;
end;

function GenerateTextReport(Res: TScanResult): string;
var
  SL: TStringList;
  i: Integer;
  A: TAppResult;
  F: TFinding;
begin
  SL := TStringList.Create;
  try
    SL.Add('==============================================');
    SL.Add(' Pegasus Detection Report');
    SL.Add('==============================================');
    SL.Add('Device: ' + Res.DeviceSerial);
    SL.Add('Model: ' + Res.DeviceModel);
    SL.Add('Android: ' + Res.AndroidVersion);
    SL.Add(Format('Started: %s  Finished: %s', [DateTimeToStr(Res.Started), DateTimeToStr(Res.Finished)]));
    SL.Add('Apps scanned: ' + IntToStr(Res.Apps.Count));
    SL.Add('');
    SL.Add('--- Applications ---');
    for i := 0 to Res.Apps.Count - 1 do begin
      A := TAppResult(Res.Apps[i]);
      SL.Add(Format('%3d  %-45s %-9s sha256=%s sha1=%s', [A.Score, A.PackageName,
        SeverityToString(A.Severity), A.Sha256, A.Sha1]));
    end;
    SL.Add('');
    SL.Add('--- Findings ---');
    for i := 0 to Res.Findings.Count - 1 do begin
      F := TFinding(Res.Findings[i]);
      SL.Add(Format('[%s] %s :: %s :: %s', [SeverityToString(F.Severity), F.App, F.Kind, F.Detail]));
    end;
    Result := SL.Text;
  finally
    SL.Free;
  end;
end;

function GenerateHtmlReport(Res: TScanResult): string;
var
  SL: TStringList;
  i: Integer;
  A: TAppResult;
  F: TFinding;
begin
  SL := TStringList.Create;
  try
    SL.Add('<!DOCTYPE html><html><head><meta charset="utf-8">');
    SL.Add('<title>Pegasus Detection Report</title>');
    SL.Add('<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;width:100%}');
    SL.Add('th,td{border:1px solid #ccc;padding:6px;text-align:left}th{background:#f0f0f0}');
    SL.Add('.critical{color:#fff;background:#c00}.high{color:#fff;background:#e80}.medium{background:#fc0}');
    SL.Add('.low{background:#ff9}td,th{font-size:13px}</style></head><body>');
    SL.Add('<h1>Pegasus Detection Report</h1>');
    SL.Add('<p>Device: ' + HtmlEscape(Res.DeviceSerial) + '<br>');
    SL.Add('Model: ' + HtmlEscape(Res.DeviceModel) + '<br>');
    SL.Add('Android: ' + HtmlEscape(Res.AndroidVersion) + '<br>');
    SL.Add(Format('Started: %s &mdash; Finished: %s</p>', [DateTimeToStr(Res.Started), DateTimeToStr(Res.Finished)]));
    SL.Add('<h2>Applications (' + IntToStr(Res.Apps.Count) + ')</h2>');
    SL.Add('<table><tr><th>Score</th><th>Package</th><th>Severity</th><th>SHA-256</th><th>Families</th></tr>');
    for i := 0 to Res.Apps.Count - 1 do begin
      A := TAppResult(Res.Apps[i]);
      SL.Add(Format('<tr class="%s"><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
        [SeverityToString(A.Severity), A.Score, HtmlEscape(A.PackageName),
         SeverityToString(A.Severity), HtmlEscape(A.Sha256),
         HtmlEscape(A.MatchedFamilies.CommaText)]));
    end;
    SL.Add('</table>');
    SL.Add('<h2>Findings (' + IntToStr(Res.Findings.Count) + ')</h2>');
    SL.Add('<table><tr><th>Severity</th><th>App</th><th>Type</th><th>Detail</th></tr>');
    for i := 0 to Res.Findings.Count - 1 do begin
      F := TFinding(Res.Findings[i]);
      SL.Add(Format('<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
        [SeverityToString(F.Severity), SeverityToString(F.Severity), HtmlEscape(F.App),
         HtmlEscape(F.Kind), HtmlEscape(F.Detail)]));
    end;
    SL.Add('</table></body></html>');
    Result := SL.Text;
  finally
    SL.Free;
  end;
end;

function JStr(const S: string): string;
begin
  Result := '"' + JsonEscape(S) + '"';
end;

function GenerateJsonReport(Res: TScanResult): string;
var
  SL: TStringList;
  i: Integer;
  A: TAppResult;
  F: TFinding;
begin
  SL := TStringList.Create;
  try
    SL.Add('{');
    SL.Add(Format('  "device": %s,', [JStr(Res.DeviceSerial)]));
    SL.Add(Format('  "model": %s,', [JStr(Res.DeviceModel)]));
    SL.Add(Format('  "android": %s,', [JStr(Res.AndroidVersion)]));
    SL.Add(Format('  "started": %s,', [JStr(DateTimeToStr(Res.Started))]));
    SL.Add(Format('  "finished": %s,', [JStr(DateTimeToStr(Res.Finished))]));
    SL.Add('  "apps": [');
    for i := 0 to Res.Apps.Count - 1 do begin
      A := TAppResult(Res.Apps[i]);
      SL.Add('    {');
      SL.Add(Format('      "package": %s,', [JStr(A.PackageName)]));
      SL.Add(Format('      "score": %d,', [A.Score]));
      SL.Add(Format('      "severity": %s,', [JStr(SeverityToString(A.Severity))]));
      SL.Add(Format('      "sha256": %s,', [JStr(A.Sha256)]));
      SL.Add(Format('      "sha1": %s,', [JStr(A.Sha1)]));
      SL.Add(Format('      "md5": %s,', [JStr(A.Md5)]));
      SL.Add(Format('      "cert_sha256": %s,', [JStr(A.CertSha256)]));
      SL.Add(Format('      "signer": %s,', [JStr(A.Signer)]));
      SL.Add(Format('      "installer": %s,', [JStr(A.Installer)]));
      SL.Add(Format('      "has_launcher": %s,', [BoolToStr(A.HasLauncher, 'true', 'false')]));
      SL.Add(Format('      "families": [%s]', [JStr(A.MatchedFamilies.CommaText)]));
      if i < Res.Apps.Count - 1 then SL.Add('    },') else SL.Add('    }');
    end;
    SL.Add('  ],');
    SL.Add('  "findings": [');
    for i := 0 to Res.Findings.Count - 1 do begin
      F := TFinding(Res.Findings[i]);
      SL.Add('    {');
      SL.Add(Format('      "app": %s,', [JStr(F.App)]));
      SL.Add(Format('      "kind": %s,', [JStr(F.Kind)]));
      SL.Add(Format('      "severity": %s,', [JStr(SeverityToString(F.Severity))]));
      SL.Add(Format('      "detail": %s', [JStr(F.Detail)]));
      if i < Res.Findings.Count - 1 then SL.Add('    },') else SL.Add('    }');
    end;
    SL.Add('  ]');
    SL.Add('}');
    Result := SL.Text;
  finally
    SL.Free;
  end;
end;

procedure SaveReports(Res: TScanResult; const Dir, BaseName: string;
  out HtmlPath, JsonPath, TxtPath: string);
begin
  if not DirectoryExists(Dir) then
    ForceDirectories(Dir);
  HtmlPath := IncludeTrailingPathDelimiter(Dir) + BaseName + '.html';
  JsonPath := IncludeTrailingPathDelimiter(Dir) + BaseName + '.json';
  TxtPath := IncludeTrailingPathDelimiter(Dir) + BaseName + '.txt';

  with TStringList.Create do try
    Text := GenerateHtmlReport(Res);
    SaveToFile(HtmlPath);
  finally Free; end;

  with TStringList.Create do try
    Text := GenerateJsonReport(Res);
    SaveToFile(JsonPath);
  finally Free; end;

  with TStringList.Create do try
    Text := GenerateTextReport(Res);
    SaveToFile(TxtPath);
  finally Free; end;
end;

end.


