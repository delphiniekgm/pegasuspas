unit stix2;

{$mode objfpc}{$H+}

// Minimal STIX 2.1 indicator-bundle parser for MVT-compatible IoC files.
// Extracts the IOC patterns MVT actually uses for Android:
//   [domain-name:value='example.com']
//   [ipv4-addr:value='1.2.3.4']   [ipv6-addr:value='...']
//   [url:value='http://...']       [email-addr:value='x@y.com']
//   [file:hashes.'SHA-256' = '...'] / 'SHA-1' / 'MD5'
//   [android-package-name:value='com.example']
// Deliberately dependency-free (no JSON library): it scans the raw bundle text
// for "pattern" fields, which is sufficient for MVT's STIX2 indicator files.

interface

uses
  Classes, SysUtils, StrUtils;

type
  TStixKind = (skDomain, skIpv4, skIpv6, skUrl, skEmail,
               skSha256, skSha1, skMd5, skPackage,
               skProperty, skFilePath, skFileName, skProcess,
               skCertSha256, skCertSha1);

  TStix2Indicators = class
  public
    Family: string;
    IsAndroid: Boolean;
    Domains: TStringList;
    Ips: TStringList;
    Urls: TStringList;
    Emails: TStringList;
    Sha256: TStringList;
    Sha1: TStringList;
    Md5: TStringList;
    Packages: TStringList;
    Properties: TStringList;
    Paths: TStringList;
    FileNames: TStringList;
    Processes: TStringList;
    CertSha256: TStringList;
    CertSha1: TStringList;
    constructor Create;
    destructor Destroy; override;
    procedure LoadFile(const FileName: string);
    function TotalCount: Integer;
  end;

function LoadStix2Directory(const Dir: string): TList;
procedure FreeStix2List(List: TList);
function ExtractHostFromUrl(const Url: string): string;

implementation

function ReadFileAsString(const FileName: string): string;
var
  F: TFileStream;
  SS: TStringStream;
begin
  SS := TStringStream.Create('');
  try
    F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      SS.CopyFrom(F, F.Size);
    finally
      F.Free;
    end;
    Result := SS.DataString;
  finally
    SS.Free;
  end;
end;

// Content between the last two single quotes in a pattern string.
function LastQuoted(const S: string): string;
var
  i, j: Integer;
begin
  Result := '';
  i := Length(S);
  while (i >= 1) and (S[i] <> '''') do
    Dec(i);
  j := i - 1;
  while (j >= 1) and (S[j] <> '''') do
    Dec(j);
  if (j >= 1) and (i > j) then
    Result := Copy(S, j + 1, i - j - 1);
end;

function ClassifyPattern(const Pattern: string; out Kind: TStixKind;
  out Value: string): Boolean;
begin
  Result := True;
  Value := LastQuoted(Pattern);
  if Pos('domain-name:value', Pattern) > 0 then
    Kind := skDomain
  else if Pos('ipv4-addr:value', Pattern) > 0 then
    Kind := skIpv4
  else if Pos('ipv6-addr:value', Pattern) > 0 then
    Kind := skIpv6
  else if Pos('url:value', Pattern) > 0 then
    Kind := skUrl
  else if Pos('email-addr:value', Pattern) > 0 then
    Kind := skEmail
  else if Pos('android-property', Pattern) > 0 then
    Kind := skProperty
  else if Pos('file:path', Pattern) > 0 then
    Kind := skFilePath
  else if Pos('file:name', Pattern) > 0 then
    Kind := skFileName
  else if Pos('file:hashes', Pattern) > 0 then begin
    if Pos('SHA-256', Pattern) > 0 then Kind := skSha256
    else if Pos('SHA-1', Pattern) > 0 then Kind := skSha1
    else if Pos('MD5', Pattern) > 0 then Kind := skMd5
    else Result := False;
  end
  else if Pos('x509-certificate', Pattern) > 0 then begin
    if Pos('SHA-256', Pattern) > 0 then Kind := skCertSha256
    else if Pos('SHA-1', Pattern) > 0 then Kind := skCertSha1
    else Result := False;
  end
  else if Pos('process:name', Pattern) > 0 then
    Kind := skProcess
  else if (Pos('android-package', Pattern) > 0) or
          (Pos('package-name', Pattern) > 0) then
    Kind := skPackage
  else
    Result := False;
  if Result and (Value = '') then
    Result := False;
end;

function ExtractHostFromUrl(const Url: string): string;
var
  P, Q: Integer;
begin
  Result := '';
  P := Pos('://', Url);
  if P = 0 then
    Exit;
  P := P + 3;
  Q := P;
  while (Q <= Length(Url)) and (Url[Q] in ['a'..'z', 'A'..'Z', '0'..'9', '.', '-', '_', ':', '[', ']']) do
    Inc(Q);
  Result := LowerCase(Copy(Url, P, Q - P));
  P := Pos(':', Result);
  if (P > 0) and (Pos(']', Result) = 0) then
    Result := Copy(Result, 1, P - 1);
end;

constructor TStix2Indicators.Create;
begin
  inherited Create;
  Family := '';
  IsAndroid := False;
  Domains := TStringList.Create; Domains.Sorted := True; Domains.Duplicates := dupIgnore;
  Ips := TStringList.Create; Ips.Sorted := True; Ips.Duplicates := dupIgnore;
  Urls := TStringList.Create; Urls.Sorted := True; Urls.Duplicates := dupIgnore;
  Emails := TStringList.Create; Emails.Sorted := True; Emails.Duplicates := dupIgnore;
  Sha256 := TStringList.Create; Sha256.Sorted := True; Sha256.Duplicates := dupIgnore;
  Sha1 := TStringList.Create; Sha1.Sorted := True; Sha1.Duplicates := dupIgnore;
  Md5 := TStringList.Create; Md5.Sorted := True; Md5.Duplicates := dupIgnore;
  Packages := TStringList.Create; Packages.Sorted := True; Packages.Duplicates := dupIgnore;
  Properties := TStringList.Create; Properties.Sorted := True; Properties.Duplicates := dupIgnore;
  Paths := TStringList.Create; Paths.Sorted := True; Paths.Duplicates := dupIgnore;
  FileNames := TStringList.Create; FileNames.Sorted := True; FileNames.Duplicates := dupIgnore;
  Processes := TStringList.Create; Processes.Sorted := True; Processes.Duplicates := dupIgnore;
  CertSha256 := TStringList.Create; CertSha256.Sorted := True; CertSha256.Duplicates := dupIgnore;
  CertSha1 := TStringList.Create; CertSha1.Sorted := True; CertSha1.Duplicates := dupIgnore;
end;

destructor TStix2Indicators.Destroy;
begin
  Domains.Free;
  Ips.Free;
  Urls.Free;
  Emails.Free;
  Sha256.Free;
  Sha1.Free;
  Md5.Free;
  Packages.Free;
  Properties.Free;
  Paths.Free;
  FileNames.Free;
  Processes.Free;
  CertSha256.Free;
  CertSha1.Free;
  inherited Destroy;
end;

function TStix2Indicators.TotalCount: Integer;
begin
  Result := Domains.Count + Ips.Count + Urls.Count + Emails.Count +
            Sha256.Count + Sha1.Count + Md5.Count + Packages.Count +
            Properties.Count + Paths.Count + FileNames.Count + Processes.Count +
            CertSha256.Count + CertSha1.Count;
end;

procedure TStix2Indicators.LoadFile(const FileName: string);
var
  Raw: string;
  Patterns: TStringList;
  i: Integer;
  Kind: TStixKind;
  Value: string;

  procedure AddOne;
  var
    Host: string;
  begin
    case Kind of
      skDomain: Domains.Add(LowerCase(Value));
      skIpv4, skIpv6: Ips.Add(LowerCase(Value));
      skUrl: begin
        Urls.Add(LowerCase(Value));
        Host := ExtractHostFromUrl(Value);
        if Host <> '' then
          Domains.Add(Host);
      end;
      skEmail: Emails.Add(LowerCase(Value));
      skSha256: Sha256.Add(LowerCase(Value));
      skSha1: Sha1.Add(LowerCase(Value));
      skMd5: Md5.Add(LowerCase(Value));
      skPackage: Packages.Add(LowerCase(Value));
      skProperty: Properties.Add(LowerCase(Value));
      skFilePath: Paths.Add(Value);
      skFileName: FileNames.Add(LowerCase(Value));
      skProcess: Processes.Add(LowerCase(Value));
      skCertSha256: CertSha256.Add(LowerCase(Value));
      skCertSha1: CertSha1.Add(LowerCase(Value));
    end;
  end;

  procedure CollectPatterns(const RawJson: string);
  var
    P, Q: Integer;
    Key: string;
    Pat: string;
  begin
    Key := '"pattern"';
    P := PosEx(Key, RawJson, 1);
    while P > 0 do begin
      P := PosEx('"', RawJson, P + Length(Key));
      if P = 0 then
        Break;
      Inc(P);
      Q := P;
      while (Q <= Length(RawJson)) and (RawJson[Q] <> '"') do
        Inc(Q);
      Pat := Copy(RawJson, P, Q - P);
      Patterns.Add(Pat);
      P := PosEx(Key, RawJson, Q + 1);
    end;
  end;

begin
  if not FileExists(FileName) then
    Exit;
  Family := LowerCase(ChangeFileExt(ExtractFileName(FileName), ''));
  IsAndroid := Pos('android', Family) > 0;
  if Pos('pegasus', Family) > 0 then
    Family := 'NSO-Pegasus'
  else if Pos('android', Family) > 0 then
    Family := 'MVT-Android-Campaign';

  Raw := ReadFileAsString(FileName);
  Patterns := TStringList.Create;
  try
    CollectPatterns(Raw);
    for i := 0 to Patterns.Count - 1 do begin
      if ClassifyPattern(Patterns[i], Kind, Value) then
        AddOne;
    end;
  finally
    Patterns.Free;
  end;
end;

function LoadStix2Directory(const Dir: string): TList;
var
  SR: TSearchRec;
  St: TStix2Indicators;
begin
  Result := TList.Create;
  if not DirectoryExists(Dir) then
    Exit;
  if FindFirst(IncludeTrailingPathDelimiter(Dir) + '*.stix2', faAnyFile, SR) = 0 then begin
    repeat
      if (SR.Attr and faDirectory) = 0 then begin
        St := TStix2Indicators.Create;
        St.LoadFile(IncludeTrailingPathDelimiter(Dir) + SR.Name);
        Result.Add(St);
      end;
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
end;

procedure FreeStix2List(List: TList);
var
  i: Integer;
begin
  if List = nil then
    Exit;
  for i := 0 to List.Count - 1 do
    TStix2Indicators(List[i]).Free;
  List.Free;
end;

end.

