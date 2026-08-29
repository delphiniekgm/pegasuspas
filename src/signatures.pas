unit signatures;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TIocKind = (iocPackage, iocSha256, iocSha1, iocMd5, iocPerm, iocString, iocClass, iocCert,
    iocCertSha256, iocLib, iocAsset, iocDomain, iocIp, iocUrl, iocEmail);

  TIoc = record
    Kind: TIocKind;
    Value: string;
  end;

  TSignatureBlock = class
  public
    Family: string;
    Name: string;
    Severity: string;
    Iocs: array of TIoc;
    procedure Add(Kind: TIocKind; const Value: string);
  end;

  TSignatureDB = class
  public
    Blocks: array of TSignatureBlock;
    procedure LoadFile(const FileName: string);
    procedure LoadDirectory(const Dir: string);
    function Count: Integer;
    destructor Destroy; override;
  end;

function WildcardMatch(const Pattern, S: string): Boolean;

implementation

function WildcardMatch(const Pattern, S: string): Boolean;
var
  Pi, Si, Star, Ss: Integer;
begin
  Pi := 1; Si := 1; Star := 0; Ss := 0;
  while Si <= Length(S) do begin
    if (Pi <= Length(Pattern)) and ((Pattern[Pi] = '?') or (Pattern[Pi] = S[Si])) then begin
      Inc(Pi); Inc(Si);
    end
    else if (Pi <= Length(Pattern)) and (Pattern[Pi] = '*') then begin
      Star := Pi; Ss := Si; Inc(Pi);
    end
    else if Star <> 0 then begin
      Pi := Star + 1; Inc(Ss); Si := Ss;
    end
    else begin
      Result := False;
      Exit;
    end;
  end;
  while (Pi <= Length(Pattern)) and (Pattern[Pi] = '*') do
    Inc(Pi);
  Result := Pi > Length(Pattern);
end;

procedure TSignatureBlock.Add(Kind: TIocKind; const Value: string);
var
  N: Integer;
begin
  N := Length(Iocs);
  SetLength(Iocs, N + 1);
  Iocs[N].Kind := Kind;
  Iocs[N].Value := Value;
end;

function TSignatureDB.Count: Integer;
begin
  Result := Length(Blocks);
end;

destructor TSignatureDB.Destroy;
var
  i: Integer;
begin
  for i := 0 to High(Blocks) do
    Blocks[i].Free;
  inherited Destroy;
end;

procedure TSignatureDB.LoadFile(const FileName: string);
var
  Lines: TStringList;
  i, P: Integer;
  S, Key, Val: string;
  Cur: TSignatureBlock;
begin
  if not FileExists(FileName) then
    Exit;
  Cur := nil;
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(FileName);
    for i := 0 to Lines.Count - 1 do begin
      S := Trim(Lines[i]);
      if (S = '') or (Pos('#', S) = 1) then
        Continue;
      P := Pos(':', S);
      if P = 0 then
        Continue;
      Key := LowerCase(Trim(Copy(S, 1, P - 1)));
      Val := Trim(Copy(S, P + 1, MaxInt));
      if Key = 'family' then begin
        Cur := TSignatureBlock.Create;
        Cur.Family := Val;
        SetLength(Blocks, Length(Blocks) + 1);
        Blocks[High(Blocks)] := Cur;
      end
      else if Cur <> nil then begin
        if Key = 'name' then
          Cur.Name := Val
        else if Key = 'severity' then
          Cur.Severity := LowerCase(Val)
        else if Key = 'package' then
          Cur.Add(iocPackage, Val)
        else if Key = 'sha256' then
          Cur.Add(iocSha256, LowerCase(Val))
        else if Key = 'sha1' then
          Cur.Add(iocSha1, LowerCase(Val))
        else if Key = 'md5' then
          Cur.Add(iocMd5, LowerCase(Val))
        else if Key = 'perm' then
          Cur.Add(iocPerm, Val)
        else if Key = 'string' then
          Cur.Add(iocString, Val)
        else if Key = 'class' then
          Cur.Add(iocClass, Val)
        else if Key = 'lib' then
          Cur.Add(iocLib, LowerCase(Val))
        else if Key = 'asset' then
          Cur.Add(iocAsset, Val)
        else if Key = 'cert' then
          Cur.Add(iocCert, Val)
        else if Key = 'cert_sha256' then
          Cur.Add(iocCertSha256, LowerCase(Val))
        else if Key = 'domain' then
          Cur.Add(iocDomain, Val)
        else if Key = 'ip' then
          Cur.Add(iocIp, Val)
        else if Key = 'url' then
          Cur.Add(iocUrl, Val)
        else if Key = 'email' then
          Cur.Add(iocEmail, Val);
      end;
    end;
  finally
    Lines.Free;
  end;
end;

procedure TSignatureDB.LoadDirectory(const Dir: string);
var
  SR: TSearchRec;
begin
  if not DirectoryExists(Dir) then
    Exit;
  if FindFirst(IncludeTrailingPathDelimiter(Dir) + '*.txt', faAnyFile, SR) = 0 then begin
    repeat
      if (SR.Attr and faDirectory) = 0 then
        LoadFile(IncludeTrailingPathDelimiter(Dir) + SR.Name);
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
end;

end.
