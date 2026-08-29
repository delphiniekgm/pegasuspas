unit apk;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, manifest;

type
  TApkAnalysis = class
  public
    FileName: string;
    PackageName: string;
    Sha256: string;
    Sha1: string;
    Md5: string;
    CertSha256: string;
    CertSha1: string;
    Permissions: TStringList;
    Components: TStringList;
    Strings: TStringList;
    Libraries: TStringList;
    Assets: TStringList;
    FileNames: TStringList;
    HasManifest: Boolean;
    HasLauncher: Boolean;
    ManifestError: string;
    constructor Create;
    destructor Destroy; override;
  end;

function AnalyzeApk(const ApkPath, WorkDir: string; ExtractStrings: Boolean;
  MinStringLen: Integer): TApkAnalysis;
procedure ExtractAsciiStrings(const FileName: string; MinLen: Integer; Strings: TStringList);
function ExtractSignerCertDer(const Blob: TBytes): TBytes;

implementation

uses zipper, hashes, logging;

procedure ReadFileBytes(const FileName: string; out B: TBytes);
var
  F: TFileStream;
begin
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    SetLength(B, F.Size);
    if F.Size > 0 then
      F.Read(B[0], F.Size);
  finally
    F.Free;
  end;
end;

procedure ExtractAsciiStrings(const FileName: string; MinLen: Integer; Strings: TStringList);
const
  MaxStrings = 200000;
var
  F: TFileStream;
  Buf: array[0..65535] of Byte;
  N, i: Integer;
  Cur: string;
begin
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Cur := '';
    repeat
      N := F.Read(Buf, SizeOf(Buf));
      for i := 0 to N - 1 do begin
        if (Buf[i] >= 32) and (Buf[i] <= 126) then begin
          if Length(Cur) < 4096 then
            Cur := Cur + Char(Buf[i]);
        end
        else begin
          if (Length(Cur) >= MinLen) and (Strings.Count < MaxStrings) then
            Strings.Add(Cur);
          Cur := '';
        end;
      end;
      if Strings.Count >= MaxStrings then
        Break;
    until N <= 0;
    if (Length(Cur) >= MinLen) and (Strings.Count < MaxStrings) then
      Strings.Add(Cur);
  finally
    F.Free;
  end;
end;

procedure ExtractApk(const ApkPath, DestDir: string; out ManifestPath: string;
  out DexPaths, LibNames, AssetNames, FileNames: TStringList;
  out SignFile: string);
var
  UnZipper: TUnZipper;
  Wanted: TStringList;
  i: Integer;
  EntryName, Lower, Ext: string;
begin
  ManifestPath := '';
  SignFile := '';
  DexPaths := TStringList.Create;
  LibNames := TStringList.Create;
  AssetNames := TStringList.Create;
  FileNames := TStringList.Create;
  Wanted := TStringList.Create;
  if not DirectoryExists(DestDir) then
    ForceDirectories(DestDir);
  UnZipper := TUnZipper.Create;
  try
    UnZipper.FileName := ApkPath;
    UnZipper.OutputPath := DestDir;
    UnZipper.Examine;
    for i := 0 to UnZipper.Entries.Count - 1 do begin
      EntryName := TZipFileEntry(UnZipper.Entries[i]).ArchiveFileName;
      Lower := LowerCase(EntryName);
      if EntryName = 'AndroidManifest.xml' then begin
        ManifestPath := IncludeTrailingPathDelimiter(DestDir) + 'AndroidManifest.xml';
        Wanted.Add(EntryName);
      end
      else if (Pos('classes', Lower) = 1) and (Pos('/', EntryName) = 0) then begin
        DexPaths.Add(IncludeTrailingPathDelimiter(DestDir) + EntryName);
        Wanted.Add(EntryName);
      end;
      // Collect file/asset/native-library names for IoC matching.
      if EntryName <> '' then
        FileNames.Add(Lower);
      if (Pos('lib/', Lower) = 1) and (Pos('.so', Lower) > 0) then
        LibNames.Add(ExtractFileName(EntryName));
      if Pos('assets/', Lower) = 1 then
        AssetNames.Add(EntryName);
      // v1 (JAR) signature block holds the signer certificate.
      if (SignFile = '') and (Pos('meta-inf/', Lower) = 1) then begin
        Ext := UpperCase(ExtractFileExt(EntryName));
        if (Ext = '.RSA') or (Ext = '.DSA') or (Ext = '.EC') then begin
          SignFile := IncludeTrailingPathDelimiter(DestDir) + EntryName;
          Wanted.Add(EntryName);
        end;
      end;
    end;
    if Wanted.Count > 0 then
      UnZipper.UnZipFiles(Wanted);
  finally
    Wanted.Free;
    UnZipper.Free;
  end;
end;

function ParseDerLength(const B: TBytes; var Pos: Integer): Integer;
var
  First, N, i: Integer;
begin
  Result := -1;
  if Pos >= Length(B) then
    Exit;
  First := B[Pos];
  Inc(Pos);
  if (First and $80) = 0 then
    Result := First
  else begin
    N := First and $7F;
    if (N = 0) or (N > 4) or (Pos + N > Length(B)) then
      Exit;
    Result := 0;
    for i := 0 to N - 1 do begin
      Result := (Result shl 8) or B[Pos];
      Inc(Pos);
    end;
  end;
end;

// Extract the DER-encoded signer certificate from a PKCS#7/CMS SignedData blob
// (the contents of a META-INF/*.RSA|.DSA|.EC file inside an APK).
function ExtractSignerCertDer(const Blob: TBytes): TBytes;
var
  Pos, Len, EndPos, CertStart: Integer;
begin
  Result := nil;
  Pos := 0;
  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
  if (Pos >= Length(Blob)) or (Blob[Pos] <> $30) then Exit;
  Inc(Pos);
  Len := ParseDerLength(Blob, Pos);
  if (Len < 0) or (Pos + Len > Length(Blob)) then Exit;
  // skip contentType OID
  if (Pos >= Length(Blob)) or (Blob[Pos] <> $06) then Exit;
  Inc(Pos);
  Len := ParseDerLength(Blob, Pos);
  if Len < 0 then Exit;
  Inc(Pos, Len);
  // content [0] EXPLICIT wrapping SignedData
  if (Pos >= Length(Blob)) or (Blob[Pos] <> $A0) then Exit;
  Inc(Pos);
  Len := ParseDerLength(Blob, Pos);
  if Len < 0 then Exit;
  // SignedData ::= SEQUENCE
  if (Pos >= Length(Blob)) or (Blob[Pos] <> $30) then Exit;
  Inc(Pos);
  Len := ParseDerLength(Blob, Pos);
  if Len < 0 then Exit;
  EndPos := Pos + Len;
  // Walk SignedData fields to the certificates [0] IMPLICIT field.
  while Pos < EndPos do begin
    if Blob[Pos] = $A0 then begin
      Inc(Pos);
      Len := ParseDerLength(Blob, Pos);
      if Len < 0 then Exit;
      // first child is the certificate SEQUENCE
      if (Pos < Length(Blob)) and (Blob[Pos] = $30) then begin
        CertStart := Pos;
        Inc(Pos);
        Len := ParseDerLength(Blob, Pos);
        if Len < 0 then Exit;
        SetLength(Result, Pos + Len - CertStart);
        if Length(Result) > 0 then
          Move(Blob[CertStart], Result[0], Length(Result));
      end;
      Exit;
    end
    else begin
      Inc(Pos);
      Len := ParseDerLength(Blob, Pos);
      if Len < 0 then Exit;
      Inc(Pos, Len);
    end;
  end;
end;

function AnalyzeApk(const ApkPath, WorkDir: string; ExtractStrings: Boolean;
  MinStringLen: Integer): TApkAnalysis;
var
  M: TManifestInfo;
  ManifestPath, AppDir, SignFile: string;
  DexPaths, LibNames, AssetNames, FileNames: TStringList;
  i: Integer;
  B, CertDer: TBytes;
begin
  Result := TApkAnalysis.Create;
  Result.FileName := ApkPath;
  Result.Sha256 := SHA256File(ApkPath);
  Result.Sha1 := SHA1HexFile(ApkPath);
  Result.Md5 := MD5HexFile(ApkPath);
  AppDir := IncludeTrailingPathDelimiter(WorkDir) + ChangeFileExt(ExtractFileName(ApkPath), '');
  DexPaths := nil;
  LibNames := nil;
  AssetNames := nil;
  FileNames := nil;
  try
    try
      ExtractApk(ApkPath, AppDir, ManifestPath, DexPaths, LibNames, AssetNames, FileNames, SignFile);
    except
      on E: Exception do begin
        ManifestPath := '';
        SignFile := '';
        Logger.ExceptionLog('failed to extract apk ' + ApkPath, E);
      end;
    end;
    if LibNames <> nil then Result.Libraries.Assign(LibNames);
    if AssetNames <> nil then Result.Assets.Assign(AssetNames);
    if FileNames <> nil then Result.FileNames.Assign(FileNames);
    if (SignFile <> '') and FileExists(SignFile) then begin
      try
        ReadFileBytes(SignFile, B);
        CertDer := ExtractSignerCertDer(B);
        if Length(CertDer) > 0 then begin
          Result.CertSha256 := SHA256BytesHex(CertDer[0], Length(CertDer));
          Result.CertSha1 := SHA1HexData(CertDer[0], Length(CertDer));
        end;
      except
        on E: Exception do
          Logger.ExceptionLog('certificate parse failed for ' + ApkPath, E);
      end;
    end;
    if (ManifestPath <> '') and FileExists(ManifestPath) then begin
      try
        ReadFileBytes(ManifestPath, B);
        M := ParseBinaryManifest(B);
        try
          Result.PackageName := M.PackageName;
          Result.Permissions.Assign(M.Permissions);
          Result.Components.Assign(M.Components);
          Result.HasManifest := True;
          Result.HasLauncher := M.HasLauncher;
        finally
          M.Free;
        end;
      except
        on E: Exception do begin
          Result.HasManifest := False;
          Result.ManifestError := E.Message;
          Logger.ExceptionLog('manifest parse failed for ' + ApkPath, E);
        end;
      end;
    end;
    if ExtractStrings and (DexPaths <> nil) then begin
      for i := 0 to DexPaths.Count - 1 do
        if FileExists(DexPaths[i]) then
          ExtractAsciiStrings(DexPaths[i], MinStringLen, Result.Strings);
      // sort + dedup (keeps memory/scan small and IoC matching fast)
      Result.Strings.Sort;
      for i := Result.Strings.Count - 1 downto 1 do
        if Result.Strings[i] = Result.Strings[i - 1] then
          Result.Strings.Delete(i);
    end;
  finally
    DexPaths.Free;
    LibNames.Free;
    AssetNames.Free;
    FileNames.Free;
  end;
end;

constructor TApkAnalysis.Create;
begin
  inherited Create;
  PackageName := '';
  Sha256 := '';
  Sha1 := '';
  Md5 := '';
  CertSha256 := '';
  CertSha1 := '';
  HasManifest := False;
  HasLauncher := False;
  ManifestError := '';
  Permissions := TStringList.Create;
  Components := TStringList.Create;
  Strings := TStringList.Create;
  Libraries := TStringList.Create;
  Assets := TStringList.Create;
  FileNames := TStringList.Create;
end;

destructor TApkAnalysis.Destroy;
begin
  Permissions.Free;
  Components.Free;
  Strings.Free;
  Libraries.Free;
  Assets.Free;
  FileNames.Free;
  inherited Destroy;
end;

end.
