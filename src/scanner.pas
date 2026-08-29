unit scanner;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, config, adb, apk, signatures, logging, stix2;

type
  TSeverity = (sevNone, sevLow, sevMedium, sevHigh, sevCritical);

  TFinding = class
  public
    App: string;
    Kind: string;
    Severity: TSeverity;
    Detail: string;
    constructor Create(const AApp, AKind: string; ASeverity: TSeverity; const ADetail: string);
  end;

  TAppResult = class
  public
    PackageName: string;
    Score: Integer;
    Severity: TSeverity;
    Sha256: string;
    Sha1: string;
    Md5: string;
    CertSha256: string;
    CertSha1: string;
    Signer: string;
    Installer: string;
    HasManifest: Boolean;
    HasLauncher: Boolean;
    MatchedFamilies: TStringList;
    Permissions: TStringList;
    Components: TStringList;
    Strings: TStringList;
    Libraries: TStringList;
    Assets: TStringList;
    FileNames: TStringList;
    constructor Create;
    destructor Destroy; override;
  end;

  TScanResult = class
  public
    DeviceSerial: string;
    DeviceModel: string;
    AndroidVersion: string;
    Started: TDateTime;
    Finished: TDateTime;
    Apps: TList;
    Findings: TList;
    Log: TStringList;
    constructor Create;
    destructor Destroy; override;
    procedure AddLog(const S: string);
  end;

  TScanner = class
  private
    FConfig: TAppConfig;
    FAdb: TAdb;
    FDb: TSignatureDB;
    FStixSets: TList;
    FOnIdle: TIdleProc;
    procedure DoLog(const S: string);
    procedure DoError(const S: string);
    procedure ScanApp(const Serial, Pkg, WorkDir: string; Res: TScanResult);
    function ScoreApp(Res: TAppResult): Integer;
    procedure MatchStixIndicators(App: TAppResult; Res: TScanResult);
    procedure MatchDeviceIndicators(const Serial: string; Res: TScanResult);
    procedure SetOnIdle(const Value: TIdleProc);
  public
    constructor Create(AConfig: TAppConfig);
    destructor Destroy; override;
    function Scan(const Serial, WorkDir: string): TScanResult;
    function ScanApkDirectory(const Dir, WorkDir: string): TScanResult;
    function ScanOne(const Serial, Pkg, WorkDir: string): TScanResult;
    property OnIdle: TIdleProc read FOnIdle write SetOnIdle;
  end;

function SeverityToString(Sev: TSeverity): string;

implementation

uses StrUtils;

function SeverityToString(Sev: TSeverity): string;
begin
  case Sev of
    sevNone: Result := 'none';
    sevLow: Result := 'low';
    sevMedium: Result := 'medium';
    sevHigh: Result := 'high';
    sevCritical: Result := 'critical';
  end;
end;

constructor TFinding.Create(const AApp, AKind: string; ASeverity: TSeverity; const ADetail: string);
begin
  inherited Create;
  App := AApp;
  Kind := AKind;
  Severity := ASeverity;
  Detail := ADetail;
end;

constructor TAppResult.Create;
begin
  inherited Create;
  Score := 0;
  Severity := sevNone;
  Signer := '';
  Installer := '';
  CertSha256 := '';
  CertSha1 := '';
  HasManifest := False;
  HasLauncher := False;
  MatchedFamilies := TStringList.Create;
  MatchedFamilies.Duplicates := dupIgnore;
  Permissions := TStringList.Create;
  Components := TStringList.Create;
  Strings := TStringList.Create;
  Libraries := TStringList.Create;
  Assets := TStringList.Create;
  FileNames := TStringList.Create;
end;

destructor TAppResult.Destroy;
begin
  MatchedFamilies.Free;
  Permissions.Free;
  Components.Free;
  Strings.Free;
  Libraries.Free;
  Assets.Free;
  FileNames.Free;
  inherited Destroy;
end;

constructor TScanResult.Create;
begin
  inherited Create;
  Apps := TList.Create;
  Findings := TList.Create;
  Log := TStringList.Create;
  Started := Now;
end;

destructor TScanResult.Destroy;
var
  i: Integer;
begin
  for i := 0 to Apps.Count - 1 do
    TObject(Apps[i]).Free;
  Apps.Free;
  for i := 0 to Findings.Count - 1 do
    TObject(Findings[i]).Free;
  Findings.Free;
  Log.Free;
  inherited Destroy;
end;

procedure TScanResult.AddLog(const S: string);
begin
  Log.Add(S);
end;

constructor TScanner.Create(AConfig: TAppConfig);
begin
  inherited Create;
  FConfig := AConfig;
  FAdb := TAdb.Create(AConfig.AdbPath, AConfig.TimeoutMs);
  FDb := TSignatureDB.Create;
  FDb.LoadDirectory(AConfig.RulesDir);
  DoLog(Format('Loaded %d signature blocks from "%s"', [FDb.Count, AConfig.RulesDir]));
  FStixSets := LoadStix2Directory(AConfig.RulesDir);
  DoLog(Format('Loaded %d STIX2 indicator set(s) from "%s"', [FStixSets.Count, AConfig.RulesDir]));
end;

destructor TScanner.Destroy;
begin
  FreeStix2List(FStixSets);
  FDb.Free;
  FAdb.Free;
  inherited Destroy;
end;

procedure TScanner.SetOnIdle(const Value: TIdleProc);
begin
  FOnIdle := Value;
  FAdb.OnIdle := Value;
end;

procedure TScanner.DoLog(const S: string);
begin
  Logger.Info(S);
end;

procedure TScanner.DoError(const S: string);
begin
  Logger.Error(S);
end;

function ExtractSigner(const Dump: string): string;
var
  P, Q: Integer;
begin
  Result := '';
  P := Pos('signatures=', Dump);
  if P = 0 then
    Exit;
  P := PosEx('[', Dump, P);
  if P = 0 then
    Exit;
  Q := PosEx(']', Dump, P);
  if Q = 0 then
    Exit;
  Result := Copy(Dump, P + 1, Q - P - 1);
end;

function ExtractInstaller(const Dump: string): string;
var
  P, Q: Integer;
begin
  Result := '';
  P := Pos('installerPackageName=', Dump);
  if P = 0 then
    Exit;
  P := P + Length('installerPackageName=');
  Q := P;
  while (Q <= Length(Dump)) and (not (Dump[Q] in [#10, #13])) do
    Inc(Q);
  Result := Trim(Copy(Dump, P, Q - P));
end;

function BlockMatches(Block: TSignatureBlock; App: TAppResult): Boolean;
var
  i, j: Integer;
  K: TIocKind;
  V: string;
  Soft: Integer;
begin
  // Hard indicators (package / hash / cert) match a family on their own.
  // Soft indicators (perm / string / class) need at least 2 hits to count.
  Soft := 0;
  for i := 0 to High(Block.Iocs) do begin
    K := Block.Iocs[i].Kind;
    V := Block.Iocs[i].Value;
    case K of
      iocPackage:
        if WildcardMatch(V, App.PackageName) then Exit(True);
      iocSha256:
        if SameText(V, App.Sha256) then Exit(True);
      iocSha1:
        if SameText(V, App.Sha1) then Exit(True);
      iocMd5:
        if SameText(V, App.Md5) then Exit(True);
      iocCert:
        if (App.Signer <> '') and (Pos(LowerCase(V), LowerCase(App.Signer)) > 0) then Exit(True);
      iocCertSha256:
        if (App.CertSha256 <> '') and SameText(V, App.CertSha256) then Exit(True);
      iocLib:
        for j := 0 to App.Libraries.Count - 1 do
          if SameText(App.Libraries[j], V) then Exit(True);
      iocAsset:
        for j := 0 to App.Assets.Count - 1 do
          if SameText(App.Assets[j], V) then Exit(True);
      iocDomain, iocIp, iocUrl, iocEmail:
        for j := 0 to App.Strings.Count - 1 do
          if ContainsText(App.Strings[j], V) then Exit(True);
      iocPerm:
        for j := 0 to App.Permissions.Count - 1 do
          if SameText(App.Permissions[j], V) then begin
            Inc(Soft);
            Break;
          end;
      iocString:
        for j := 0 to App.Strings.Count - 1 do
          if ContainsText(App.Strings[j], V) then begin
            Inc(Soft);
            Break;
          end;
      iocClass:
        for j := 0 to App.Components.Count - 1 do
          if ContainsText(App.Components[j], V) then begin
            Inc(Soft);
            Break;
          end;
    end;
  end;
  Result := Soft >= 2;
end;

function TScanner.ScoreApp(Res: TAppResult): Integer;
begin
  if Res.MatchedFamilies.Count > 0 then begin
    Res.Score := 100;
    Res.Severity := sevCritical;
  end
  else begin
    Res.Score := 0;
    Res.Severity := sevNone;
  end;
  Result := Res.Score;
end;

procedure ExtractHostCandidates(const S: string; Candidates: TStringList);
var
  i, j, P: Integer;
  Tok: string;
begin
  i := 1;
  while i <= Length(S) do begin
    if S[i] in ['a'..'z', 'A'..'Z', '0'..'9', '.', '-', '_'] then begin
      j := i;
      while (j <= Length(S)) and (S[j] in ['a'..'z', 'A'..'Z', '0'..'9', '.', '-', '_']) do
        Inc(j);
      Tok := LowerCase(Copy(S, i, j - i));
      if (Length(Tok) >= 4) and (Pos('.', Tok) > 0) and
         (Tok[1] <> '.') and (Tok[1] <> '-') and
         (Tok[Length(Tok)] <> '.') and (Tok[Length(Tok)] <> '-') then begin
        P := 1;
        while (P <= Length(Tok)) and (not (Tok[P] in ['a'..'z'])) do
          Inc(P);
        if P <= Length(Tok) then
          Candidates.Add(Tok);
      end;
      i := j;
    end
    else
      Inc(i);
  end;
end;

procedure TScanner.MatchStixIndicators(App: TAppResult; Res: TScanResult);
var
  SetIdx, i, j, P: Integer;
  St: TStix2Indicators;
  Hosts: TStringList;
  Host: string;
  Matched: Boolean;
begin
  Hosts := TStringList.Create;
  Hosts.Sorted := True;
  Hosts.Duplicates := dupIgnore;
  try
    for i := 0 to App.Strings.Count - 1 do
      ExtractHostCandidates(App.Strings[i], Hosts);

    for SetIdx := 0 to FStixSets.Count - 1 do begin
      St := TStix2Indicators(FStixSets[SetIdx]);

      if (App.PackageName <> '') and
         (St.Packages.IndexOf(LowerCase(App.PackageName)) >= 0) then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known spyware package (' + St.Family + '): ' + App.PackageName));
      end;

      if (App.Sha256 <> '') and (St.Sha256.IndexOf(App.Sha256) >= 0) then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known APK SHA-256 (' + St.Family + '): ' + App.Sha256));
      end;

      if (App.Md5 <> '') and (St.Md5.IndexOf(App.Md5) >= 0) then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known APK MD5 (' + St.Family + '): ' + App.Md5));
      end;

      if (App.Sha1 <> '') and (St.Sha1.IndexOf(App.Sha1) >= 0) then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known APK SHA-1 (' + St.Family + '): ' + App.Sha1));
      end;

      if (App.CertSha256 <> '') and (St.CertSha256.IndexOf(App.CertSha256) >= 0) then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known signer certificate SHA-256 (' + St.Family + '): ' + App.CertSha256));
      end;

      if (App.CertSha1 <> '') and (St.CertSha1.IndexOf(App.CertSha1) >= 0) then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known signer certificate SHA-1 (' + St.Family + '): ' + App.CertSha1));
      end;

      for i := 0 to St.FileNames.Count - 1 do
        for j := 0 to App.FileNames.Count - 1 do
          if (App.FileNames[j] = St.FileNames[i]) or
             (ExtractFileName(App.FileNames[j]) = St.FileNames[i]) then begin
            App.MatchedFamilies.Add(St.Family);
            Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
              'Known file name found in APK (' + St.Family + '): ' + St.FileNames[i]));
          end;

      Matched := False;
      for i := 0 to Hosts.Count - 1 do begin
        Host := Hosts[i];
        repeat
          if St.Domains.IndexOf(Host) >= 0 then begin
            Matched := True;
            Break;
          end;
          P := Pos('.', Host);
          if P = 0 then
            Break;
          Host := Copy(Host, P + 1, MaxInt);
        until False;
        if Matched then
          Break;
      end;
      if Matched then begin
        App.MatchedFamilies.Add(St.Family);
        Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
          'Known Pegasus C2 domain found in code (' + St.Family + ')'));
      end;

      for i := 0 to App.Strings.Count - 1 do begin
        for j := 0 to St.Emails.Count - 1 do
          if ContainsText(App.Strings[i], St.Emails[j]) then begin
            App.MatchedFamilies.Add(St.Family);
            Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevHigh,
              'Known Pegasus email address found: ' + St.Emails[j]));
          end;
        for j := 0 to St.Ips.Count - 1 do
          if ContainsText(App.Strings[i], St.Ips[j]) then begin
            App.MatchedFamilies.Add(St.Family);
            Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
              'Known C2 IP found: ' + St.Ips[j]));
          end;
        for j := 0 to St.Urls.Count - 1 do
          if ContainsText(App.Strings[i], St.Urls[j]) then begin
            App.MatchedFamilies.Add(St.Family);
            Res.Findings.Add(TFinding.Create(App.PackageName, 'stix', sevCritical,
              'Known C2 URL found: ' + St.Urls[j]));
          end;
      end;
    end;
  finally
    Hosts.Free;
  end;
end;

procedure CollectProcessNames(const PsOutput: string; Names: TStringList);
var
  Lines: TStringList;
  i, P: Integer;
  Line, Tok: string;
begin
  Lines := TStringList.Create;
  try
    Lines.Text := PsOutput;
    for i := 0 to Lines.Count - 1 do begin
      Line := Trim(Lines[i]);
      if Line = '' then
        Continue;
      // The process name is the last whitespace-delimited field on each line.
      P := Length(Line);
      while (P >= 1) and (not (Line[P] in [' ', #9])) do
        Dec(P);
      Tok := LowerCase(Trim(Copy(Line, P + 1, MaxInt)));
      if Tok <> '' then
        Names.Add(Tok);
    end;
  finally
    Lines.Free;
  end;
end;

procedure TScanner.MatchDeviceIndicators(const Serial: string; Res: TScanResult);
var
  SetIdx, j: Integer;
  St: TStix2Indicators;
  ProcSnap, PropVal, OutS: string;
  ProcNames: TStringList;
begin
  DoLog('Checking device-level indicators ...');
  ProcSnap := '';
  FAdb.Shell(Serial, 'ps -A', ProcSnap);
  if Trim(ProcSnap) = '' then
    FAdb.Shell(Serial, 'ps', ProcSnap);

  ProcNames := TStringList.Create;
  ProcNames.Sorted := True;
  ProcNames.Duplicates := dupIgnore;
  try
    CollectProcessNames(ProcSnap, ProcNames);

    for SetIdx := 0 to FStixSets.Count - 1 do begin
      St := TStix2Indicators(FStixSets[SetIdx]);

      for j := 0 to St.Properties.Count - 1 do begin
        PropVal := FAdb.GetProp(Serial, St.Properties[j]);
        if Trim(PropVal) <> '' then
          Res.Findings.Add(TFinding.Create('(device)', 'stix', sevCritical,
            'Known device property marker (' + St.Family + '): ' + St.Properties[j] + '=' + PropVal));
      end;

      for j := 0 to St.Paths.Count - 1 do begin
        if FAdb.Shell(Serial, 'test -e ' + St.Paths[j] + ' && echo exists', OutS) and
           (Pos('exists', OutS) > 0) then
          Res.Findings.Add(TFinding.Create('(device)', 'stix', sevCritical,
            'Known staging file exists (' + St.Family + '): ' + St.Paths[j]));
      end;

      // Process names are OS-specific; only match Android-family indicators.
      if St.IsAndroid then
        for j := 0 to St.Processes.Count - 1 do
          if ProcNames.IndexOf(LowerCase(St.Processes[j])) >= 0 then
            Res.Findings.Add(TFinding.Create('(device)', 'stix', sevCritical,
              'Known process running (' + St.Family + '): ' + St.Processes[j]));
    end;
  finally
    ProcNames.Free;
  end;
end;

function MatchFamilies(Db: TSignatureDB; App: TAppResult; Res: TScanResult): Integer;
var
  i: Integer;
  B: TSignatureBlock;
  Sev: TSeverity;
  Detail: string;
begin
  Result := 0;
  for i := 0 to High(Db.Blocks) do begin
    B := Db.Blocks[i];
    if BlockMatches(B, App) then begin
      App.MatchedFamilies.Add(B.Family);
      Inc(Result);
      if B.Severity = 'critical' then Sev := sevCritical
      else if B.Severity = 'high' then Sev := sevHigh
      else if B.Severity = 'medium' then Sev := sevMedium
      else if B.Severity = 'low' then Sev := sevLow
      else Sev := sevHigh;
      if B.Name <> '' then
        Detail := 'Matched IoC family "' + B.Family + '" (' + B.Name + ')'
      else
        Detail := 'Matched IoC family "' + B.Family + '"';
      Res.Findings.Add(TFinding.Create(App.PackageName, 'signature', Sev, Detail));
    end;
  end;
end;

function IsValidApk(const FileName: string): Boolean;
var
  F: TFileStream;
  Magic: array[0..1] of Byte;
begin
  Result := False;
  if not FileExists(FileName) then
    Exit;
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    if F.Size < 4 then
      Exit;
    F.Read(Magic, 2);
    // APKs are ZIP archives and always start with the 'PK' magic bytes.
    Result := (Magic[0] = $50) and (Magic[1] = $4B);
  finally
    F.Free;
  end;
end;

procedure TScanner.ScanApp(const Serial, Pkg, WorkDir: string; Res: TScanResult);
var
  RemotePath, LocalPath, Dump: string;
  Ana: TApkAnalysis;
  App: TAppResult;
begin
  DoLog('Scanning ' + Pkg + ' ...');
  if not FAdb.GetPackagePath(Serial, Pkg, RemotePath) then begin
    DoLog('  skip (no apk path): ' + Pkg);
    Exit;
  end;
  if not DirectoryExists(WorkDir) then
    ForceDirectories(WorkDir);
  LocalPath := IncludeTrailingPathDelimiter(WorkDir) +
               StringReplace(Pkg, '.', '_', [rfReplaceAll]) + '.apk';
  if not FAdb.Pull(Serial, RemotePath, LocalPath) then begin
    DoLog('  skip (pull failed): ' + Pkg);
    Exit;
  end;
  if not FileExists(LocalPath) then begin
    DoLog('  skip (apk missing locally): ' + Pkg);
    Exit;
  end;
  if not IsValidApk(LocalPath) then begin
    DoLog('  skip (invalid/corrupt apk): ' + Pkg);
    DeleteFile(LocalPath);
    Exit;
  end;
  Ana := AnalyzeApk(LocalPath, WorkDir, FConfig.ExtractStrings, FConfig.MinStringLen);
  try
    App := TAppResult.Create;
    App.PackageName := Ana.PackageName;
    if App.PackageName = '' then
      App.PackageName := Pkg;
    App.Sha256 := Ana.Sha256;
    App.Sha1 := Ana.Sha1;
    App.Md5 := Ana.Md5;
    App.CertSha256 := Ana.CertSha256;
    App.CertSha1 := Ana.CertSha1;
    App.Permissions.Assign(Ana.Permissions);
    App.Components.Assign(Ana.Components);
    App.Strings.Assign(Ana.Strings);
    App.Libraries.Assign(Ana.Libraries);
    App.Assets.Assign(Ana.Assets);
    App.FileNames.Assign(Ana.FileNames);
    App.HasManifest := Ana.HasManifest;
    App.HasLauncher := Ana.HasLauncher;
    if FAdb.DumpsysPackage(Serial, Pkg, Dump) then begin
      App.Signer := ExtractSigner(Dump);
      App.Installer := ExtractInstaller(Dump);
    end;
    MatchFamilies(FDb, App, Res);
    MatchStixIndicators(App, Res);
    ScoreApp(App);
    Res.Apps.Add(App);
    DoLog(Format('  %s score=%d severity=%s', [App.PackageName, App.Score, SeverityToString(App.Severity)]));
  finally
    Ana.Free;
  end;
end;

function TScanner.Scan(const Serial, WorkDir: string): TScanResult;
var
  Info: TDevice;
  Pkgs: TStringList;
  i: Integer;
begin
  Result := TScanResult.Create;
  Result.DeviceSerial := Serial;
  FAdb.DeviceInfo(Serial, Info);
  Result.DeviceModel := Info.Model;
  Result.AndroidVersion := Info.AndroidVersion;
  DoLog('Device: ' + Serial + ' (' + Info.Model + ', Android ' + Info.AndroidVersion + ')');
  Pkgs := FAdb.ListPackages(Serial, FConfig.SkipSystemPackages);
  try
    DoLog(Format('Found %d packages', [Pkgs.Count]));
    for i := 0 to Pkgs.Count - 1 do begin
      if (FConfig.MaxApkPull > 0) and (i >= FConfig.MaxApkPull) then begin
        DoLog('Reached MaxApkPull limit, stopping.');
        Break;
      end;
      try
        ScanApp(Serial, Pkgs[i], WorkDir, Result);
      except
        on E: EAbort do
          raise;
        on E: Exception do
          DoError('  error scanning ' + Pkgs[i] + ': ' + E.Message);
      end;
    end;
  finally
    Pkgs.Free;
  end;
  try
    MatchDeviceIndicators(Serial, Result);
  except
    on E: EAbort do
      raise;
    on E: Exception do
      DoError('device indicator scan failed: ' + E.Message);
  end;
  Result.Finished := Now;
end;

function TScanner.ScanOne(const Serial, Pkg, WorkDir: string): TScanResult;
var
  Info: TDevice;
begin
  Result := TScanResult.Create;
  Result.DeviceSerial := Serial;
  FAdb.DeviceInfo(Serial, Info);
  Result.DeviceModel := Info.Model;
  Result.AndroidVersion := Info.AndroidVersion;
  DoLog('Scanning single package: ' + Pkg);
  try
    ScanApp(Serial, Pkg, WorkDir, Result);
  except
    on E: EAbort do raise;
    on E: Exception do DoError('  error scanning ' + Pkg + ': ' + E.Message);
  end;
  try
    MatchDeviceIndicators(Serial, Result);
  except
    on E: EAbort do raise;
    on E: Exception do DoError('device indicator scan failed: ' + E.Message);
  end;
  Result.Finished := Now;
end;

function TScanner.ScanApkDirectory(const Dir, WorkDir: string): TScanResult;
var
  SR: TSearchRec;
  Ana: TApkAnalysis;
  App: TAppResult;
  ApkPath: string;
begin
  Result := TScanResult.Create;
  Result.DeviceSerial := '(demo)';
  if not DirectoryExists(WorkDir) then
    ForceDirectories(WorkDir);
  if FindFirst(IncludeTrailingPathDelimiter(Dir) + '*.apk', faAnyFile, SR) = 0 then begin
    repeat
      if (SR.Attr and faDirectory) = 0 then begin
        ApkPath := IncludeTrailingPathDelimiter(Dir) + SR.Name;
        DoLog('Analyzing ' + ApkPath + ' ...');
        try
          Ana := AnalyzeApk(ApkPath, WorkDir, FConfig.ExtractStrings, FConfig.MinStringLen);
          try
            App := TAppResult.Create;
            App.PackageName := Ana.PackageName;
            if App.PackageName = '' then
              App.PackageName := SR.Name;
            App.Sha256 := Ana.Sha256;
            App.Sha1 := Ana.Sha1;
            App.Md5 := Ana.Md5;
            App.CertSha256 := Ana.CertSha256;
            App.CertSha1 := Ana.CertSha1;
            App.Permissions.Assign(Ana.Permissions);
            App.Components.Assign(Ana.Components);
            App.Strings.Assign(Ana.Strings);
            App.Libraries.Assign(Ana.Libraries);
            App.Assets.Assign(Ana.Assets);
            App.FileNames.Assign(Ana.FileNames);
            App.HasManifest := Ana.HasManifest;
            App.HasLauncher := Ana.HasLauncher;
            MatchFamilies(FDb, App, Result);
            MatchStixIndicators(App, Result);
            ScoreApp(App);
            Result.Apps.Add(App);
            DoLog(Format('  %s score=%d severity=%s', [App.PackageName, App.Score, SeverityToString(App.Severity)]));
          finally
            Ana.Free;
          end;
        except
          on E: EAbort do
            raise;
          on E: Exception do
            DoError('  error analyzing ' + ApkPath + ': ' + E.Message);
        end;
      end;
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;
  Result.Finished := Now;
end;

end.



