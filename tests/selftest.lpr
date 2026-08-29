program selftest;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, hashes, signatures, stix2, apk, sms;

type
  TColVal = record
    Serial: Int64;
    Data: TBytes;
  end;

var
  GBuf: TBytes;
  GPos: Integer;
  FailCount: Integer;
  TmpFile: string;
  SL: TStringList;
  Db: TSignatureDB;
  St: TStix2Indicators;
  CertBlob, CertDer: TBytes;

procedure Check(const Name: string; const Cond: Boolean);
begin
  if Cond then
    Writeln('PASS: ', Name)
  else begin
    Writeln('FAIL: ', Name);
    Inc(FailCount);
  end;
end;

procedure GAppend(B: Byte);
begin
  if GPos >= Length(GBuf) then
    SetLength(GBuf, GPos * 2 + 64);
  GBuf[GPos] := B;
  Inc(GPos);
end;

procedure GAppendText(const S: string);
var
  i: Integer;
begin
  for i := 1 to Length(S) do
    GAppend(Ord(S[i]));
end;

procedure GAppendVarint(V: Int64);
var
  Tmp: array[0..8] of Byte;
  N, i: Integer;
begin
  N := 0;
  repeat
    Tmp[N] := Byte(V and $7F);
    V := V shr 7;
    Inc(N);
  until V = 0;
  for i := N - 1 downto 0 do begin
    if i = 0 then
      GAppend(Tmp[i])
    else
      GAppend(Tmp[i] or $80);
  end;
end;

procedure GAppendBe16(V: Integer);
begin
  GAppend((V shr 8) and $FF);
  GAppend(V and $FF);
end;

procedure GAppendBe32(Value: Int64);
begin
  GAppend((Value shr 24) and $FF);
  GAppend((Value shr 16) and $FF);
  GAppend((Value shr 8) and $FF);
  GAppend(Value and $FF);
end;

procedure GAppendPage(const P: TBytes);
var
  i: Integer;
begin
  for i := 0 to Length(P) - 1 do
    GAppend(P[i]);
end;

function VarintLen(V: Int64): Integer;
begin
  Result := 1;
  while V >= $80 do begin
    V := V shr 7;
    Inc(Result);
  end;
end;

procedure AppendVarintTo(var Buf: TBytes; var Off: Integer; V: Int64);
var
  Tmp: array[0..8] of Byte;
  N, i: Integer;
begin
  N := 0;
  repeat
    Tmp[N] := Byte(V and $7F);
    V := V shr 7;
    Inc(N);
  until V = 0;
  for i := N - 1 downto 0 do begin
    if i = 0 then
      Buf[Off] := Tmp[i]
    else
      Buf[Off] := Tmp[i] or $80;
    Inc(Off);
  end;
end;

function ColText(const S: string): TColVal;
var
  i: Integer;
begin
  Result.Serial := Int64(Length(S)) * 2 + 13;
  SetLength(Result.Data, Length(S));
  for i := 1 to Length(S) do
    Result.Data[i - 1] := Byte(S[i]);
end;

function ColInt(Value: Int64): TColVal;
var
  i: Integer;
begin
  Result.Serial := 6;
  SetLength(Result.Data, 8);
  for i := 7 downto 0 do begin
    Result.Data[i] := Byte(Value and $FF);
    Value := Value shr 8;
  end;
end;

function BuildRecordPayload(const Cols: array of TColVal): TBytes;
var
  i, HeaderSize, BodyLen, Off: Integer;
begin
  Result := nil;
  HeaderSize := 1;
  for i := 0 to High(Cols) do
    HeaderSize := HeaderSize + VarintLen(Cols[i].Serial);
  BodyLen := 0;
  for i := 0 to High(Cols) do
    BodyLen := BodyLen + Length(Cols[i].Data);
  SetLength(Result, HeaderSize + BodyLen);
  Off := 0;
  AppendVarintTo(Result, Off, HeaderSize);
  for i := 0 to High(Cols) do
    AppendVarintTo(Result, Off, Cols[i].Serial);
  for i := 0 to High(Cols) do begin
    if Length(Cols[i].Data) > 0 then
      Move(Cols[i].Data[0], Result[Off], Length(Cols[i].Data));
    Off := Off + Length(Cols[i].Data);
  end;
end;

function BuildLeafCell(RowId: Int64; Payload: TBytes): TBytes;
var
  Off: Integer;
begin
  Result := nil;
  SetLength(Result, VarintLen(Length(Payload)) + VarintLen(RowId) + Length(Payload));
  Off := 0;
  AppendVarintTo(Result, Off, Length(Payload));
  AppendVarintTo(Result, Off, RowId);
  if Length(Payload) > 0 then
    Move(Payload[0], Result[Off], Length(Payload));
end;

function BuildLeafPage(const Cells: array of TBytes; PageSize, HeaderOffset: Integer): TBytes;
var
  NumCells, i, ContentStart: Integer;
begin
  Result := nil;
  NumCells := Length(Cells);
  SetLength(Result, PageSize);
  FillChar(Result[0], PageSize, 0);
  Result[HeaderOffset] := $0D;
  Result[HeaderOffset + 3] := Byte((NumCells shr 8) and $FF);
  Result[HeaderOffset + 4] := Byte(NumCells and $FF);
  ContentStart := HeaderOffset + 8 + NumCells * 2;
  Result[HeaderOffset + 5] := Byte((ContentStart shr 8) and $FF);
  Result[HeaderOffset + 6] := Byte(ContentStart and $FF);
  for i := 0 to NumCells - 1 do begin
    Result[HeaderOffset + 8 + i * 2] := Byte((ContentStart shr 8) and $FF);
    Result[HeaderOffset + 8 + i * 2 + 1] := Byte(ContentStart and $FF);
    if Length(Cells[i]) > 0 then
      Move(Cells[i][0], Result[ContentStart], Length(Cells[i]));
    ContentStart := ContentStart + Length(Cells[i]);
  end;
end;

procedure BuildTestSmsDb(const FileName: string);
const
  PageSize = 512;
  PageCount = 2;
var
  SchemaSql: string;
  MasterPayload, MasterCell, MasterPage: TBytes;
  SmsPayload1, SmsPayload2, SmsCell1, SmsCell2, SmsPage: TBytes;
  F: TFileStream;
  i: Integer;
begin
  SchemaSql := 'CREATE TABLE sms (_id INTEGER,address TEXT,date INTEGER,type INTEGER,body TEXT)';

  GPos := 0;
  SetLength(GBuf, 4096);

  // 100-byte database header.
  GAppendText('SQLite format 3');
  GAppend(0);
  GAppendBe16(PageSize);
  GAppend(1);
  GAppend(1);
  GAppend(0);
  GAppend(64);
  GAppend(32);
  GAppend(32);
  GAppendBe32(1);              // change counter
  GAppendBe32(PageCount);      // db size in pages
  GAppendBe32(0);              // freelist trunk
  GAppendBe32(0);              // freelist count
  GAppendBe32(1);              // schema cookie
  GAppendBe32(1);              // schema format
  GAppendBe32(0);              // page cache size
  GAppendBe32(0);              // largest root page
  GAppendBe32(1);              // text encoding UTF-8
  GAppendBe32(0);              // user version
  GAppendBe32(0);              // incremental vacuum
  GAppendBe32(0);              // application id
  for i := 1 to 20 do GAppend(0); // reserved
  GAppendBe32(1);              // version-valid-for
  GAppendBe32(3037000);        // sqlite version number

  // sqlite_master row: type,name,tbl_name,rootpage,sql (root page 1).
  MasterPayload := BuildRecordPayload(
    [ColText('table'), ColText('sms'), ColText('sms'), ColInt(2), ColText(SchemaSql)]);
  MasterCell := BuildLeafCell(1, MasterPayload);
  MasterPage := BuildLeafPage([MasterCell], PageSize, 100);
  // Page 1 contains the 100-byte database header at its start, so copy the
  // header into the page and reassemble GBuf from the pages only.
  for i := 0 to 99 do
    MasterPage[i] := GBuf[i];
  GPos := 0;
  GAppendPage(MasterPage);

  // sms table rows (root page 2).
  SmsPayload1 := BuildRecordPayload(
    [ColInt(1), ColText('+1234567890'), ColInt(1700000000000), ColInt(1),
     ColText('Visit http://pegasus.example.com/payload now')]);
  SmsPayload2 := BuildRecordPayload(
    [ColInt(2), ColText('Google'), ColInt(1700000000001), ColInt(2),
     ColText('Hello, this is a normal message')]);
  SmsCell1 := BuildLeafCell(1, SmsPayload1);
  SmsCell2 := BuildLeafCell(2, SmsPayload2);
  SmsPage := BuildLeafPage([SmsCell1, SmsCell2], PageSize, 0);
  GAppendPage(SmsPage);

  F := TFileStream.Create(FileName, fmCreate);
  try
    F.Write(GBuf[0], GPos);
  finally
    F.Free;
  end;
end;

procedure RunSmsTests;
var
  Msgs: TList;
  M: TSmsMessage;
  St2: TStix2Indicators;
  Kind, Value, Fn: string;
begin
  // 1) adb "content query" single-line output.
  Msgs := ParseContentQuery(
    'Row: 0 address=+1234567890, date=1700000000000, type=1, body=Visit http://pegasus.example.com/payload now'#10 +
    'Row: 1 address=Google, date=1700000000001, type=2, body=Normal message');
  try
    Check('SMS content-query 2 rows', Msgs.Count = 2);
    if Msgs.Count = 2 then begin
      Check('SMS row0 address', TSmsMessage(Msgs[0]).Address = '+1234567890');
      Check('SMS row0 type', TSmsMessage(Msgs[0]).MsgType = '1');
      Check('SMS row0 body', TSmsMessage(Msgs[0]).Body =
        'Visit http://pegasus.example.com/payload now');
      Check('SMS row1 type', TSmsMessage(Msgs[1]).MsgType = '2');
    end;
  finally
    FreeSmsList(Msgs);
  end;

  // 2) mmssms.db (SQLite) parse.
  Fn := GetTempDir + 'selftest_mmssms.db';
  BuildTestSmsDb(Fn);
  Msgs := ParseMmssmsDb(Fn);
  try
    Check('SMS db 2 rows', Msgs.Count = 2);
    if Msgs.Count = 2 then begin
      M := TSmsMessage(Msgs[0]);
      Check('SMS db address', M.Address = '+1234567890');
      Check('SMS db type', M.MsgType = '1');
      Check('SMS db body host', Pos('pegasus.example.com', M.Body) > 0);
      Check('SMS db row1 type', TSmsMessage(Msgs[1]).MsgType = '2');
    end;
  finally
    FreeSmsList(Msgs);
  end;
  DeleteFile(Fn);

  // 3) message-body indicator matching.
  St2 := TStix2Indicators.Create;
  try
    St2.Domains.Add('pegasus.example.com');
    St2.Urls.Add('http://evil.example.org/c2');
    St2.Emails.Add('a@pegasus.example.com');
    St2.Ips.Add('1.2.3.4');
    Check('SMS match domain', MatchMessageBody('Visit pegasus.example.com now', St2, Kind, Value) and (Kind = 'domain'));
    Check('SMS match subdomain', MatchMessageBody('go to x.pegasus.example.com', St2, Kind, Value));
    Check('SMS match url', MatchMessageBody('see http://evil.example.org/c2 now', St2, Kind, Value) and (Kind = 'url'));
    Check('SMS match ip', MatchMessageBody('connect 1.2.3.4', St2, Kind, Value) and (Kind = 'ip'));
    Check('SMS match email', MatchMessageBody('mail a@pegasus.example.com', St2, Kind, Value) and (Kind = 'email'));
    Check('SMS no match', not MatchMessageBody('all clear here', St2, Kind, Value));
  finally
    St2.Free;
  end;
end;

begin
  FailCount := 0;

  Check('SHA256(empty)',
    SHA256String('') = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  Check('SHA256(abc)',
    SHA256String('abc') = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  TmpFile := GetTempDir + 'selftest_abc.bin';
  with TFileStream.Create(TmpFile, fmCreate) do try
    Write('abc'[1], 3);
  finally Free; end;
  Check('MD5(abc)', MD5HexFile(TmpFile) = '900150983cd24fb0d6963f7d28e17f72');
  Check('SHA1(abc)', SHA1HexFile(TmpFile) = 'a9993e364706816aba3e25717850c26c9cd0d89d');
  DeleteFile(TmpFile);

  Check('Wildcard a*bc', WildcardMatch('a*bc', 'axxbc'));
  Check('Wildcard negative', not WildcardMatch('a*bc', 'axxbd'));
  Check('Wildcard ?', WildcardMatch('com.foo.?ar', 'com.foo.bar'));
  Check('Wildcard package', WildcardMatch('com.skynet.*', 'com.skynet.bot'));

  Db := TSignatureDB.Create;
  try
    Db.LoadFile(GetTempDir + 'does_not_exist.txt');
    Check('DB empty load no crash', Db.Count = 0);
  finally
    Db.Free;
  end;

  TmpFile := GetTempDir + 'selftest_iocs.txt';
  SL := TStringList.Create;
  try
    SL.Add('family: TestFam');
    SL.Add('severity: high');
    SL.Add('package: com.test.*');
    SL.Add('string: abc');
    SL.SaveToFile(TmpFile);
  finally
    SL.Free;
  end;
  Db := TSignatureDB.Create;
  try
    Db.LoadFile(TmpFile);
    Check('DB 1 block', Db.Count = 1);
    Check('DB family name', (Db.Count = 1) and (Db.Blocks[0].Family = 'TestFam'));
    Check('DB 2 iocs', (Db.Count = 1) and (Length(Db.Blocks[0].Iocs) = 2));
  finally
    Db.Free;
  end;
  DeleteFile(TmpFile);

  // New rule keys: sha1 / cert_sha256 / lib / asset.
  TmpFile := GetTempDir + 'selftest_iocs2.txt';
  SL := TStringList.Create;
  try
    SL.Add('family: TestFam2');
    SL.Add('severity: high');
    SL.Add('sha1: a9993e364706816aba3e25717850c26c9cd0d89d');
    SL.Add('cert_sha256: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
    SL.Add('lib: libtest.so');
    SL.Add('asset: assets/config.bin');
    SL.SaveToFile(TmpFile);
  finally
    SL.Free;
  end;
  Db := TSignatureDB.Create;
  try
    Db.LoadFile(TmpFile);
    Check('DB new keys parse', (Db.Count = 1) and (Length(Db.Blocks[0].Iocs) = 4));
  finally
    Db.Free;
  end;
  DeleteFile(TmpFile);

  TmpFile := GetTempDir + 'selftest_iocs.stix2';
  SL := TStringList.Create;
  try
    SL.Add('{"type":"bundle","objects":[');
    SL.Add('{"type":"indicator","pattern":"[domain-name:value=''pegasus.example.com'']"},');
    SL.Add('{"type":"indicator","pattern":"[domain-name:value=''pegasus.example.com'']"},');
    SL.Add('{"type":"indicator","pattern":"[ipv4-addr:value=''1.2.3.4'']"},');
    SL.Add('{"type":"indicator","pattern":"[email-addr:value=''a@pegasus.example.com'']"}');
    SL.Add(']}');
    SL.SaveToFile(TmpFile);
  finally
    SL.Free;
  end;
  St := TStix2Indicators.Create;
  try
    St.LoadFile(TmpFile);
    Check('STIX2 domains deduped', St.Domains.Count = 1);
    Check('STIX2 domain value', (St.Domains.Count = 1) and
      (St.Domains[0] = 'pegasus.example.com'));
    Check('STIX2 ips', St.Ips.Count = 1);
    Check('STIX2 emails', St.Emails.Count = 1);
  finally
    St.Free;
  end;
  DeleteFile(TmpFile);

  // New STIX2 pattern types.
  TmpFile := GetTempDir + 'selftest_iocs2.stix2';
  SL := TStringList.Create;
  try
    SL.Add('{"type":"bundle","objects":[');
    SL.Add('{"type":"indicator","pattern":"[android-property:name=''sys.brand.note'']"},');
    SL.Add('{"type":"indicator","pattern":"[file:path=''/data/local/tmp/dropbox'']"},');
    SL.Add('{"type":"indicator","pattern":"[file:name=''roleaccountd.plist'']"},');
    SL.Add('{"type":"indicator","pattern":"[process:name=''fservernetd'']"},');
    SL.Add('{"type":"indicator","pattern":"[x509-certificate:hashes.''SHA-256'' = ''00112233'']"}');
    SL.Add(']}');
    SL.SaveToFile(TmpFile);
  finally
    SL.Free;
  end;
  St := TStix2Indicators.Create;
  try
    St.LoadFile(TmpFile);
    Check('STIX2 properties', St.Properties.Count = 1);
    Check('STIX2 paths', St.Paths.Count = 1);
    Check('STIX2 filenames', St.FileNames.Count = 1);
    Check('STIX2 processes', St.Processes.Count = 1);
    Check('STIX2 cert sha256', St.CertSha256.Count = 1);
  finally
    St.Free;
  end;
  DeleteFile(TmpFile);

  // Synthetic PKCS#7 SignedData -> ExtractSignerCertDer returns the cert SEQUENCE.
  SetLength(CertBlob, 25);
  CertBlob[0] := $30; CertBlob[1] := $17;
  CertBlob[2] := $06; CertBlob[3] := $01; CertBlob[4] := $00;
  CertBlob[5] := $A0; CertBlob[6] := $12;
  CertBlob[7] := $30; CertBlob[8] := $10;
  CertBlob[9] := $02; CertBlob[10] := $01; CertBlob[11] := $01;
  CertBlob[12] := $31; CertBlob[13] := $00;
  CertBlob[14] := $30; CertBlob[15] := $00;
  CertBlob[16] := $A0; CertBlob[17] := $05;
  CertBlob[18] := $30; CertBlob[19] := $03;
  CertBlob[20] := $02; CertBlob[21] := $01; CertBlob[22] := $05;
  CertBlob[23] := $31; CertBlob[24] := $00;
  CertDer := ExtractSignerCertDer(CertBlob);
  Check('Cert DER extraction', (Length(CertDer) = 5) and (CertDer[0] = $30) and
    (CertDer[1] = $03) and (CertDer[2] = $02) and (CertDer[3] = $01) and (CertDer[4] = $05));

  RunSmsTests;

  if FailCount = 0 then begin
    Writeln('All tests passed.');
    ExitCode := 0;
  end
  else begin
    Writeln(FailCount, ' test(s) failed.');
    ExitCode := 1;
  end;
end.
