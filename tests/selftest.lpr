program selftest;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, hashes, signatures, stix2, apk;

var
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

  if FailCount = 0 then begin
    Writeln('All tests passed.');
    ExitCode := 0;
  end
  else begin
    Writeln(FailCount, ' test(s) failed.');
    ExitCode := 1;
  end;
end.
