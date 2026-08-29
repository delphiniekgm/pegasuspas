unit sms;

{$mode objfpc}{$H+}

// SMS message extraction and IoC matching.
// Two extraction paths:
//   * adb "content query --uri content://sms" text output (dependency-free).
//   * mmssms.db (SQLite) pulled from a rooted device, parsed by a minimal
//     built-in read-only SQLite reader (no external SQLite library).
// Matching reuses the STIX2 indicator lists already loaded by the scanner.

interface

uses
  Classes, SysUtils, stix2;

type
  TSmsMessage = class
  public
    Address: string;
    Body: string;
    DateMs: string;
    MsgType: string; // '1' = inbox, '2' = sent, ...
    constructor Create;
  end;

// Parse adb "content query --uri content://sms" output.
function ParseContentQuery(const Text: string): TList;

// Parse a pulled mmssms.db (SQLite) and return the sms table rows.
function ParseMmssmsDb(const FileName: string): TList;

procedure FreeSmsList(List: TList);

// Extract host-like tokens from arbitrary text (for domain matching).
procedure ExtractHostTokens(const S: string; Tokens: TStringList);

// Extract hosts from explicit http(s) URLs in the text.
procedure ExtractUrlHosts(const S: string; Tokens: TStringList);

// Match one message body against a STIX2 indicator set.
// Returns True and sets Kind/Value on the first match.
function MatchMessageBody(const Body: string; St: TStix2Indicators;
  out Kind: string; out Value: string): Boolean;

implementation

uses StrUtils;

constructor TSmsMessage.Create;
begin
  inherited Create;
  Address := '';
  Body := '';
  DateMs := '';
  MsgType := '';
end;

procedure FreeSmsList(List: TList);
var
  i: Integer;
begin
  if List = nil then
    Exit;
  for i := 0 to List.Count - 1 do
    TSmsMessage(List[i]).Free;
  List.Free;
end;

function ExtractCol(const Line, Key, NextKey: string): string;
var
  P, Q: Integer;
begin
  Result := '';
  P := Pos(Key, Line);
  if P = 0 then
    Exit;
  P := P + Length(Key);
  if NextKey = '' then
    Result := Trim(Copy(Line, P, MaxInt))
  else begin
    Q := PosEx(NextKey, Line, P);
    if Q = 0 then
      Result := Trim(Copy(Line, P, MaxInt))
    else
      Result := Trim(Copy(Line, P, Q - P));
  end;
end;

// Fill fields from a single-line "Row: N address=.., date=.., type=.., body=.."
// record. Body is assumed to be the last projected column.
procedure FillFromLine(const Line: string; M: TSmsMessage);
begin
  if Pos('address=', Line) > 0 then
    M.Address := ExtractCol(Line, 'address=', ', date=');
  if Pos('date=', Line) > 0 then
    M.DateMs := ExtractCol(Line, 'date=', ', type=');
  if Pos('type=', Line) > 0 then
    M.MsgType := ExtractCol(Line, 'type=', ', body=');
  if Pos('body=', Line) > 0 then
    M.Body := ExtractCol(Line, 'body=', '');
end;

// Fill fields from the multi-line "  key=value" content-query format.
procedure FillFromMultiline(const Line: string; M: TSmsMessage);
var
  S: string;
  P: Integer;
  Key, Val: string;
begin
  S := Line;
  P := 1;
  while (P <= Length(S)) and (S[P] in [' ', #9]) do
    Inc(P);
  S := Copy(S, P, MaxInt);
  P := Pos('=', S);
  if P = 0 then
    Exit;
  Key := Copy(S, 1, P - 1);
  Val := Copy(S, P + 1, MaxInt);
  if Key = 'address' then
    M.Address := Val
  else if Key = 'date' then
    M.DateMs := Val
  else if Key = 'type' then
    M.MsgType := Val
  else if Key = 'body' then begin
    if M.Body = '' then
      M.Body := Val
    else
      M.Body := M.Body + #10 + Val;
  end;
end;

function ParseContentQuery(const Text: string): TList;
var
  Lines: TStringList;
  i, P: Integer;
  Line, L: string;
  M: TSmsMessage;
  SingleLine: Boolean;
begin
  Result := TList.Create;
  Lines := TStringList.Create;
  try
    Lines.Text := Text;
    SingleLine := False;
    // Detect whether rows are single-line (comma separated) or multi-line.
    for i := 0 to Lines.Count - 1 do begin
      Line := Lines[i];
      if Pos('Row:', Line) = 1 then begin
        L := Trim(Copy(Line, 5, MaxInt));
        P := Pos(' ', L);
        if P > 0 then begin
          L := Trim(Copy(L, P + 1, MaxInt));
          SingleLine := Pos('=', L) > 0;
        end;
        Break;
      end;
    end;

    M := nil;
    for i := 0 to Lines.Count - 1 do begin
      Line := Lines[i];
      if Pos('Row:', Line) = 1 then begin
        M := TSmsMessage.Create;
        Result.Add(M);
        if SingleLine then
          FillFromLine(Line, M);
      end
      else if M <> nil then begin
        if SingleLine then begin
          if Trim(Line) <> '' then begin
            if M.Body = '' then
              M.Body := Trim(Line)
            else
              M.Body := M.Body + #10 + Trim(Line);
          end;
        end
        else
          FillFromMultiline(Line, M);
      end;
    end;
  finally
    Lines.Free;
  end;
end;

procedure ExtractHostTokens(const S: string; Tokens: TStringList);
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
          Tokens.Add(Tok);
      end;
      i := j;
    end
    else
      Inc(i);
  end;
end;

procedure ExtractUrlHosts(const S: string; Tokens: TStringList);
var
  P, Q, Start: Integer;
  Url, Host: string;
begin
  P := PosEx('://', S, 1);
  while P > 0 do begin
    Start := P - 1;
    while (Start >= 1) and (S[Start] in ['a'..'z', 'A'..'Z', '0'..'9', '+', '.', '-']) do
      Dec(Start);
    Inc(Start);
    Q := P + 3;
    while (Q <= Length(S)) and
          (S[Q] in ['a'..'z', 'A'..'Z', '0'..'9', '.', '-', '_', '/', '?', '&', '=', '%', ':', '[', ']', '#']) do
      Inc(Q);
    Url := Copy(S, Start, Q - Start);
    Host := ExtractHostFromUrl(Url);
    if Host <> '' then
      Tokens.Add(Host);
    P := PosEx('://', S, Q);
  end;
end;

function MatchMessageBody(const Body: string; St: TStix2Indicators;
  out Kind: string; out Value: string): Boolean;
var
  i, P: Integer;
  H: string;
  Low: string;
  Hosts: TStringList;
begin
  Result := False;
  Kind := '';
  Value := '';
  Low := LowerCase(Body);
  if Low = '' then
    Exit;

  for i := 0 to St.Urls.Count - 1 do
    if Pos(St.Urls[i], Low) > 0 then begin
      Kind := 'url';
      Value := St.Urls[i];
      Result := True;
      Exit;
    end;

  for i := 0 to St.Ips.Count - 1 do
    if Pos(St.Ips[i], Low) > 0 then begin
      Kind := 'ip';
      Value := St.Ips[i];
      Result := True;
      Exit;
    end;

  for i := 0 to St.Emails.Count - 1 do
    if Pos(St.Emails[i], Low) > 0 then begin
      Kind := 'email';
      Value := St.Emails[i];
      Result := True;
      Exit;
    end;

  Hosts := TStringList.Create;
  Hosts.Sorted := True;
  Hosts.Duplicates := dupIgnore;
  try
    ExtractHostTokens(Body, Hosts);
    ExtractUrlHosts(Body, Hosts);
    for i := 0 to Hosts.Count - 1 do begin
      H := Hosts[i];
      repeat
        if St.Domains.IndexOf(H) >= 0 then begin
          Kind := 'domain';
          Value := H;
          Result := True;
          Exit;
        end;
        P := Pos('.', H);
        if P = 0 then
          Break;
        H := Copy(H, P + 1, MaxInt);
      until False;
    end;
  finally
    Hosts.Free;
  end;
end;

// ---------------- Minimal read-only SQLite parser ----------------

function LoadFileBytes(const FileName: string): TBytes;
var
  F: TFileStream;
begin
  Result := nil;
  if not FileExists(FileName) then
    Exit;
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    SetLength(Result, F.Size);
    if F.Size > 0 then
      F.ReadBuffer(Result[0], F.Size);
  finally
    F.Free;
  end;
end;

function Be16(const B: TBytes; Off: Integer): Integer;
begin
  Result := (B[Off] shl 8) or B[Off + 1];
end;

function Be32(const B: TBytes; Off: Integer): Int64;
begin
  Result := (Int64(B[Off]) shl 24) or (Int64(B[Off + 1]) shl 16) or
            (Int64(B[Off + 2]) shl 8) or Int64(B[Off + 3]);
end;

function ReadVarint(const B: TBytes; var Off: Integer): Int64;
var
  Bv: Byte;
  Shift: Integer;
begin
  Result := 0;
  Shift := 0;
  repeat
    if Off >= Length(B) then
      Exit(0);
    Bv := B[Off];
    Inc(Off);
    Result := Result or ((Int64(Bv) and $7F) shl Shift);
    Shift := Shift + 7;
  until (Bv and $80) = 0;
end;

function ReadBigEndianInt(const B: TBytes; Off, Len: Integer): Int64;
var
  i: Integer;
begin
  Result := 0;
  for i := 0 to Len - 1 do
    Result := (Result shl 8) or B[Off + i];
end;

function BytesToStr(const B: TBytes; Off, Len: Integer): string;
begin
  if Len <= 0 then begin
    Result := '';
    Exit;
  end;
  SetLength(Result, Len);
  Move(B[Off], Result[1], Len);
end;

function IsSqliteHeader(const B: TBytes): Boolean;
const
  Magic: array[0..15] of Byte =
    (Ord('S'), Ord('Q'), Ord('L'), Ord('i'), Ord('t'), Ord('e'),
     Ord(' '), Ord('f'), Ord('o'), Ord('r'), Ord('m'), Ord('a'),
     Ord('t'), Ord(' '), Ord('3'), 0);
var
  i: Integer;
begin
  Result := Length(B) >= 16;
  if Result then
    for i := 0 to 15 do
      if B[i] <> Magic[i] then begin
        Result := False;
        Exit;
      end;
end;

function DecodeRecord(const Payload: TBytes): TStringList;
var
  Off, H, i, N: Integer;
  Ser: array of Int64;
  BodyOff: Integer;
  T: Int64;
begin
  Result := TStringList.Create;
  Off := 0;
  H := ReadVarint(Payload, Off);
  Ser := nil;
  while Off < H do begin
    SetLength(Ser, Length(Ser) + 1);
    Ser[High(Ser)] := ReadVarint(Payload, Off);
  end;
  BodyOff := Off;
  for i := 0 to High(Ser) do begin
    T := Ser[i];
    case T of
      0: Result.Add('');
      1..4: begin
        N := T;
        Result.Add(IntToStr(ReadBigEndianInt(Payload, BodyOff, N)));
        BodyOff := BodyOff + N;
      end;
      5: begin
        Result.Add(IntToStr(ReadBigEndianInt(Payload, BodyOff, 6)));
        BodyOff := BodyOff + 6;
      end;
      6: begin
        Result.Add(IntToStr(ReadBigEndianInt(Payload, BodyOff, 8)));
        BodyOff := BodyOff + 8;
      end;
      7: begin
        Result.Add(''); // IEEE float: skip
        BodyOff := BodyOff + 8;
      end;
      8: Result.Add('0');
      9: Result.Add('1');
      10, 11: ; // reserved, no body
    else
      if (T mod 2) = 0 then begin
        N := (T - 12) div 2; // blob
        Result.Add('');
        BodyOff := BodyOff + N;
      end
      else begin
        N := (T - 13) div 2; // text
        Result.Add(BytesToStr(Payload, BodyOff, N));
        BodyOff := BodyOff + N;
      end;
    end;
  end;
end;

function ReadCellPayload(const B: TBytes; PageSize, CellAbs: Integer;
  out RowId: Int64): TBytes;
var
  Off, Local, Usable, X, M, K, Remaining, Posn, Chunk, PageStart: Integer;
  PTotal: Int64;
  PageNum: Int64;
begin
  Result := nil;
  RowId := 0;
  Off := CellAbs;
  PTotal := ReadVarint(B, Off);
  RowId := ReadVarint(B, Off);
  if PTotal <= 0 then
    Exit;
  if PTotal > High(Integer) then
    Exit;
  Usable := PageSize;
  X := Usable - 35;
  if PTotal <= X then
    Local := PTotal
  else begin
    M := ((Usable - 12) * 32 div 255) - 23;
    K := M + ((PTotal - M) mod (Usable - 4));
    if K <= X then
      Local := K
    else
      Local := M;
  end;

  SetLength(Result, PTotal);
  if Local > 0 then
    Move(B[Off], Result[0], Local);

  Remaining := PTotal - Local;
  if Remaining > 0 then begin
    PageNum := Be32(B, Off + Local);
    Posn := Local;
    while (Remaining > 0) and (PageNum > 0) and (PageNum <= High(Integer)) do begin
      PageStart := (PageNum - 1) * PageSize;
      if PageStart + 4 > Length(B) then
        Break;
      PageNum := Be32(B, PageStart);
      Chunk := PageSize - 4;
      if Chunk > Remaining then
        Chunk := Remaining;
      if PageStart + 4 + Chunk > Length(B) then
        Break;
      Move(B[PageStart + 4], Result[Posn], Chunk);
      Posn := Posn + Chunk;
      Remaining := Remaining - Chunk;
    end;
  end;
end;

procedure CollectTableRows(const B: TBytes; PageNum, PageSize: Integer;
  Rows: TList);
var
  PageStart, Hdr, NumCells, i, Ptr, CellAbs, RightMost: Integer;
  PageType: Byte;
  Payload: TBytes;
  RowId: Int64;
  Row: TStringList;
begin
  if PageNum <= 0 then
    Exit;
  PageStart := (PageNum - 1) * PageSize;
  if PageStart < 0 then
    Exit;
  if PageNum = 1 then
    Hdr := 100
  else
    Hdr := 0;
  if PageStart + Hdr + 8 > Length(B) then
    Exit;
  PageType := B[PageStart + Hdr];
  NumCells := Be16(B, PageStart + Hdr + 3);
  if PageType = $0D then begin
    for i := 0 to NumCells - 1 do begin
      Ptr := Be16(B, PageStart + Hdr + 8 + i * 2);
      CellAbs := PageStart + Ptr;
      if CellAbs < 0 then
        Continue;
      Payload := ReadCellPayload(B, PageSize, CellAbs, RowId);
      Row := DecodeRecord(Payload);
      Rows.Add(Row);
    end;
  end
  else if PageType = $05 then begin
    RightMost := Be32(B, PageStart + Hdr + 8);
    for i := 0 to NumCells - 1 do begin
      Ptr := Be16(B, PageStart + Hdr + 12 + i * 2);
      CellAbs := PageStart + Ptr;
      if CellAbs < 0 then
        Continue;
      CollectTableRows(B, Be32(B, CellAbs), PageSize, Rows);
    end;
    if RightMost > 0 then
      CollectTableRows(B, RightMost, PageSize, Rows);
  end;
end;

procedure FreeRows(Rows: TList);
var
  i: Integer;
begin
  if Rows = nil then
    Exit;
  for i := 0 to Rows.Count - 1 do
    TStringList(Rows[i]).Free;
  Rows.Free;
end;

procedure SplitTopLevel(const S: string; OutList: TStringList);
var
  i, Start, Depth: Integer;
  InQuote: Char;
begin
  Depth := 0;
  InQuote := #0;
  Start := 1;
  for i := 1 to Length(S) do begin
    if InQuote <> #0 then begin
      if S[i] = InQuote then
        InQuote := #0;
    end
    else if S[i] = '''' then
      InQuote := ''''
    else if S[i] = '"' then
      InQuote := '"'
    else if S[i] = '(' then
      Inc(Depth)
    else if S[i] = ')' then
      Dec(Depth)
    else if (S[i] = ',') and (Depth = 0) then begin
      OutList.Add(Copy(S, Start, i - Start));
      Start := i + 1;
    end;
  end;
  OutList.Add(Copy(S, Start, Length(S) - Start + 1));
end;

function FirstToken(const S: string): string;
var
  i: Integer;
begin
  Result := '';
  i := 1;
  while (i <= Length(S)) and (S[i] in [' ', #9, #13, #10]) do
    Inc(i);
  while (i <= Length(S)) and (S[i] in ['a'..'z', 'A'..'Z', '0'..'9', '_', '$']) do begin
    Result := Result + S[i];
    Inc(i);
  end;
end;

function ParseCreateColumns(const Sql: string; out AddrIdx, DateIdx,
  TypeIdx, BodyIdx: Integer): Boolean;
var
  P, Q, i: Integer;
  Inside: string;
  Cols: TStringList;
  Name: string;
begin
  AddrIdx := -1;
  DateIdx := -1;
  TypeIdx := -1;
  BodyIdx := -1;
  Result := False;
  P := Pos('(', Sql);
  if P = 0 then
    Exit;
  Q := Length(Sql);
  while (Q >= P) and (Sql[Q] <> ')') do
    Dec(Q);
  if Q < P then
    Exit;
  Inside := Copy(Sql, P + 1, Q - P - 1);
  Cols := TStringList.Create;
  try
    SplitTopLevel(Inside, Cols);
    for i := 0 to Cols.Count - 1 do begin
      Name := FirstToken(Trim(Cols[i]));
      if Name = 'address' then
        AddrIdx := i
      else if Name = 'date' then
        DateIdx := i
      else if Name = 'type' then
        TypeIdx := i
      else if Name = 'body' then
        BodyIdx := i;
    end;
  finally
    Cols.Free;
  end;
  Result := (AddrIdx >= 0) and (DateIdx >= 0) and (TypeIdx >= 0) and (BodyIdx >= 0);
end;

function ParseMmssmsDb(const FileName: string): TList;
var
  B: TBytes;
  PageSize, RootPage, i: Integer;
  AddrIdx, DateIdx, TypeIdx, BodyIdx: Integer;
  Rows: TList;
  Row: TStringList;
  SqlText: string;
  M: TSmsMessage;
begin
  Result := TList.Create;
  B := LoadFileBytes(FileName);
  if not IsSqliteHeader(B) then
    Exit;
  PageSize := Be16(B, 16);
  if PageSize = 1 then
    PageSize := 65536;
  if PageSize < 512 then
    Exit;

  RootPage := -1;
  SqlText := '';
  Rows := TList.Create;
  try
    CollectTableRows(B, 1, PageSize, Rows); // sqlite_master
    for i := 0 to Rows.Count - 1 do begin
      Row := TStringList(Rows[i]);
      if (Row.Count > 4) and (Row[0] = 'table') and (Row[1] = 'sms') then begin
        RootPage := StrToInt64Def(Row[3], -1);
        SqlText := Row[4];
        Break;
      end;
    end;
  finally
    FreeRows(Rows);
  end;

  if (RootPage <= 0) or
     (not ParseCreateColumns(SqlText, AddrIdx, DateIdx, TypeIdx, BodyIdx)) then
    Exit;

  Rows := TList.Create;
  try
    CollectTableRows(B, RootPage, PageSize, Rows);
    for i := 0 to Rows.Count - 1 do begin
      Row := TStringList(Rows[i]);
      if Row.Count <= BodyIdx then
        Continue;
      M := TSmsMessage.Create;
      M.Address := Row[AddrIdx];
      M.DateMs := Row[DateIdx];
      M.MsgType := Row[TypeIdx];
      M.Body := Row[BodyIdx];
      Result.Add(M);
    end;
  finally
    FreeRows(Rows);
  end;
end;

end.





