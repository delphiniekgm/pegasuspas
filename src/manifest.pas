unit manifest;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TManifestInfo = class
  public
    PackageName: string;
    Debuggable: Boolean;
    Permissions: TStringList;
    Components: TStringList;   // "kind:name", e.g. "receiver:com.foo.Receiver"
    HasLauncher: Boolean;
    constructor Create;
    destructor Destroy; override;
    procedure AddPermission(const P: string);
    procedure AddComponent(const Kind, Name: string);
  end;

function ParseBinaryManifestFromFile(const FileName: string): TManifestInfo;
function ParseBinaryManifest(const Bytes: TBytes): TManifestInfo;

implementation

const
  AXML_STRING_POOL = $0001;
  AXML_XML        = $0003;
  AXML_START_ELEM = $0102;
  AXML_END_ELEM   = $0103;
  AXML_UTF8_FLAG  = $0100;

type
  TAxmlReader = class
  private
    Data: TBytes;
    Size: Integer;
    Pos: Integer;
    Strings: TStringList;
    UTF8: Boolean;
    function ReadU8: Byte;
    function ReadU16: Word;
    function ReadU32: Cardinal;
    function ReadU16At(P: Integer): Word;
    function GetString(Index: Integer): string;
    procedure ParseStringPool(ChunkStart: Integer; ChunkSize: Cardinal);
  public
    constructor Create(const Bytes: TBytes);
    destructor Destroy; override;
  end;

procedure AppendUtf8(var S: string; Cp: Cardinal);
begin
  if Cp < $80 then
    S := S + Chr(Cp)
  else if Cp < $800 then begin
    S := S + Chr($C0 or (Cp shr 6));
    S := S + Chr($80 or (Cp and $3F));
  end
  else if Cp < $10000 then begin
    S := S + Chr($E0 or (Cp shr 12));
    S := S + Chr($80 or ((Cp shr 6) and $3F));
    S := S + Chr($80 or (Cp and $3F));
  end
  else begin
    S := S + Chr($F0 or (Cp shr 18));
    S := S + Chr($80 or ((Cp shr 12) and $3F));
    S := S + Chr($80 or ((Cp shr 6) and $3F));
    S := S + Chr($80 or (Cp and $3F));
  end;
end;

constructor TAxmlReader.Create(const Bytes: TBytes);
begin
  inherited Create;
  Data := Bytes;
  Size := Length(Bytes);
  Pos := 0;
  UTF8 := False;
  Strings := TStringList.Create;
end;

destructor TAxmlReader.Destroy;
begin
  Strings.Free;
  inherited Destroy;
end;

function TAxmlReader.ReadU8: Byte;
begin
  if Pos < Size then begin
    Result := Data[Pos];
    Inc(Pos);
  end
  else
    Result := 0;
end;

function TAxmlReader.ReadU16: Word;
begin
  if Pos + 1 < Size then begin
    Result := Word(Data[Pos]) or (Word(Data[Pos + 1]) shl 8);
    Inc(Pos, 2);
  end
  else begin
    Result := 0;
    Inc(Pos);
  end;
end;

function TAxmlReader.ReadU16At(P: Integer): Word;
begin
  if (P >= 0) and (P + 1 < Size) then
    Result := Word(Data[P]) or (Word(Data[P + 1]) shl 8)
  else
    Result := 0;
end;

function TAxmlReader.ReadU32: Cardinal;
begin
  if Pos + 3 < Size then begin
    Result := Cardinal(Data[Pos]) or (Cardinal(Data[Pos + 1]) shl 8) or
              (Cardinal(Data[Pos + 2]) shl 16) or (Cardinal(Data[Pos + 3]) shl 24);
    Inc(Pos, 4);
  end
  else begin
    Result := 0;
    Inc(Pos);
  end;
end;

function TAxmlReader.GetString(Index: Integer): string;
begin
  if (Index >= 0) and (Index < Strings.Count) then
    Result := Strings[Index]
  else
    Result := '';
end;

procedure TAxmlReader.ParseStringPool(ChunkStart: Integer; ChunkSize: Cardinal);
var
  StringCount, StyleCount, Flags, StringsStart: Cardinal;
  Offsets: array of Cardinal;
  i, P, StrLen: Integer;
  Cu, Cu2: Cardinal;
  S: string;
begin
  StringCount := ReadU32;
  StyleCount := ReadU32;
  Flags := ReadU32;
  StringsStart := ReadU32;
  ReadU32; // stylesStart (unused)
  UTF8 := (Flags and AXML_UTF8_FLAG) <> 0;
  SetLength(Offsets, StringCount);
  for i := 0 to StringCount - 1 do
    Offsets[i] := ReadU32;
  for i := 0 to StringCount - 1 do begin
    P := ChunkStart + Integer(StringsStart) + Integer(Offsets[i]);
    S := '';
    if UTF8 then begin
      if (P >= 0) and (P < Size) then begin
        StrLen := Data[P];
        Inc(P);
        if (StrLen and $80) <> 0 then begin
          StrLen := ((StrLen and $7F) shl 8) or Data[P];
          Inc(P);
        end;
        if StrLen > 0 then begin
          SetLength(S, StrLen);
          Move(Data[P], S[1], StrLen);
        end;
      end;
    end
    else begin
      StrLen := ReadU16At(P);
      Inc(P, 2);
      if (StrLen and $8000) <> 0 then begin
        StrLen := ((StrLen and $7FFF) shl 16) or ReadU16At(P);
        Inc(P, 2);
      end;
      Cu := 0;
      while Cu < StrLen do begin
        Cu2 := ReadU16At(P + Cu * 2);
        if (Cu2 >= $D800) and (Cu2 <= $DBFF) and (Cu + 1 < StrLen) then begin
          Cu2 := ((Cu2 - $D800) shl 10) + (ReadU16At(P + (Cu + 1) * 2) - $DC00) + $10000;
          Inc(Cu, 2);
        end
        else
          Inc(Cu);
        AppendUtf8(S, Cu2);
      end;
    end;
    Strings.Add(S);
  end;
end;

function ParseBinaryManifest(const Bytes: TBytes): TManifestInfo;
var
  R: TAxmlReader;
  ChunkType, HeaderSize: Word;
  ChunkSize: Cardinal;
  ChunkStart, Tmp: Integer;
  Ns, Name: Cardinal;
  AttrCount: Word;
  AttrNs, AttrName, AttrRawValue: Cardinal;
  ElemName, AttrNameStr, AttrValueStr: string;
  a: Integer;
  CurAct: string;
  InActivity, InFilter, SawMain, SawLaunch: Boolean;

  procedure FinalizeActivity;
  begin
    if InActivity and (CurAct <> '') and SawMain and SawLaunch then
      Result.HasLauncher := True;
    InActivity := False;
    InFilter := False;
    SawMain := False;
    SawLaunch := False;
    CurAct := '';
  end;

begin
  Result := TManifestInfo.Create;
  R := TAxmlReader.Create(Bytes);
  CurAct := '';
  InActivity := False;
  InFilter := False;
  SawMain := False;
  SawLaunch := False;
  try
    while R.Pos < R.Size do begin
      ChunkStart := R.Pos;
      ChunkType := R.ReadU16;
      HeaderSize := R.ReadU16;
      ChunkSize := R.ReadU32;
      case ChunkType of
        AXML_STRING_POOL:
          R.ParseStringPool(ChunkStart, ChunkSize);
        AXML_START_ELEM: begin
          R.ReadU32; // lineNumber
          R.ReadU32; // comment
          Ns := R.ReadU32;
          Name := R.ReadU32;
          ElemName := R.GetString(Name);
          if (ElemName = 'activity') or (ElemName = 'activity-alias') then begin
            FinalizeActivity;
            InActivity := True;
          end
          else if ElemName = 'intent-filter' then begin
            if InActivity then
              InFilter := True;
          end;
          R.ReadU16; // attributeStart
          R.ReadU16; // attributeSize
          AttrCount := R.ReadU16;
          R.ReadU16; R.ReadU16; R.ReadU16; // idIndex, classIndex, styleIndex
          for a := 0 to AttrCount - 1 do begin
            AttrNs := R.ReadU32;
            AttrName := R.ReadU32;
            AttrRawValue := R.ReadU32;
            R.ReadU16; R.ReadU8; R.ReadU8; R.ReadU32; // typed value (size,res0,type,data)
            AttrNameStr := R.GetString(AttrName);
            AttrValueStr := R.GetString(AttrRawValue);
            if ElemName = 'manifest' then begin
              if AttrNameStr = 'package' then
                Result.PackageName := AttrValueStr;
            end
            else if ElemName = 'application' then begin
              if (AttrNameStr = 'debuggable') and (AttrValueStr = 'true') then
                Result.Debuggable := True;
            end
            else if ElemName = 'uses-permission' then begin
              if AttrNameStr = 'name' then
                Result.AddPermission(AttrValueStr);
            end
            else if (ElemName = 'activity') or (ElemName = 'activity-alias') or
                    (ElemName = 'service') or (ElemName = 'receiver') or
                    (ElemName = 'provider') then begin
              if AttrNameStr = 'name' then begin
                Result.AddComponent(ElemName, AttrValueStr);
                if (ElemName = 'activity') or (ElemName = 'activity-alias') then
                  CurAct := AttrValueStr;
              end;
            end
            else if (ElemName = 'action') and InFilter then begin
              if (AttrNameStr = 'name') and
                 (AttrValueStr = 'android.intent.action.MAIN') then
                SawMain := True;
            end
            else if (ElemName = 'category') and InFilter then begin
              if (AttrNameStr = 'name') and
                 (AttrValueStr = 'android.intent.category.LAUNCHER') then
                SawLaunch := True;
            end;
          end;
        end;
        AXML_END_ELEM: begin
          R.ReadU32; // lineNumber
          R.ReadU32; // comment
          R.ReadU32; // ns
          Name := R.ReadU32;
          ElemName := R.GetString(Name);
          if (ElemName = 'activity') or (ElemName = 'activity-alias') then
            FinalizeActivity;
        end;
      end;
      if ChunkType = AXML_XML then
        Tmp := ChunkStart + Integer(HeaderSize)
      else
        Tmp := ChunkStart + Integer(ChunkSize);
      if (Tmp >= R.Pos) and (Tmp <= R.Size) then
        R.Pos := Tmp
      else
        Break;
    end;
    FinalizeActivity;
  finally
    R.Free;
  end;
end;

function ParseBinaryManifestFromFile(const FileName: string): TManifestInfo;
var
  F: TFileStream;
  B: TBytes;
begin
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    SetLength(B, F.Size);
    if F.Size > 0 then
      F.Read(B[0], F.Size);
  finally
    F.Free;
  end;
  Result := ParseBinaryManifest(B);
end;

constructor TManifestInfo.Create;
begin
  inherited Create;
  PackageName := '';
  Debuggable := False;
  HasLauncher := False;
  Permissions := TStringList.Create;
  Permissions.Sorted := True;
  Permissions.Duplicates := dupIgnore;
  Components := TStringList.Create;
  Components.Sorted := True;
  Components.Duplicates := dupIgnore;
end;

destructor TManifestInfo.Destroy;
begin
  Permissions.Free;
  Components.Free;
  inherited Destroy;
end;

procedure TManifestInfo.AddPermission(const P: string);
begin
  if P <> '' then
    Permissions.Add(P);
end;

procedure TManifestInfo.AddComponent(const Kind, Name: string);
begin
  if Name <> '' then
    Components.Add(Kind + ':' + Name);
end;

end.

