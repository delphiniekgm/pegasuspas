unit hashes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, md5, sha1;

function SHA256String(const S: string): string;
function SHA256File(const FileName: string): string;
function SHA256BytesHex(const B; Len: SizeInt): string;
function MD5HexFile(const FileName: string): string;
function SHA1HexFile(const FileName: string): string;
function SHA1HexData(const B; Len: SizeInt): string;

implementation

type
  TSha256State = record
    H: array[0..7] of Cardinal;
    Len: QWord;
    Buf: array[0..63] of Byte;
    BufLen: Integer;
  end;

const
  SHA256_K: array[0..63] of Cardinal = (
    $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
    $d807aa98, $12835b01, $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
    $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc, $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
    $983e5152, $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147, $06ca6351, $14292967,
    $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
    $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819, $d6990624, $f40e3585, $106aa070,
    $19a4c116, $1e376c08, $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
    $748f82ee, $78a5636f, $84c87814, $8cc70208, $90befffa, $a4506ceb, $bef9a3f7, $c67178f2
  );

function ROR32(X: Cardinal; N: Byte): Cardinal; inline;
begin
  Result := (X shr N) or (X shl (32 - N));
end;

procedure Sha256Init(var S: TSha256State);
begin
  S.H[0] := $6a09e667; S.H[1] := $bb67ae85; S.H[2] := $3c6ef372; S.H[3] := $a54ff53a;
  S.H[4] := $510e527f; S.H[5] := $9b05688c; S.H[6] := $1f83d9ab; S.H[7] := $5be0cd19;
  S.Len := 0;
  S.BufLen := 0;
  FillChar(S.Buf, SizeOf(S.Buf), 0);
end;

procedure Sha256Transform(var S: TSha256State; const Block: array of Byte);
var
  W: array[0..63] of Cardinal;
  A, B, C, D, E, F, G, H: Cardinal;
  T1, T2: Cardinal;
  i: Integer;
begin
  for i := 0 to 15 do
    W[i] := (Cardinal(Block[i * 4]) shl 24) or (Cardinal(Block[i * 4 + 1]) shl 16) or
            (Cardinal(Block[i * 4 + 2]) shl 8) or Cardinal(Block[i * 4 + 3]);
  for i := 16 to 63 do
    W[i] := (ROR32(W[i - 15], 7) xor ROR32(W[i - 15], 18) xor (W[i - 15] shr 3)) +
            W[i - 16] +
            (ROR32(W[i - 2], 17) xor ROR32(W[i - 2], 19) xor (W[i - 2] shr 10)) +
            W[i - 7];
  A := S.H[0]; B := S.H[1]; C := S.H[2]; D := S.H[3];
  E := S.H[4]; F := S.H[5]; G := S.H[6]; H := S.H[7];
  for i := 0 to 63 do begin
    T1 := H + (ROR32(E, 6) xor ROR32(E, 11) xor ROR32(E, 25)) +
          ((E and F) xor ((not E) and G)) + SHA256_K[i] + W[i];
    T2 := (ROR32(A, 2) xor ROR32(A, 13) xor ROR32(A, 22)) +
          ((A and B) xor (A and C) xor (B and C));
    H := G; G := F; F := E; E := D + T1;
    D := C; C := B; B := A; A := T1 + T2;
  end;
  S.H[0] := S.H[0] + A; S.H[1] := S.H[1] + B; S.H[2] := S.H[2] + C; S.H[3] := S.H[3] + D;
  S.H[4] := S.H[4] + E; S.H[5] := S.H[5] + F; S.H[6] := S.H[6] + G; S.H[7] := S.H[7] + H;
end;

procedure Sha256Update(var S: TSha256State; const Data: Pointer; Len: SizeInt);
var
  P: PByte;
  N: SizeInt;
begin
  P := PByte(Data);
  while Len > 0 do begin
    N := 64 - S.BufLen;
    if N > Len then
      N := Len;
    Move(P^, S.Buf[S.BufLen], N);
    Inc(S.BufLen, N);
    Inc(P, N);
    Dec(Len, N);
    Inc(S.Len, N);
    if S.BufLen = 64 then begin
      Sha256Transform(S, S.Buf);
      S.BufLen := 0;
    end;
  end;
end;

procedure Sha256Final(var S: TSha256State; out Digest: array of Byte);
var
  i: Integer;
  BitLen: QWord;
begin
  BitLen := S.Len * 8;
  S.Buf[S.BufLen] := $80;
  Inc(S.BufLen);
  if S.BufLen > 56 then begin
    while S.BufLen < 64 do begin
      S.Buf[S.BufLen] := 0;
      Inc(S.BufLen);
    end;
    Sha256Transform(S, S.Buf);
    S.BufLen := 0;
  end;
  while S.BufLen < 56 do begin
    S.Buf[S.BufLen] := 0;
    Inc(S.BufLen);
  end;
  for i := 0 to 7 do
    S.Buf[56 + i] := Byte((BitLen shr ((7 - i) * 8)) and $FF);
  Sha256Transform(S, S.Buf);
  for i := 0 to 7 do begin
    Digest[i * 4]     := Byte((S.H[i] shr 24) and $FF);
    Digest[i * 4 + 1] := Byte((S.H[i] shr 16) and $FF);
    Digest[i * 4 + 2] := Byte((S.H[i] shr 8) and $FF);
    Digest[i * 4 + 3] := Byte(S.H[i] and $FF);
  end;
end;

function DigestToHex(const Digest: array of Byte): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to High(Digest) do
    Result := Result + LowerCase(HexStr(Digest[i], 2));
end;

function SHA256Bytes(const B; Len: SizeInt): string;
var
  S: TSha256State;
  D: array[0..31] of Byte;
begin
  Sha256Init(S);
  Sha256Update(S, @B, Len);
  Sha256Final(S, D);
  Result := DigestToHex(D);
end;

function SHA256String(const S: string): string;
begin
  if S = '' then
    Result := SHA256Bytes(S, 0)
  else
    Result := SHA256Bytes(S[1], Length(S));
end;

function SHA256File(const FileName: string): string;
var
  S: TSha256State;
  F: TFileStream;
  Buf: array[0..65535] of Byte;
  N: Integer;
  D: array[0..31] of Byte;
begin
  Sha256Init(S);
  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    repeat
      N := F.Read(Buf, SizeOf(Buf));
      if N > 0 then
        Sha256Update(S, @Buf[0], N);
    until N <= 0;
  finally
    F.Free;
  end;
  Sha256Final(S, D);
  Result := DigestToHex(D);
end;

function MD5HexFile(const FileName: string): string;
begin
  Result := LowerCase(MD5Print(MD5File(FileName)));
end;

function SHA256BytesHex(const B; Len: SizeInt): string;
begin
  Result := SHA256Bytes(B, Len);
end;

function SHA1HexFile(const FileName: string): string;
begin
  Result := LowerCase(SHA1Print(SHA1File(FileName)));
end;

function SHA1HexData(const B; Len: SizeInt): string;
begin
  Result := LowerCase(SHA1Print(SHA1Buffer(B, Len)));
end;

end.
