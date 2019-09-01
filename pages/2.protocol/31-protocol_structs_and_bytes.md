---
title: データ構造とバイト列の変換
tags: [protocol]
sidebar: doc_sidebar
permalink: protocol_structs_and_bytes.html
---

Pythonではデータ構造としてメッセージを保存し、ソケット通信で送るときはデータ構造をバイト列に変換します。
このセクションでは、基本的な型のデータ構造とバイト列の変換について説明します。

## Uint型 (数値)

一般的には uint は unsinged int の略ですが、RFC 8446 では次のように型が定義されています。

| 型 | C言語の型 | サイズ |
|---|---|---|
| uint8  | unsinged char  | 1 |
| uint16 | unsinged short | 2 |
| uint24 |                | 3 |
| uint32 | unsinged int   | 4 |

そこで、Uint8, Uint16, Uint24, Uint32 のクラスを作ります。
共通する処理が出てくると思うので、Uint という抽象クラスも作ります。
Uintの実装では次の機能を実装します。

- Uint型をバイト列に変換する処理 `.__bytes__()`
- バイト列からUint型を復元する処理 `.from_bytes()`

作成したUintN型の期待する動作例を以下に示します。

```python
num = Uint16(0x1234)
num_byte = b'\x12\x34'
assert bytes(num) == num_byte
assert num == Uint16.from_bytes(num_byte)
```

## Opaque型 (バイト列)

RFC で使われる opaque はバイト列を格納する型です。
opaque には固定長と可変長があります。

```
opaque string[16];        /* stringは16byte固定 */
opaque string<0..2^4-1>;  /* stringは0〜15byte */
opaque stirng<0..2^8-1>;  /* stringは0〜255byte */
opaque stirng<0..2^16-1>; /* stringは0〜65535byte */
opaque stirng<0..2^32-1>; /* stringは0〜4294967295byte */
```

固定長のopaqueはサイズが固定なので、バイト列だけが格納されています。
可変長のopaqueはサイズが可変なので、バイト列の長さを表す部分と、バイト列が格納されている部分から構成されています。

- `opaque[16]` : データ(16byte)
- `opaque<0..2^4-1>` : データ長を表す部分(1byte) + データ(Nbyte)
- `opaque<0..2^8-1>` : データ長を表す部分(2byte) + データ(Nbyte)
- `opaque<0..2^16-1>` : データ長を表す部分(3byte) + データ(Nbyte)
- `opaque<0..2^32-1>` : データ長を表す部分(4byte) + データ(Nbyte)

そこで、固定長の OpaqueFix と可変長の OpaqueVar という2つのクラスを作ります。

- OpaqueFix クラスは固定長のバイト列を格納するので、引数でサイズ(整数)を受け取る。
- OpaqueVar クラスは可変長のバイト列を格納するので、引数でデータ長を表す部分のサイズ(UintN)を受け取る。

それぞれのOpaqueの実装では次の機能を実装します。

- Opaque型をバイト列に変換する処理 `.__bytes__()`
- バイト列からOpaque型を復元する処理 `.from_bytes()`

作成したOpaque型の期待する動作例を以下に示します。

```python
# 固定長の場合
Opaque4 = OpaqueFix(4)
nonce = Opaque4(b'\xaa\xaa\xaa\xaa')
nonce_byte = b'\xaa\xaa\xaa\xaa'
assert bytes(nonce) == nonce_byte
assert nonce == Opaque4.from_bytes(nonce)

# 可変長の場合
OpaqueUint8 = OpaqueVar(Uint8)
session_id = OpaqueUint8(b'\xbb\xbb\xbb\xbb')
session_id_byte = b'\x04\xbb\xbb\xbb\xbb'
assert bytes(session_id) == session_id_byte
assert session_id == OpaqueUint8.from_bytes(session_id_byte)
```


## List型 (ベクタ型, 配列)

ベクタ型には2種類あります。要素が固定長のものと、要素が可変長のものです。
要素が固定長の場合は比較的実装が楽なのですが、要素が可変長の場合は今のままでは大変ですので、今まで実装してきたUint型とOpaque型について少し変更を加えます。

### .from_bytes → .from_fs

今まではバイト列から型を復元していましたが、ここではストリームから型を復元するように変更します。
ストリームとはバイトシーケンスへの読み書きを提供するものです。
例えばストリームに対して .read(2) をすると最初の2バイトを読みます。再び .read(2) をすると、1回目で読み取った場所の最後の一から2バイト読みます。
簡単なプログラムを書くと以下のようになります。

```python
import io
f = io.BytesIO(b'abcdefg')
f.read(2) # => b'ab'
f.read(2) # => b'cd'
f.read(3) # => b'efg'
```

次に、Uint型とOpaque型もストリーム型から型を復元するように関数を変更します。
期待する動作は以下の通りです。

```python
import io

# Uint型
f = io.BytesIO(b'\x11\x22\x33\x44')
value1 = Uint8.from_fs(f)  # => Uint8(0x11)
value2 = Uint16.from_fs(f) # => Uint16(0x2233)

# Opaque型
f = io.BytesIO(b'\x02\xaa\xaa\x03\xbb\xbb\xbb')
value1 = OpaqueUint8(f)  #=> Opaque<Uint8>(b'\xaa\xaa')
value2 = OpaqueUint8(f)  #=> Opaque<Uint8>(b'\xbb\xbb\xbb')
```

また、今までの .from_bytes も使えるようにするために、全ての型の親クラスとして `Type` クラスを作り、ここで .from_bytes が呼ばれたら引数のバイト列をストリームに変換して .from_fs を呼び出すようにしておきます。なぜこうするかというと、バイト列から型を復元できるのテストをするときに便利だからです。

```python
class Type:
    @classmethod
    def from_bytes(cls, data):
        return cls.from_fs(io.BytesIO(data))

class Uint(Type):
    ...

class Opaque(Type):
    ...
```

### List型の実装

.from_fs ができた上でList型を実装していきます。
List型とは「Listの長さを表す部分」と「Listの各要素の部分」から構成されています。
よって、型をバイト列に変換するときは、OpaqueVar型と同じようにList型の各要素のバイト列の長さをUint型で表したものをバイト列の先頭に付け加えます。
逆にバイト列からList型を復元するときは、先頭にある長さを読み取ってから、その長さの分だけ要素の型で .from_fs を繰り返すだけです。
簡単なプログラム例として、List型のサイズを表す型を `size_t`、 List型の要素の型を `elem_t` とすると以下のように書くことができます。

```python
def from_fs(fs):
    ...
    list_size = int(size_t.from_fs(fs)) # リスト全体の長さ
    array = []
    # 現在のストリーム位置が全体の長さを超えない間、繰り返し行う
    startpos = fs.tell()
    while (fs.tell() - startpos) < list_size:
        elem = elem_t.from_fs(fs, parent)
        array.append(elem)
    ...
```

作成したList型の期待する動作例を以下に示します。

```python
OpaqueUint8 = OpaqueVar(Uint8)
OpaqueUint8s = List(size_t=Uint8, elem_t=OpaqueUint8)
sample = OpaqueUint8s([
    OpaqueUint8(0xaa),
    OpaqueUint8(0xbbbb),
])
sample_byte = b'\x05\x01\xaa\x02\xbb\xbb'
assert bytes(sample) == sample_byte
assert sample == OpaqueUint8s.from_bytes(sample_byte)
```

### Enum型

Enum型(列挙型)は、TLSバージョンや暗号スイートを表すために使われます。
作成したEnum型の期待する動作例を以下に示します。

```python
class ContentType(Enum):
    elem_t = Uint8

    alert = Uint8(0x15)
    handshake = Uint8(0x16)
    application_data = Uint8(0x17)

assert ContentType.handshake == Uint8(0x16)

assert bytes(ContentType.handshake) == b'\x16'
assert ContentType.handshake == ContentType.from_bytes(b'\x16')
```
