---
title: データ構造とバイト列の変換
tags: [protocol]
sidebar: doc_sidebar
permalink: protocol_structs_and_bytes.html
---

Pythonではデータ構造としてメッセージを保存し、ソケット通信で送るときはデータ構造をバイト列に変換します。
このセクションでは、基本的な型のデータ構造とバイト列の変換について説明します。

## uint (数値)

一般的には uint は unsinged int の略ですが、RFC 8446 では次のように型が定義されています。

| 型 | C言語の型 | サイズ |
|---|---|---|
| uint8  | unsinged char  | 1 |
| uint16 | unsinged short | 2 |
| uint24 |                | 3 |
| uint32 | unsinged int   | 4 |

というわけで、Uint8, Uint16, Uint24, Uint32 のクラスを作ります。
さらに、抽象化するために Uint という抽象クラスも作ります。

ここの実装で重要な点は、以下の処理の部分です。

- Uint型とバイト列で相互変換ができる
  - `Uint16(0x0003)` <=> `b'\x00\x03'`
- bytes(UintNのインスタンス) : Uint型をバイト列に変換します (`bytes()`)
- UintN.from_bytes(バイト列) : バイト列からUint型を復元します (`from_bytes()`)

実際のプログラムを以下に示します。

```python
import abc # 抽象基底クラス
import struct # バイト列の解釈

# UintNの抽象クラス
class Uint(abc.ABC):
    def __init__(self, value):
        assert isinstance(value, int)
        max_value = 1 << (8 * self.__class__.size)
        assert 0 <= value < max_value
        self.value = value

    @abc.abstractmethod # 抽象メソッド
    def __bytes__(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod # 抽象メソッド
    def from_bytes(cls, data):
        raise NotImplementedError()

    def __len__(self):
        return self.__class__.size

    def __int__(self):
        return self.value

    def __eq__(self, other):
        return hasattr(other, 'value') and self.value == other.value

    def __repr__(self):
        classname = self.__class__.__name__
        value = self.value
        width = self.__class__.size * 2
        return "{}(0x{:0{width}x})".format(classname, value, width=width)


class Uint8(Uint):
    size = 1  # unsinged char

    def __bytes__(self):
        return struct.pack('>B', self.value)

    @classmethod
    def from_bytes(cls, data):
        return Uint8(struct.unpack('>B', data)[0])

class Uint16(Uint):
    size = 2  # unsigned short

    def __bytes__(self):
        return struct.pack('>H', self.value)

    @classmethod
    def from_bytes(cls, data):
        return Uint16(struct.unpack('>H', data)[0])

class Uint24(Uint):
    size = 3

    def __bytes__(self):
        return struct.pack('>BH', self.value >> 16, self.value & 0xffff)

    @classmethod
    def from_bytes(cls, data):
        high, low = struct.unpack('>BH', data)
        return Uint24((high << 16) + low)

class Uint32(Uint):
    size = 4  # unsigned int

    def __bytes__(self):
        return struct.pack('>I', self.value)

    @classmethod
    def from_bytes(cls, data):
        return Uint32(struct.unpack('>I', data)[0])
```

UintNが正しく動くことを確認するためにテストも書きます。
例えば Uint8(255) は成功しますが、Uint8(256) はオーバーフローするのでエラーを吐きます。
また、bytes() で変換したものを UintN.from_bytes() で復元すると元に戻ることも確認します。
これをテストに落とし込むと次のようになります。

```python
import unittest

class TestUint(unittest.TestCase):

    def test_uint8(self):
        u = Uint8(255)
        self.assertEqual(bytes(u), b'\xff')
        # 変換して復元したものが元に戻るか確認する
        self.assertEqual(Uint8.from_bytes(bytes(u)), u)

    def test_uint8_out_range(self):
        # 不正な値を入れたときにエラーになるか
        with self.assertRaises(AssertionError) as cm:
            u = Uint8(256)
        with self.assertRaises(AssertionError) as cm:
            u = Uint8(-1)

unittest.main()
```


## opaque (バイト列)

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

というわけで、固定長の OpaqueFix と可変長の OpaqueVar という2つのクラスを作ります。
さらに、これらをクラスはそれぞれサイズの情報をクラス定数として保持したいので、クラスの返す関数を作り、関数の中でクラスの定数としてサイズの情報を格納していきます。

ここの実装でやりたいことは、次のことです。

- OpaqueFix という固定長のバイト列を格納するクラスを作る。引数でサイズを受け取る。
- OpaqueVar という可変長のバイト列を格納するクラスを作る。引数でデータ長を表す部分のサイズを受け取る。
- OpaqueFix/OpaqueVar の構造体とバイト列は `bytes()` と `from_bytes()` で相互変換できる
  - `OpaqueFix(4)(b'\x01\x23\x45\x67')` <=> `b'\x01\x23\x45\x67'`
  - `OpaqueVar(Uint8)(b'\x01\x23\x45\x67')` <=> `b'\x04\x01\x23\x45\x67'`
- 関数 Opaque で、クラスの定数を格納した OpaqueFix/OpaqueVar クラスを返す (高階関数を作る)

実際のプログラムを以下に示します。

```python
def Opaque(size):

    # 固定長のOpaque (e.g. opaque string[16])
    class OpaqueFix:
        size = 0

        def __init__(self, byte):
            max_size = OpaqueFix.size
            assert isinstance(byte, (bytes, bytearray))
            assert len(byte) <= max_size
            self.byte = byte.rjust(max_size, b'\x00')

        def __bytes__(self):
            return self.byte

        @classmethod
        def from_bytes(cls, data):
            return OpaqueFix(data)

        def __eq__(self, other):
            return self.byte == other.byte

        def __len__(self):
            return len(self.byte)

    # 可変長のOpaque (e.g. opaque string<0..15>)
    class OpaqueVar:
        size = None
        size_t = Uint

        def __init__(self, byte):
            assert isinstance(byte, (bytes, bytearray))
            size_t = OpaqueVar.size_t
            self.byte = byte
            self.size_t = size_t

        def __bytes__(self):
            UintN = self.size_t
            return bytes(UintN(len(self.byte))) + self.byte

        @classmethod
        def from_bytes(cls, data):
            size_t = OpaqueVar.size_t
            f = io.BytesIO(data)
            length = size_t.from_bytes(f.read(size_t.size))
            byte   = f.read(int(length))
            return OpaqueVar(byte)

        def __eq__(self, other):
            return self.byte == other.byte and self.size_t == other.size_t

        def __len__(self):
            return len(self.byte)

    if isinstance(size, int): # 引数がintのときは固定長
        OpaqueFix.size = size
        return OpaqueFix
    if issubclass(size, Uint): # 引数がUintNのときは可変長
        OpaqueVar.size = None
        OpaqueVar.size_t = size
        return OpaqueVar
    raise TypeError("size's type must be an int or Uint class.")
```

次にテストをします。
OpaqueFixクラスのテストでは、最大N[byte]のときにM[byte]のバイト列を渡したときの振る舞いを確認すると共に、バイト列に変換して復元できるかの確認もします。
OpaqueVarクラスのテストでは、バイト列に変換したときに、データ長を表す部分が正しくバイト列に反映されているか確認します。

```python
class TestUint(unittest.TestCase):

    def test_opaque_fix(self):
        # 4byteのOpaqueに対して、4byteのバイト列を渡す
        Opaque4 = Opaque(4)
        o = Opaque4(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
        self.assertEqual(Opaque4.from_bytes(bytes(o)), o)

        # 8byteのOpaqueに対して、4byteのバイト列を渡す
        Opaque8 = Opaque(8)
        o = Opaque8(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x00\x00\x00\x00\x01\x23\x45\x67')
        self.assertEqual(Opaque8.from_bytes(bytes(o)), o)

    def test_opaque_fix_invalid_args(self):
        # 4byteのOpaqueに対して、5byteのバイト列を渡す
        Opaque4 = Opaque(4)
        with self.assertRaises(Exception) as cm:
            o = Opaque4(b'\x01\x23\x45\x67\x89')

    def test_opaque_var(self):
        # 可変長のOpaqueでデータ長を表す部分がUint8のとき
        OpaqueVar1 = Opaque(Uint8)
        o = OpaqueVar1(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x04\x01\x23\x45\x67')
        self.assertEqual(OpaqueVar1.from_bytes(bytes(o)), o)

        # 可変長のOpaqueでデータ長を表す部分がUint16のとき
        OpaqueVar2 = Opaque(Uint16)
        o = OpaqueVar2(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x00\x04\x01\x23\x45\x67')
        self.assertEqual(OpaqueVar2.from_bytes(bytes(o)), o)
```


## 配列

配列には2種類あります。要素が固定長の配列と、要素が可変長の配列です。

```python
def List(elem_t, size_t):

    class List:
        size = None
        size_t = Uint
        elem_t = None # Elements' Type

        def __init__(self, array):
            self.array = array

        def __bytes__(self):
            size_t = List.size_t
            buffer = bytearray(0)
            buffer += bytes(size_t(sum(map(len, self.array))))
            buffer += b''.join(bytes(elem) for elem in self.array)
            return bytes(buffer)

        @classmethod
        def from_bytes(cls, data):
            size_t = cls.size_t
            elem_t = cls.elem_t
            f = io.BytesIO(data)
            list_size = int(size_t.from_bytes(f.read(size_t.size)))
            elem_size = elem_t.size

            if elem_t.size: # 要素が固定長の場合
                array = []
                for i in range(list_size // elem_size): # 要素数
                    array.append(elem_t.from_bytes(f.read(elem_t.size)))
                return List(array)

            else: # 要素が可変長の場合
                array = []
                while True:
                    tmp = f.read(elem_t.size_t.size)       # 要素の長さを取得
                    if tmp == b'': break
                    elem_len = int(size_t.from_bytes(tmp)) # 要素の長さを取得
                    elem     = elem_t(f.read(elem_len))    # 要素の内容を取得
                    array.append(elem)
                return List(array)

        def __eq__(self, other):
            assert isinstance(other, List)
            if len(self.array) != len(other.array):
                return False
            for self_elem, other_elem in zip(self.array, other.array):
                if self_elem != other_elem:
                    return False
            return True

    List.size_t = size_t
    List.elem_t = elem_t
    return List
```

次にテストをします。

```python
class TestUint(unittest.TestCase):
    def test_list_fix(self):
        ListUint16 = List(size_t=Uint8, elem_t=Uint16)
        l = ListUint16([])
        self.assertEqual(bytes(l), b'\x00')
        self.assertEqual(ListUint16.from_bytes(bytes(l)), l)

        ListUint16 = List(size_t=Uint8, elem_t=Uint16)
        l = ListUint16([Uint16(1), Uint16(2), Uint16(65535)])
        self.assertEqual(bytes(l), b'\x06\x00\x01\x00\x02\xff\xff')
        self.assertEqual(ListUint16.from_bytes(bytes(l)), l)

        Opaque2 = Opaque(2)
        ListOpaque2 = List(size_t=Uint8, elem_t=Opaque2)
        l = ListOpaque2([Opaque2(b'\xdd\xdd'), Opaque2(b'\xff\xff')])
        self.assertEqual(bytes(l), b'\x04\xdd\xdd\xff\xff')
        self.assertEqual(ListOpaque2.from_bytes(bytes(l)), l)

    def test_list_var(self):
        OpaqueUint8 = Opaque(Uint8)
        ListOpaqueUint8 = List(size_t=Uint8, elem_t=OpaqueUint8)
        l = ListOpaqueUint8([OpaqueUint8(b'\x12\x12'), OpaqueUint8(b'\xff\xff')])
        self.assertEqual(bytes(l), b'\x04\x02\x12\x12\x02\xff\xff')
        self.assertEqual(ListOpaqueUint8.from_bytes(bytes(l)), l)
```
