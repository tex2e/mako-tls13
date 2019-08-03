---
title: データ構造とバイト列の変換
tags: [protocol]
sidebar: doc_sidebar
permalink: protocol_structs_and_bytes.html
---

Pythonではデータ構造としてメッセージを保存し、ソケット通信で送るときはデータ構造をバイト列に変換します。

## 型

基本的な型のデータ構造とバイト列の変換について説明します。

### Uint

一般的には uint は unsinged int の略ですが、RFC 8446 では次のように型が定義されています。

| 型 | C言語の型 | サイズ |
|---|---|---|
| uint8  | unsinged char  | 1 |
| uint16 | unsinged short | 2 |
| uint24 |                | 3 |
| uint32 | unsinged int   | 4 |

というわけで、Uint8, Uint16, Uint24, Uint32 のクラスを作ります。
さらに、抽象化するために Uint という抽象クラスも作ります。

実装で重要なメソッドは、以下の点です。

- bytes(UintNのインスタンス) : Uint型をバイト列に変換します (`__bytes__`)
- UintN.from_bytes(バイト列) : バイト列からUint型を復元します (`from_bytes`)

```python
import abc # 抽象基底クラス
import struct # バイト列の解釈

class Uint(abc.ABC):
    def __init__(self, value):
        assert isinstance(value, int)
        max_value = 1 << (8 * self.__class__.size)
        assert 0 <= value < max_value
        self.value = value

    @abc.abstractmethod
    def __bytes__(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
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
