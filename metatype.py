# ------------------------------------------------------------------------------
# TLSで使用する型を表すための基本クラス
# ------------------------------------------------------------------------------

import sys
import inspect
import io # バイトストリーム操作
import textwrap # テキストの折り返しと詰め込み
from enum import Enum as BuildinEnum

# TLS用の型一覧
# + Type
#   + Uint
#     + Uint8
#     + Uint16
#     + Uint24
#     + Uint32
#     + Uint64
#   + VarLenIntEncoding  (QUIC用)
#   + Opaque
#     + OpaqueFix
#     + OpaqueVar
#   + List
#   + Enum
#     + EnumUnknown
#   + Empty
#   + MetaStruct  (metastruct.py参照)

# 全ての型が継承するクラス
class Type:
    size = None # 固定長のときに使用する
    size_t = None # 可変長のときに使用する
    # バイト列から構造体を構築するメソッドの中では、
    # バイト列の代わりにストリームを渡すことで、読み取った文字数をストリームが保持する。
    @classmethod
    def from_bytes(cls, data):
        stream = io.BytesIO(data)
        try:
            return cls.from_stream(stream)
        except Exception as e:
            print('[-] from_bytes: Error while reading bytes at {0:d} (0x{0:x}).'.format(stream.tell()), file=sys.stderr)
            raise e

    # 抽象クラス以外は必ず上書きすること
    @classmethod
    def from_stream(cls, fs, parent=None):
        raise NotImplementedError

    # 構造体の構築時には、Opaqueは親インスタンスを参照できるようにする。
    def set_parent(self, instance):
        self.parent = instance

    def __bytes__(self):
        raise NotImplementedError(self.__class__.__name__ + "#bytes")

    def __repr__(self):
        raise NotImplementedError(self.__class__.__name__ + "#repr")


# --- Uint ---------------------------------------------------------------------

# UintNの抽象クラス
class Uint(Type):
    def __init__(self, value):
        assert self.__class__ != Uint, \
            "Uint (Abstract Class) cannot construct instance!"
        assert isinstance(value, int)
        max_value = 1 << (8 * self.__class__.size)
        assert 0 <= value < max_value
        self.value = value

    def __bytes__(self):
        res = []
        tmp = self.value
        for i in range(self.__class__.size):
            res.append(bytes([tmp & 0xff]))
            tmp >>= 8
        res.reverse()
        return self.value.to_bytes(self.__class__.size, byteorder='big')

    @classmethod
    def from_stream(cls, fs, parent=None):
        data = fs.read(cls.size)
        return cls(int.from_bytes(data, byteorder='big'))

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

    def __hash__(self):
        return hash((self.__class__.size, self.value))


class Uint8(Uint):
    size = 1  # unsinged char

class Uint16(Uint):
    size = 2  # unsigned short

class Uint24(Uint):
    size = 3

class Uint32(Uint):
    size = 4  # unsigned int

class Uint64(Uint):
    size = 8  # unsinged long


# [QUIC]
# Variable-Length Integer Encoding
#
#   +======+========+=============+=======================+
#   | 2MSB | Length | Usable Bits | Range                 |
#   +======+========+=============+=======================+
#   | 00   | 1      | 6           | 0-63                  |
#   | 01   | 2      | 14          | 0-16383               |
#   | 10   | 4      | 30          | 0-1073741823          |
#   | 11   | 8      | 62          | 0-4611686018427387903 |
#   +------+--------+-------------+-----------------------+
#
class VarLenIntEncoding(Type):

    def __init__(self, value):
        assert isinstance(value, Uint)
        size_t = value.__class__
        size = size_t.size
        assert 0 <= int(value) < (1 << (6 + 8*(size-1)))
        self.size = size
        self.size_t = size_t
        self.value = value

    @classmethod
    def from_stream(cls, fs, parent=None):
        head = fs.read(1)
        if head == b'':
            raise RuntimeError("Byte stream has no length!")
        msb2bit = ord(head) >> 6
        length, UintN = cls._get_msb2bit_info(msb2bit)
        rest = fs.read(length - 1)
        byte = bytes([ord(head) & 0b00111111]) + rest
        value = UintN.from_bytes(byte)
        return VarLenIntEncoding(value)

    def __bytes__(self):
        size = self._get_size()
        msb2bit = self._get_msb2bit()
        msb2bit_mask = msb2bit << 6
        byte = bytearray(bytes(self.value))
        byte[0] |= msb2bit_mask
        return bytes(byte)

    def __repr__(self):
        return 'VarLenIntEncoding' + repr(self.value)

    def _get_size(self):
        size = self.size_t.size
        assert size in (1, 2, 4, 8)
        return size

    def _get_msb2bit(self):
        length = self._get_size()
        if length == 1: return 0b00
        if length == 2: return 0b01
        if length == 4: return 0b10
        if length == 8: return 0b11

    @classmethod
    def _get_msb2bit_info(cls, msb2bit):
        if msb2bit == 0b00: return (1, Uint8)
        if msb2bit == 0b01: return (2, Uint16)
        if msb2bit == 0b10: return (4, Uint32)
        if msb2bit == 0b11: return (8, Uint64)

    @staticmethod
    def len2uint(byte_len):
        if 0 <= byte_len <= 63: return Uint8
        if 0 <= byte_len <= 16383: return Uint16
        if 0 <= byte_len <= 1073741823: return Uint32
        if 0 <= byte_len <= 4611686018427387903: return Uint64

    def __eq__(self, other):
        return (self.size_t == other.size_t and self.value == other.value)

    def __int__(self):
        return int(self.value)

    def __len__(self):
        return self._get_size()


# --- Opaque -------------------------------------------------------------------

class OpaqueMeta(Type):
    def get_raw_bytes(self):
        return self.byte

    def __eq__(self, other):
        return self.byte == other.byte

    def __len__(self):
        return len(self.byte)


def Opaque(size_t):
    if isinstance(size_t, int): # 引数がintのときは固定長
        return OpaqueFix(size_t)
    if isinstance(size_t, type(lambda: None)): # 引数がラムダのときは実行時に決定する固定長
        return OpaqueFix(size_t)
    if inspect.isclass(size_t):
        if issubclass(size_t, (Uint, VarLenIntEncoding)): # 引数がUintNのときは可変長
            return OpaqueVar(size_t)
    raise TypeError("Opaque's size type (%s) must be an int, Uint, VarLenIntEncoding class." % \
                    size_t.__class__.__name__)

def OpaqueFix(size):

    # 固定長のOpaque (e.g. opaque string[16])
    # ただし、外部の変数によってサイズが決まる場合もある (e.g. opaque string[Hash.length])
    class OpaqueFix(OpaqueMeta):
        size = 0

        def __init__(self, byte):
            assert isinstance(byte, (bytes, bytearray))
            size = OpaqueFix.size
            if callable(size): # ラムダのときは実行時に評価した値がサイズになる
                self.byte = byte
            else:
                assert len(byte) <= size
                self.byte = bytes(byte).rjust(size, b'\x00')

        def __bytes__(self):
            return bytes(self.byte)

        @classmethod
        def from_stream(cls, fs: io.BytesIO, parent: Type=None):
            size = cls.size
            if callable(size): # ラムダのときは実行時に評価した値がサイズになる
                try:
                    size = int(size(parent))
                except Exception as e:
                    print('[-] OpaqueFix.from_stream: cls:   ', cls,  file=sys.stderr)
                    print('[-] OpaqueFix.from_stream: size:  ', size, file=sys.stderr)
                    print('[-] OpaqueFix.from_stream: parent:',       file=sys.stderr)
                    print(parent,                                     file=sys.stderr)
                    raise e
            opaque = OpaqueFix(fs.read(size))
            opaque.set_parent(parent)
            return opaque

        def __repr__(self):
            size = OpaqueFix.size
            if callable(size):
                size = int(size(self.parent))
            return 'Opaque[%d](%s)' % (size, repr(self.byte))

        def get_size(self):
            if callable(self.size):
                return int(OpaqueFix.size(self.parent))
            return self.size

    OpaqueFix.size = size
    return OpaqueFix

def OpaqueVar(size_t):

    # 可変長のOpaque (e.g. opaque string<0..15>)
    class OpaqueVar(OpaqueMeta):
        size_t = Uint

        def __init__(self, byte: bytes):
            assert isinstance(byte, (bytes, bytearray))
            self.byte = bytes(byte)
            self.size_t = OpaqueVar.size_t

        def __bytes__(self):
            if issubclass(self.size_t, Uint):
                UintN = self.size_t
                return bytes(UintN(len(self.byte))) + self.byte
            elif issubclass(self.size_t, VarLenIntEncoding):
                VarLenInt = self.size_t
                byte_len = len(self.byte)
                UintN = VarLenIntEncoding.len2uint(byte_len)
                return bytes(VarLenInt(UintN(byte_len))) + self.byte
            else:
                raise NotImplementedError

        @classmethod
        def from_stream(cls, fs: io.BytesIO, parent=None):
            size_t = OpaqueVar.size_t
            length = int(size_t.from_stream(fs))
            byte   = fs.read(length)
            return OpaqueVar(byte)

        def __repr__(self):
            return 'Opaque<%s>(%s)' % \
                (OpaqueVar.size_t.__name__, repr(self.byte))

    OpaqueVar.size_t = size_t
    return OpaqueVar

OpaqueUint8  = Opaque(Uint8)
OpaqueUint16 = Opaque(Uint16)
OpaqueUint24 = Opaque(Uint24)
OpaqueUint32 = Opaque(Uint32)
OpaqueLength = Opaque(lambda self: self.length)
OpaqueVarLenIntEncoding = Opaque(VarLenIntEncoding)  # [QUIC]


# --- List ---------------------------------------------------------------------

class ListMeta(Type):
    pass

# 配列の構造を表すためのクラス
def List(size_t: Uint, elem_t: Type):

    # List ではスコープが異なる(グローバルとローカル)と、
    # 組み込み関数 issubclass が期待通りに動かない場合があるので、
    # 子クラスの基底クラス名の一覧の中に親クラス名が存在すれば True を返す関数を使用する。
    # この関数は List クラス内で issubclass の代わりに利用する。
    def my_issubclass(child, parent):
        if not hasattr(child, '__bases__'):
            return False
        return parent.__name__ in map(lambda x: x.__name__, child.__bases__)

    class List(ListMeta):
        size_t = None # リストの長さを表す部分の型
        elem_t = None # リストの要素の型

        def __init__(self, array):
            self.array = array

        def __getitem__(self, item):
            return self.array[item]

        def get_array(self):
            return self.array

        # 構造体の構築時には、Listは親インスタンスを参照できるようにする。
        # そして要素がMetaStructであれば、各要素の.set_parent()に親インスタンスを渡す。
        def set_parent(self, instance: Type):
            self.parent = instance

            from metastruct import MetaStruct
            if my_issubclass(List.elem_t, MetaStruct):
                for elem in self.get_array():
                    # elem.set_parent(self.parent)
                    elem.set_parent(self)

        def __bytes__(self):
            size_t = List.size_t
            content = b''.join(bytes(elem) for elem in self.get_array())
            content_len = len(content)
            if isinstance(size_t, type(lambda: None)): # サイズが動的の場合は先頭に長さのバイト列を加えない
                return content
            else:
                return bytes(size_t(content_len)) + content

        @classmethod
        def from_stream(cls, fs: io.BytesIO, parent=None):
            from metastruct import MetaStruct
            size_t = cls.size_t
            elem_t = cls.elem_t
            if isinstance(size_t, type(lambda: None)): # サイズが動的の場合は、無名関数を実行してサイズを決定する
                list_size = int(size_t(parent))
            else:
                list_size = int(size_t.from_stream(fs)) # リスト全体の長さ
            elem_size = elem_t.size # 要素の長さを表す部分の長さ

            array = []
            # 現在のストリーム位置が全体の長さを超えない間、繰り返し行う
            startpos = fs.tell()
            while (fs.tell() - startpos) < list_size:
                elem = elem_t.from_stream(fs, parent)
                array.append(elem)
            return List(array)

        def __eq__(self, other):
            if len(self.get_array()) != len(other.get_array()):
                return False
            for self_elem, other_elem in zip(self.get_array(), other.get_array()):
                if self_elem != other_elem:
                    return False
            return True

        def __repr__(self):
            from metastruct import MetaStruct

            if isinstance(self.__class__.size_t, type(lambda: None)): # サイズが動的の場合は、lambdaと表示
                size_t_class_name = 'lambda'
            else: # サイズが静的の場合は、長さを表すクラス名を表示
                size_t_class_name = self.__class__.size_t.__name__

            if my_issubclass(List.elem_t, MetaStruct):
                # リストの要素がMetaStructのときは、各要素を複数行で表示する
                output = ''
                for elem in self.get_array():
                    content = textwrap.indent(repr(elem), prefix="  ").strip()
                    output += '+ %s\n' % content
                return 'List<%s>:\n%s' % (size_t_class_name, output)
            else:
                # それ以外のときは配列の中身を一行で表示する
                return 'List<%s>%s' % (size_t_class_name, repr(self.get_array()))

        def __iter__(self):
            return iter(self.array)

        def find(self, arg):
            if callable(arg):
                # 引数が関数の場合、条件を満たす値を返す
                return next((x for x in iter(self) if arg(x)), None)
            else:
                # 引数がスカラ値の場合、引数と一致する値を返す
                return next((x for x in iter(self) if x == arg), None)

    List.size_t = size_t
    List.elem_t = elem_t
    return List


# --- Enum ---------------------------------------------------------------------

# 列挙型を表すためのクラス
class Enum(Type, BuildinEnum):
    # 親クラスにクラス変数を定義すると、子クラスでEnumが定義できなくなるので注意。
    # elem_t = UintN # Enumの要素の型

    # Enum は .name でラベル名、.value で値を得ることができる
    def __bytes__(self):
        return bytes(self.value)

    @classmethod
    def from_stream(cls, fs: io.BytesIO, parent=None):
        elem_t = cls.get_type()
        return cls(elem_t.from_stream(fs))

    @classmethod
    def get_type(cls):
        return cls.elem_t.value

    def __repr__(self):
        return '%s.%s(%s)' % (self.__class__.__name__, self.name, self.value)

    def __int__(self):
        return int(self.value)

# 列挙型にない値が与えらたとき unknown という名前の値を動的に生成して返すためのクラス
class EnumUnknown(Enum):
    @classmethod
    def _missing_(cls, value):
        obj = object.__new__(cls)
        obj._name_ = 'unknown'
        obj._value_ = value
        return obj


# --- Empty --------------------------------------------------------------------

class Empty(Type):
    def __init__(self):
        pass

    @classmethod
    def from_stream(cls, fs: io.BytesIO, parent=None):
        return cls()

    def __bytes__(self):
        return b''

    def __repr__(self):
        return 'Empty'



# データ構造復元時のデバッグ方法：
# print(fs.read(10)); fs.seek(-10, 1)
