
import abc # 抽象基底クラス
import struct # バイト列の解釈
import io # バイトストリーム操作

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


def Opaque(size_t):

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

        def __repr__(self):
            return 'Opaque[%d](%s)' % (OpaqueFix.size, repr(self.byte))

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
            length = int(size_t.from_bytes(f.read(size_t.size)))
            byte   = f.read(length)
            return OpaqueVar(byte)

        def __eq__(self, other):
            return self.byte == other.byte and self.size_t == other.size_t

        def __len__(self):
            return len(self.byte)

        def __repr__(self):
            return 'Opaque<%s>(%s)' % \
                (OpaqueVar.size_t.__name__, repr(self.byte))

    if isinstance(size_t, int): # 引数がintのときは固定長
        OpaqueFix.size = size_t
        return OpaqueFix
    if issubclass(size_t, Uint): # 引数がUintNのときは可変長
        OpaqueVar.size = None
        OpaqueVar.size_t = size_t
        return OpaqueVar
    raise TypeError("size's type must be an int or Uint class.")


def List(size_t, elem_t):

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

        def __repr__(self):
            return repr(self.array)

    List.size_t = size_t
    List.elem_t = elem_t
    return List


if __name__ == '__main__':

    import unittest

    class TestUint(unittest.TestCase):

        def test_uint(self):
            with self.assertRaises(TypeError) as cm:
                a = Uint(123)

        def test_uint8(self):
            u = Uint8(0)
            self.assertEqual(Uint8.from_bytes(bytes(u)), u)
            u = Uint8(255)
            self.assertEqual(bytes(u), b'\xff')
            # 変換して復元したものが元に戻るか確認する
            self.assertEqual(Uint8.from_bytes(bytes(u)), u)

        def test_uint8_out_range(self):
            # 不正な値を入れたときにエラーになるか
            with self.assertRaises(Exception) as cm:
                u = Uint8(256)
            with self.assertRaises(Exception) as cm:
                u = Uint8(-1)

        def test_uint16(self):
            u = Uint16(0)
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)
            u = Uint16(65535)
            self.assertEqual(bytes(u), b'\xff\xff')
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)

        def test_uint16_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint16(65536)
            with self.assertRaises(Exception) as cm:
                u = Uint16(-1)

        def test_uint24(self):
            u = Uint24(0)
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)
            u = Uint24(16777215)
            self.assertEqual(bytes(u), b'\xff\xff\xff')
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)

        def test_uint24_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint24(16777216)
            with self.assertRaises(Exception) as cm:
                u = Uint24(-1)

        def test_uint32(self):
            u = Uint32(0)
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)
            u = Uint32(4294967295)
            self.assertEqual(bytes(u), b'\xff\xff\xff\xff')
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)

        def test_uint32_out_range(self):
            with self.assertRaises(Exception) as cm:
                u = Uint32(4294967296)
            with self.assertRaises(Exception) as cm:
                u = Uint32(-1)


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


        def test_list___eq__(self):
            ListUint16 = List(size_t=Uint8, elem_t=Uint16)
            l1 = ListUint16([Uint16(0), Uint16(0xffff)])
            l2 = ListUint16([Uint16(0), Uint16(0xffff)])
            l3 = ListUint16([Uint16(0), Uint16(0xfbff)])
            self.assertTrue(l1 == l2)
            self.assertTrue(l1 != l3)

        def test_list_fix(self):
            ListUint16 = List(size_t=Uint8, elem_t=Uint16)
            l = ListUint16([])
            self.assertEqual(bytes(l), b'\x00')
            self.assertEqual(ListUint16.from_bytes(bytes(l)), l)

            ListUint16 = List(size_t=Uint8, elem_t=Uint16)
            l = ListUint16([Uint16(1), Uint16(2), Uint16(65535)])
            self.assertEqual(bytes(l), b'\x06\x00\x01\x00\x02\xff\xff')
            self.assertEqual(ListUint16.from_bytes(bytes(l)), l)

            ListUint8 = List(size_t=Uint16, elem_t=Uint8)
            l = ListUint8([Uint8(1), Uint8(2), Uint8(255)])
            self.assertEqual(bytes(l), b'\x00\x03\x01\x02\xff')
            self.assertEqual(ListUint8.from_bytes(bytes(l)), l)

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



    unittest.main()
