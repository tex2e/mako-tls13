
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

def Opaque(size):

    # 固定長のOpaque (e.g. opaque string[16])
    class OpaqueFix:
        size = 0

        def __init__(self, byte):
            max_size = self.__class__.size
            assert isinstance(byte, (bytes, bytearray))
            assert len(byte) <= max_size
            self.byte = byte.rjust(max_size, b'\x00')

        def __bytes__(self):
            return self.byte

        @classmethod
        def from_bytes(self, data):
            return OpaqueFix(data)

        def __eq__(self, other):
            return self.byte == other.byte

    # 可変長のOpaque (e.g. opaque string<0..15>)
    class OpaqueVar:
        size = None
        size_t = Uint

        def __init__(self, byte):
            assert isinstance(byte, (bytes, bytearray))
            size_t = self.__class__.size_t
            self.byte = byte
            self.size_t = size_t

        def __bytes__(self):
            UintN = self.size_t
            return bytes(UintN(len(self.byte))) + self.byte

        @classmethod
        def from_bytes(cls, data):
            size_t = cls.size_t
            f = io.BytesIO(data)
            length = size_t.from_bytes(f.read(size_t.size))
            byte   = f.read(int(length))
            return OpaqueVar(byte)

        def __eq__(self, other):
            return self.byte == other.byte and self.size_t == other.size_t

    if isinstance(size, int):
        OpaqueFix.size = size
        return OpaqueFix
    if issubclass(size, Uint):
        OpaqueVar.size = None
        OpaqueVar.size_t = size
        return OpaqueVar
    raise TypeError("size's type must be an int or Uint class.")


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
            # 最大4byteのOpaqueに対して、4byteのバイト列を渡す
            Opaque4 = Opaque(4)
            o = Opaque4(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
            self.assertEqual(Opaque4.from_bytes(bytes(o)), o)

            # 最大8byteのOpaqueに対して、4byteのバイト列を渡す
            Opaque8 = Opaque(8)
            o = Opaque8(b'\x01\x23\x45\x67')
            self.assertEqual(bytes(o), b'\x00\x00\x00\x00\x01\x23\x45\x67')
            self.assertEqual(Opaque8.from_bytes(bytes(o)), o)

        def test_opaque_fix_invalid_args(self):
            # 最大4byteのOpaqueに対して、5byteのバイト列を渡す
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


    unittest.main()
