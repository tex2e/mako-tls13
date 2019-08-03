
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


if __name__ == '__main__':
    a = Uint24(123456)
    b = bytes(a)
    print(b)

    c = Uint24.from_bytes(b)
    print(c)
    print(int(c))

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
            self.assertEqual(Uint8.from_bytes(bytes(u)), u)

        def test_uint8_outrange(self):
            with self.assertRaises(AssertionError) as cm:
                u = Uint8(256)
            with self.assertRaises(AssertionError) as cm:
                u = Uint8(-1)

        def test_uint16(self):
            u = Uint16(0)
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)
            u = Uint16(65535)
            self.assertEqual(bytes(u), b'\xff\xff')
            self.assertEqual(Uint16.from_bytes(bytes(u)), u)

        def test_uint16_outrange(self):
            with self.assertRaises(AssertionError) as cm:
                u = Uint16(65536)
            with self.assertRaises(AssertionError) as cm:
                u = Uint16(-1)

        def test_uint24(self):
            u = Uint24(0)
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)
            u = Uint24(16777215)
            self.assertEqual(bytes(u), b'\xff\xff\xff')
            self.assertEqual(Uint24.from_bytes(bytes(u)), u)

        def test_uint24_outrange(self):
            with self.assertRaises(AssertionError) as cm:
                u = Uint24(16777216)
            with self.assertRaises(AssertionError) as cm:
                u = Uint24(-1)

        def test_uint32(self):
            u = Uint32(0)
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)
            u = Uint32(4294967295)
            self.assertEqual(bytes(u), b'\xff\xff\xff\xff')
            self.assertEqual(Uint32.from_bytes(bytes(u)), u)

        def test_uint32_outrange(self):
            with self.assertRaises(AssertionError) as cm:
                u = Uint32(4294967296)
            with self.assertRaises(AssertionError) as cm:
                u = Uint32(-1)


    unittest.main()
