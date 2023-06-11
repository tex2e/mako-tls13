# metatype.pyの単体テスト
# python -m unittest -v tests.test_metatype

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from metatype import *

class TestUint(unittest.TestCase):

    def test_uint(self):
        with self.assertRaises(Exception) as cm:
            a = Uint(123)

    def test_uint8(self):
        u = Uint8(0)
        self.assertEqual(bytes(u), b'\x00')
        self.assertEqual(Uint8.from_bytes(bytes(u)), u)
        u = Uint8(0x12)
        self.assertEqual(bytes(u), b'\x12')
        self.assertEqual(Uint8.from_bytes(bytes(u)), u)
        u = Uint8(255)
        self.assertEqual(bytes(u), b'\xff')
        self.assertEqual(Uint8.from_bytes(bytes(u)), u)

    def test_uint8_out_range(self):
        # 不正な値を入れたときにエラーになるか
        with self.assertRaises(Exception) as cm:
            u = Uint8(256)
        with self.assertRaises(Exception) as cm:
            u = Uint8(-1)

    def test_uint16(self):
        u = Uint16(0)
        self.assertEqual(bytes(u), b'\x00\x00')
        self.assertEqual(Uint16.from_bytes(bytes(u)), u)
        u = Uint16(0x0102)
        self.assertEqual(bytes(u), b'\x01\x02')
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
        self.assertEqual(bytes(u), b'\x00\x00\x00')
        self.assertEqual(Uint24.from_bytes(bytes(u)), u)
        u = Uint24(0x010203)
        self.assertEqual(bytes(u), b'\x01\x02\x03')
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
        self.assertEqual(bytes(u), b'\x00\x00\x00\x00')
        self.assertEqual(Uint32.from_bytes(bytes(u)), u)
        u = Uint32(0x01020304)
        self.assertEqual(bytes(u), b'\x01\x02\x03\x04')
        self.assertEqual(Uint32.from_bytes(bytes(u)), u)
        u = Uint32(4294967295)
        self.assertEqual(bytes(u), b'\xff\xff\xff\xff')
        self.assertEqual(Uint32.from_bytes(bytes(u)), u)

    def test_uint32_out_range(self):
        with self.assertRaises(Exception) as cm:
            u = Uint32(4294967296)
        with self.assertRaises(Exception) as cm:
            u = Uint32(-1)

    def test_VarLenIntEncoding_Uint8(self):
        u = VarLenIntEncoding(Uint8(0))
        self.assertEqual(bytes(u), bytes([0b00000000]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint8(1))
        self.assertEqual(bytes(u), bytes([0b00000001]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint8(63))
        self.assertEqual(bytes(u), bytes([0b00111111]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint8(63+1))
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint8(-1))

    def test_VarLenIntEncoding_Uint16(self):
        u = VarLenIntEncoding(Uint16(0))
        self.assertEqual(bytes(u), bytes([0b01000000, 0b00000000]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint16(1))
        self.assertEqual(bytes(u), bytes([0b01000000, 0b00000001]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint16(16383))
        self.assertEqual(bytes(u), bytes([0b01111111, 0b11111111]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint16(16383+1))
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint16(-1))

    def test_VarLenIntEncoding_Uint32(self):
        u = VarLenIntEncoding(Uint32(0))
        self.assertEqual(bytes(u), bytes([
            0b10000000, 0b00000000, 0b00000000, 0b00000000]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint32(1))
        self.assertEqual(bytes(u), bytes([
            0b10000000, 0b00000000, 0b00000000, 0b00000001]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint32(1073741823))
        self.assertEqual(bytes(u), bytes([
            0b10111111, 0b11111111, 0b11111111, 0b11111111]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint32(1073741823+1))
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint32(-1))

    def test_VarLenIntEncoding_Uint64(self):
        u = VarLenIntEncoding(Uint64(0))
        self.assertEqual(bytes(u), bytes([
            0b11000000, 0b00000000, 0b00000000, 0b00000000,
            0b00000000, 0b00000000, 0b00000000, 0b00000000]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint64(1))
        self.assertEqual(bytes(u), bytes([
            0b11000000, 0b00000000, 0b00000000, 0b00000000, 
            0b00000000, 0b00000000, 0b00000000, 0b00000001]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        u = VarLenIntEncoding(Uint64(4611686018427387903))
        self.assertEqual(bytes(u), bytes([
            0b11111111, 0b11111111, 0b11111111, 0b11111111, 
            0b11111111, 0b11111111, 0b11111111, 0b11111111]))
        self.assertEqual(VarLenIntEncoding.from_bytes(bytes(u)), u)
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint64(4611686018427387903+1))
        with self.assertRaises(Exception) as cm:
            u = VarLenIntEncoding(Uint64(-1))

    # --- Opaque ---

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

        self.assertEqual(Opaque4.size, 4)
        self.assertEqual(Opaque8.size, 8)

    def test_opaque_fix_invalid_args(self):
        # 4byteのOpaqueに対して、5byteのバイト列を渡す
        Opaque4 = Opaque(4)
        with self.assertRaises(Exception) as cm:
            o = Opaque4(b'\x01\x23\x45\x67\x89')

    def test_opaque_fix_lambda_immediate_eval(self):
        OpaqueUnk = Opaque(lambda self: 4)
        o = OpaqueUnk(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
        self.assertEqual(OpaqueUnk.from_bytes(bytes(o)), o)

    def test_opaque_fix_lambda_lazy_eval(self):
        OpaqueUnk = Opaque(lambda self: hash_len)
        hash_len = 4
        o = OpaqueUnk(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x01\x23\x45\x67')
        self.assertEqual(OpaqueUnk.from_bytes(bytes(o)), o)

    def test_opaque_fix_lambda_parent_length(self):
        OpaqueUnk = Opaque(lambda self: self.length)

        import metastruct as meta
        @meta.struct
        class Test(meta.MetaStruct):
            length: Uint8
            fragment: OpaqueUnk

        t = Test(length=Uint8(4), fragment=OpaqueUnk(b'\x01\x23\x45\x67'))
        self.assertEqual(bytes(t), b'\x04\x01\x23\x45\x67')
        self.assertEqual(Test.from_bytes(bytes(t)), t)

    def test_opaque_var(self):
        # 可変長のOpaqueでデータ長を表す部分がUint8のとき
        OpaqueUint8 = Opaque(Uint8)
        o = OpaqueUint8(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x04\x01\x23\x45\x67')
        self.assertEqual(OpaqueUint8.from_bytes(bytes(o)), o)

        # 可変長のOpaqueでデータ長を表す部分がUint16のとき
        OpaqueUint16 = Opaque(Uint16)
        o = OpaqueUint16(b'\x01\x23\x45\x67')
        self.assertEqual(bytes(o), b'\x00\x04\x01\x23\x45\x67')
        self.assertEqual(OpaqueUint16.from_bytes(bytes(o)), o)

        self.assertEqual(OpaqueUint8.size_t, Uint8)
        self.assertEqual(OpaqueUint16.size_t, Uint16)

    # --- List ---

    def test_list_eq_neq(self):
        ListUint16 = List(size_t=Uint8, elem_t=Uint16)
        l1 = ListUint16([Uint16(0), Uint16(0xffff)])
        l2 = ListUint16([Uint16(0), Uint16(0xffff)])
        l3 = ListUint16([Uint16(0), Uint16(0xfbff)])
        self.assertEqual(l1, l2)
        self.assertNotEqual(l1, l3)

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
        self.assertEqual(bytes(l), b'\x06\x02\x12\x12\x02\xff\xff')
        self.assertEqual(ListOpaqueUint8.from_bytes(bytes(l)), l)


    def test_enum(self):
        class FooType(Enum):
            hoge = 1

        self.assertEqual(FooType.hoge, FooType(1))
        with self.assertRaises(Exception) as cm:
            FooType(2)

    def test_enum_unknown(self):
        class FooType(EnumUnknown):
            hoge = 1

        self.assertEqual(FooType.hoge, FooType(1))
        t2 = FooType(2)
        self.assertEqual(t2.name, 'unknown')
        self.assertEqual(t2.value, 2)

# ------------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
