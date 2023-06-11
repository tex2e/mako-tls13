# metastruct.pyの単体テスト
# python -m unittest -v tests.test_metastruct

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from metastruct import *
from metatype import Uint8, Uint16, Opaque, List

class TestUint(unittest.TestCase):

    def test_metastruct(self):

        OpaqueUint8 = Opaque(size_t=Uint8)
        ListUint8OpaqueUint8 = List(size_t=Uint8, elem_t=Opaque(size_t=Uint8))

        @struct
        class Sample1(MetaStruct):
            fieldA: Uint16
            fieldB: OpaqueUint8
            fieldC: ListUint8OpaqueUint8

        s = Sample1(fieldA=Uint16(0x1),
                    fieldB=OpaqueUint8(b'\xff'),
                    fieldC=ListUint8OpaqueUint8([OpaqueUint8(b'\xaa'),
                                                 OpaqueUint8(b'\xbb')]))

        self.assertTrue(hasattr(s, 'fieldA'))
        self.assertTrue(isinstance(s.fieldA, Uint16))
        self.assertTrue(hasattr(s, 'fieldB'))
        self.assertTrue(isinstance(s.fieldB, OpaqueUint8))
        self.assertTrue(hasattr(s, 'fieldC'))
        self.assertTrue(isinstance(s.fieldC, ListUint8OpaqueUint8))

        self.assertEqual(bytes(s), b'\x00\x01\x01\xff\x04\x01\xaa\x01\xbb')
        self.assertEqual(Sample1.from_bytes(bytes(s)), s)

    def test_metastruct_eq_neq(self):

        @struct
        class Sample1(MetaStruct):
            fieldA: Uint8
            fieldB: Uint8

        s1 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
        s2 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
        s3 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x21))

        self.assertEqual(s1, s2)
        self.assertNotEqual(s1, s3)

    def test_metastruct_default_value(self):

        @struct
        class Sample1(MetaStruct):
            fieldA: Uint8 = Uint8(0x01)
            fieldB: Uint8

        s1 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
        s2 = Sample1(fieldB=Uint8(0x12))

        self.assertEqual(s1, s2)

    def test_metastruct_default_lambda(self):

        @struct
        class Sample1(MetaStruct):
            length: Uint8 = lambda self: Uint8(len(bytes(self.fragment)))
            fragment: Opaque(Uint8)

        s1 = Sample1(fragment=Opaque(Uint8)(b'test'))

        self.assertEqual(s1.length, Uint8(5))

    def test_metastruct_recursive(self):

        @struct
        class Sample1(MetaStruct):
            fieldC: Uint16
            fieldD: Uint16

        @struct
        class Sample2(MetaStruct):
            fieldA: Uint16
            fieldB: Sample1

        s = Sample2(fieldA=Uint16(0xaaaa),
                    fieldB=Sample1(fieldC=Uint16(0xbbbb),
                                    fieldD=Uint16(0xcccc)))

        self.assertTrue(isinstance(s.fieldB, Sample1))
        self.assertTrue(isinstance(s.fieldB.fieldC, Uint16))

        self.assertEqual(bytes(s), b'\xaa\xaa\xbb\xbb\xcc\xcc')
        self.assertEqual(Sample2.from_bytes(bytes(s)), s)

    def test_metastruct_keep_rest_bytes(self):
        import io

        OpaqueUint8 = Opaque(size_t=Uint8)
        ListUint8OpaqueUint8 = List(size_t=Uint8, elem_t=Opaque(size_t=Uint8))

        @struct
        class Sample1(MetaStruct):
            fieldA: Uint16
            fieldB: OpaqueUint8
            fieldC: ListUint8OpaqueUint8

        s = Sample1(fieldA=Uint16(0x1),
                    fieldB=OpaqueUint8(b'\xff'),
                    fieldC=ListUint8OpaqueUint8([OpaqueUint8(b'\xaa'),
                                                 OpaqueUint8(b'\xbb')]))

        deadbeef = bytes.fromhex('deadbeef')
        fs = io.BytesIO(bytes(s) + deadbeef)

        s2 = Sample1.from_stream(fs)

        rest = fs.read()
        self.assertEqual(rest, deadbeef)

    def test_metastruct_select(self):

        @struct
        class Sample1(MetaStruct):
            field: Uint16

        @struct
        class Sample2(MetaStruct):
            type: Uint8
            fragment: Select('type', cases={
                Uint8(0xaa): Opaque(0),
                Uint8(0xbb): Sample1,
            })

        s1 = Sample2(type=Uint8(0xaa), fragment=Opaque(0)(b''))
        self.assertEqual(bytes(s1), bytes.fromhex('aa'))
        self.assertEqual(Sample2.from_bytes(bytes(s1)), s1)

        s2 = Sample2(type=Uint8(0xbb), fragment=Sample1(field=Uint16(0x1212)))
        self.assertEqual(bytes(s2), bytes.fromhex('bb 1212'))
        self.assertEqual(Sample2.from_bytes(bytes(s2)), s2)

    def test_metastruct_parent(self):

        @struct
        class Sample1(MetaStruct):
            child_field: Select('Sample2.parent_field', cases={
                Uint8(0xaa): Uint8,
                Uint8(0xbb): Uint16,
            })

        @struct
        class Sample2(MetaStruct):
            parent_field: Uint8
            fragment: Sample1

        s1 = Sample2(
            parent_field=Uint8(0xaa),
            fragment=Sample1(
                child_field=Uint8(0xff)))
        s1_byte = bytes.fromhex('aa ff')
        s2 = Sample2(
            parent_field=Uint8(0xbb),
            fragment=Sample1(
                child_field=Uint16(0xffff)))
        s2_byte = bytes.fromhex('bb ffff')

        self.assertEqual(bytes(s1), s1_byte)
        self.assertEqual(bytes(s2), s2_byte)
        self.assertEqual(Sample2.from_bytes(bytes(s1)), s1)
        self.assertEqual(Sample2.from_bytes(bytes(s2)), s2)

    def test_metastruct_multiple_parents(self):

        @struct
        class Sample1(MetaStruct):
            child_field: Select('Sample3.parent_fieldA', cases={
                Uint8(0xaa): Uint8,
                Uint8(0xbb): Uint16,
            })

        @struct
        class Sample2(MetaStruct):
            parent_fieldB: Uint8
            fragment: Sample1

        @struct
        class Sample3(MetaStruct):
            parent_fieldA: Uint8
            fragment: Sample2

        s = Sample3(
            parent_fieldA=Uint8(0xbb),
            fragment=Sample2(
                parent_fieldB=Uint8(0x12),
                fragment=Sample1(
                    child_field=Uint16(0x0101))))
        s_byte = bytes.fromhex('bb 12 0101')

        self.assertEqual(bytes(s), s_byte)
        self.assertEqual(Sample3.from_bytes(bytes(s)), s)

    def test_metastruct_unknown_parent(self):

        @struct
        class Sample1(MetaStruct):
            child_field: Select('UnknownClass.parent_field', cases={
                Uint8(0xaa): Uint8,
                Uint8(0xbb): Uint16,
            })

        @struct
        class Sample2(MetaStruct):
            parent_field: Uint8
            fragment: Sample1

        s1_byte = bytes.fromhex('aa ff')

        # suppress stdout
        import io
        sys.stderr = io.StringIO()
        with self.assertRaisesRegex(Exception, 'UnknownClass') as cm:
            a = Sample2.from_bytes(bytes(s1_byte))
        sys.stderr = sys.__stderr__

    def test_metastruct_invalid_switch(self):
        with self.assertRaisesRegex(Exception, 'Select') as cm:
            Select('.field', cases={})
        with self.assertRaisesRegex(Exception, 'Select') as cm:
            Select('Handshake#field', cases={})
        with self.assertRaisesRegex(Exception, 'Select') as cm:
            Select('Handshake.field.fieldA', cases={})
        with self.assertRaisesRegex(Exception, 'Select') as cm:
            Select('Handshake.field.fieldA', cases={})

    def test_metastruct_has_parent_ref(self):

        @struct
        class Sample1(MetaStruct):
            child_field: Select('Sample3.parent_fieldA', cases={
                Uint8(0xaa): Uint8,
                Uint8(0xbb): Uint16,
            })

        @struct
        class Sample2(MetaStruct):
            parent_fieldB: Uint8
            fragment: Sample1

        Sample2s = List(size_t=Uint8, elem_t=Sample2)

        @struct
        class Sample3(MetaStruct):
            parent_fieldA: Uint8
            fragment: Sample2s

        s = Sample3(
            parent_fieldA=Uint8(0xbb),
            fragment=Sample2s([
                Sample2(
                    parent_fieldB=Uint8(0x12),
                    fragment=Sample1(
                        child_field=Uint16(0x0101))
                )
            ])
        )

        # コンストラクタで構造体を構築した場合
        target = s.fragment.get_array()[0].fragment # 最下の子インスタンス
        self.assertTrue(isinstance(target, Sample1))
        self.assertTrue(isinstance(target.parent, Sample2))
        self.assertTrue(is_List_of_MetaStruct(target.parent.parent))
        self.assertTrue(isinstance(target.parent.parent.parent, Sample3))

        # バイト列から構造体を構築した場合
        s2 = Sample3.from_bytes(bytes(s))
        target = s.fragment.get_array()[0].fragment # 最下の子インスタンス
        self.assertTrue(isinstance(target, Sample1))
        self.assertTrue(isinstance(target.parent, Sample2))
        self.assertTrue(is_List_of_MetaStruct(target.parent.parent))
        self.assertTrue(isinstance(target.parent.parent.parent, Sample3))


if __name__ == '__main__':
    unittest.main()
