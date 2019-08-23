
import io # バイトストリーム操作
import textwrap # テキストの折り返しと詰め込み
import re # 正規表現
from type import Type, List, ListMeta

from dataclasses import dataclass

struct = dataclass(repr=False)

# TLSメッセージの構造体を表すためのクラス群
# 使い方：
#
#   @struct
#   class ClientHello(StructMeta):
#       legacy_version: ProtocolVersion
#       random: Random
#       legacy_session_id: Opaque(size_t=Uint8)
#       cipher_suites: List(size_t=Uint16, elem_t=CipherSuite)
#       legacy_compression_methods: List(size_t=Uint16, elem_t=Uint8)
#       extensions: List(size_t=Uint16, elem_t=Extension)
#

class StructMeta(Type):

    def __post_init__(self):

        # create_emptyメソッドで生成されたとき(全ての要素がNoneのとき)は何もしない
        if all(not getattr(self, name) for name in self.get_struct().keys()):
            return

        for name, field in self.get_struct().items():
            elem = getattr(self, name)

            # デフォルト値がラムダのとき、ラムダを評価した値を格納する
            if callable(field.default):
                setattr(self, name, field.default(self))

            # 要素がStructMetaとListのときは、親インスタンスを参照できるようにする
            if isinstance(elem, (StructMeta, ListMeta)):
                elem.set_parent(self)

    @classmethod
    def create_empty(cls):
        dict = {}
        for name, field in cls.__dataclass_fields__.items():
            dict[name] = None
        return cls(**dict)

    # 全てのStructMetaは親インスタンスを参照できるようにする。
    def set_parent(self, parent):
        self.parent = parent

    def __bytes__(self):
        f = io.BytesIO()
        for name, field in self.get_struct().items():
            elem = getattr(self, name)
            if elem is None:
                raise Exception('%s.%s is None!' % (self.__class__.__name__, name))
            f.write(bytes(elem))
        return f.getvalue()

    @classmethod
    def from_fs(cls, fs, parent=None):
        # デフォルト値などを導出せずにインスタンス化する
        instance = cls.create_empty()
        instance.set_parent(parent) # 子が親インスタンスを参照できるようにする

        for name, field in cls.get_struct().items():
            # print('[+]', name, field.type)
            elem_t = field.type

            if isinstance(elem_t, Select):
                # 型がSelectのときは、既に格納した値から型を決定する
                elem_t = elem_t.select_type_by_switch(instance)

            # バイト列から構造体への変換
            if issubclass(elem_t, StructMeta) or issubclass(elem_t, ListMeta):
                # メタ構造体とリストのとき
                elem = elem_t.from_fs(fs, instance)
            else:
                elem = elem_t.from_fs(fs)
            # 値を構造体へ格納
            setattr(instance, name, elem)
        return instance

    @classmethod
    def get_struct(cls):
        return cls.__dataclass_fields__

    def __repr__(self):
        # 出力は次のようにする
        # 1. 各要素を表示するときはプラス(+)記号を加えて、出力幅が70を超えないようにする
        #     + 要素名: 型(値)
        # 2. 要素もStructMetaのときは、内部要素をスペース2つ分だけインデントする
        #     + 要素名: StructMeta名:
        #       + 要素: 型(値)
        title = "%s:\n" % self.__class__.__name__
        elems = []
        for name, field in self.get_struct().items():
            elem = getattr(self, name)
            content = repr(elem)
            output = '%s: %s' % (name, content)

            def is_StructMeta(elem):
                return isinstance(elem, StructMeta)
            def is_List_of_StructMeta(elem):
                return (isinstance(elem, ListMeta) and
                        issubclass(elem.__class__.elem_t, StructMeta))

            if is_StructMeta(elem) or is_List_of_StructMeta(elem):
                # 要素のStructMetaは出力が複数行になるので、その要素をインデントさせる
                output = textwrap.indent(output, prefix="  ").strip()
            else:
                # その他の要素は出力が1行なので、コンソールの幅を超えないように折返し出力させる
                output = '\n  '.join(textwrap.wrap(output, width=70))
            elems.append('+ ' + output)
        return title + "\n".join(elems)

    def __len__(self):
        return len(bytes(self))

# 状況に応じて型を選択するためのクラス。
# 例えば、Handshake.msg_type が client_hello と server_hello で、
# 自身や子供の構造体フィールドの型が変化する場合に使用する。
class Select:
    def __init__(self, switch, cases):
        assert isinstance(switch, str)
        assert isinstance(cases, dict)
        self.switch = switch
        self.cases = cases
        # 引数 switch の構文が正しいか確認する。
        #   自身のプロパティを参照する場合 : "プロパティ名"
        #   親のプロパティを参照する場合 : "親クラス名.プロパティ名"
        if not re.match(r'^[a-zA-Z0-9_]+(\.[a-zA-Z_]+)?$', self.switch):
            raise Exception('Select(%s) is invalid syntax!' % self.switch)

    # フィールド .switch の内容を元に、構築中のインスタンスからプロパティを検索し、
    # プロパティの値から導出した型を返す。
    def select_type_by_switch(self, instance):
        if re.match(r'^[^.]+\.[^.]+$', self.switch):
            # 条件が「クラス名.プロパティ名」のとき
            class_name, prop_name = self.switch.split('.', maxsplit=1)
        else:
            # 条件が「プロパティ名」のみ
            class_name, prop_name = instance.__class__.__name__, self.switch
        # インスタンスのクラス名がclass_nameと一致するまで親をさかのぼる
        tmp = instance
        while tmp is not None:
            if tmp.__class__.__name__ == class_name: break
            tmp = tmp.parent
        if tmp is None:
            raise Exception('Not found %s class in ancestors from %s!' % \
                (class_name, instance.__class__.__name__))
        # 既に格納した値の取得
        value = getattr(tmp, prop_name)
        # 既に格納した値から使用する型を決定する
        ret = self.cases.get(value)
        if ret is None:
            raise Exception('Select(%s) cannot map to class!' % value)
        return ret


if __name__ == '__main__':

    from type import Uint8, Uint16, Opaque, List

    import unittest

    class TestUint(unittest.TestCase):

        def test_structmeta(self):

            OpaqueUint8 = Opaque(size_t=Uint8)
            ListUint8OpaqueUint8 = List(size_t=Uint8, elem_t=Opaque(size_t=Uint8))

            @struct
            class Sample1(StructMeta):
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

        def test_structmeta_eq_neq(self):

            @struct
            class Sample1(StructMeta):
                fieldA: Uint8
                fieldB: Uint8

            s1 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
            s2 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
            s3 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x21))

            self.assertEqual(s1, s2)
            self.assertNotEqual(s1, s3)

        def test_structmeta_default_value(self):

            @struct
            class Sample1(StructMeta):
                fieldA: Uint8 = Uint8(0x01)
                fieldB: Uint8 = None

            s1 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
            s2 = Sample1(fieldB=Uint8(0x12))

            self.assertEqual(s1, s2)

        def test_structmeta_default_lambda(self):

            @struct
            class Sample1(StructMeta):
                length: Uint8 = lambda self: Uint8(len(bytes(self.fragment)))
                fragment: Opaque(Uint8) = None

            s1 = Sample1(fragment=Opaque(Uint8)(b'test'))

            self.assertEqual(s1.length, Uint8(5))

        def test_structmeta_recursive(self):

            @struct
            class Sample1(StructMeta):
                fieldC: Uint16
                fieldD: Uint16

            @struct
            class Sample2(StructMeta):
                fieldA: Uint16
                fieldB: Sample1

            s = Sample2(fieldA=Uint16(0xaaaa),
                        fieldB=Sample1(fieldC=Uint16(0xbbbb),
                                       fieldD=Uint16(0xcccc)))

            self.assertTrue(isinstance(s.fieldB, Sample1))
            self.assertTrue(isinstance(s.fieldB.fieldC, Uint16))

            self.assertEqual(bytes(s), b'\xaa\xaa\xbb\xbb\xcc\xcc')
            self.assertEqual(Sample2.from_bytes(bytes(s)), s)

        def test_structmeta_keep_rest_bytes(self):
            import io

            OpaqueUint8 = Opaque(size_t=Uint8)
            ListUint8OpaqueUint8 = List(size_t=Uint8, elem_t=Opaque(size_t=Uint8))

            @struct
            class Sample1(StructMeta):
                fieldA: Uint16
                fieldB: OpaqueUint8
                fieldC: ListUint8OpaqueUint8

            s = Sample1(fieldA=Uint16(0x1),
                        fieldB=OpaqueUint8(b'\xff'),
                        fieldC=ListUint8OpaqueUint8([OpaqueUint8(b'\xaa'),
                                                     OpaqueUint8(b'\xbb')]))

            deadbeef = bytes.fromhex('deadbeef')
            fs = io.BytesIO(bytes(s) + deadbeef)

            s2 = Sample1.from_fs(fs)

            rest = fs.read()
            self.assertEqual(rest, deadbeef)

        def test_structmeta_select(self):

            @struct
            class Sample1(StructMeta):
                field: Uint16

            @struct
            class Sample2(StructMeta):
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

        def test_structmeta_parent(self):

            @struct
            class Sample1(StructMeta):
                child_field: Select('Sample2.parent_field', cases={
                    Uint8(0xaa): Uint8,
                    Uint8(0xbb): Uint16,
                })

            @struct
            class Sample2(StructMeta):
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

        def test_structmeta_multiple_parents(self):

            @struct
            class Sample1(StructMeta):
                child_field: Select('Sample3.parent_fieldA', cases={
                    Uint8(0xaa): Uint8,
                    Uint8(0xbb): Uint16,
                })

            @struct
            class Sample2(StructMeta):
                parent_fieldB: Uint8
                fragment: Sample1

            @struct
            class Sample3(StructMeta):
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

        def test_structmeta_unknown_parent(self):

            @struct
            class Sample1(StructMeta):
                child_field: Select('UnknownClass.parent_field', cases={
                    Uint8(0xaa): Uint8,
                    Uint8(0xbb): Uint16,
                })

            @struct
            class Sample2(StructMeta):
                parent_field: Uint8
                fragment: Sample1

            s1_byte = bytes.fromhex('aa ff')

            with self.assertRaisesRegex(Exception, 'UnknownClass') as cm:
                a = Sample2.from_bytes(bytes(s1_byte))

        def test_structmeta_invalid_switch(self):
            with self.assertRaisesRegex(Exception, 'Select') as cm:
                Select('.field', cases={})
            with self.assertRaisesRegex(Exception, 'Select') as cm:
                Select('Handshake#field', cases={})
            with self.assertRaisesRegex(Exception, 'Select') as cm:
                Select('Handshake.field.fieldA', cases={})
            with self.assertRaisesRegex(Exception, 'Select') as cm:
                Select('Handshake.field.fieldA', cases={})

        def test_structmeta_has_parent_ref(self):

            @struct
            class Sample1(StructMeta):
                child_field: Select('Sample3.parent_fieldA', cases={
                    Uint8(0xaa): Uint8,
                    Uint8(0xbb): Uint16,
                })

            @struct
            class Sample2(StructMeta):
                parent_fieldB: Uint8
                fragment: Sample1

            Sample2s = List(size_t=Uint8, elem_t=Sample2)

            @struct
            class Sample3(StructMeta):
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
            self.assertTrue(isinstance(target.parent.parent, Sample3))

            # バイト列から構造体を構築した場合
            s2 = Sample3.from_bytes(bytes(s))
            target = s.fragment.get_array()[0].fragment # 最下の子インスタンス
            self.assertTrue(isinstance(target, Sample1))
            self.assertTrue(isinstance(target.parent, Sample2))
            self.assertTrue(isinstance(target.parent.parent, Sample3))

    unittest.main()
