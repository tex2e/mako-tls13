
import io # バイトストリーム操作
import textwrap # テキストの折り返しと詰め込み
import re # 正規表現
from type import Type, List
from disp import hexdump

# TLSメッセージの構造体を表すためのクラス群
# 使い方：
#
#   class ClientHello(StructMeta):
#     struct = Members([
#       Member(ProtocolVersion, 'legacy_version'),
#       Member(Random, 'random'),
#       Member(Opaque(size_t=Uint8), 'legacy_session_id'),
#       Member(List(size_t=Uint16, elem_t=CipherSuite), 'cipher_suites'),
#       Member(List(size_t=Uint16, elem_t=Uint8), 'legacy_compression_methods'),
#       Member(List(size_t=Uint16, elem_t=Extension), 'extensions'),
#     ])
#

class StructMeta(Type):
    def __init__(self, lazy_eval=False, **kwargs):
        self.__class__.struct.set_props(self, lazy_eval=lazy_eval, **kwargs)

    def __bytes__(self):
        f = io.BytesIO()
        for member in self.get_struct().get_members():
            name = member.get_name()
            elem = getattr(self, name)
            f.write(bytes(elem))
        return f.getvalue()

    @classmethod
    def from_fs(cls, fs, parent=None):
        # デフォルト値などを導出せずにインスタンス化する
        instance = cls(lazy_eval=True)
        setattr(instance, 'parent', parent) # 子が親インスタンスを参照できるようにする

        for member in cls.get_struct().get_members():
            name = member.get_name()
            elem_t = member.get_type()

            if isinstance(elem_t, Select):
                # 型がSelectのときは、既に格納した値から型を決定する
                elem_t = elem_t.select_type_by_switch(instance)

            # バイト列から構造体への変換
            if isinstance(elem_t, type) and issubclass(elem_t, StructMeta):
                elem = elem_t.from_fs(fs, instance)
            else:
                elem = elem_t.from_fs(fs)
            # 値を構造体へ格納
            setattr(instance, name, elem)
        return instance

    @classmethod
    def get_struct(cls):
        return cls.struct

    def __repr__(self):
        # 出力は次のようにする
        # 1. 各要素を表示するときはプラス(+)記号を加えて、出力幅が70を超えないようにする
        #     + 要素名: 型(値)
        # 2. 要素もStructMetaのときは、内部要素をスペース2つ分だけインデントする
        #     + 要素名: StructMeta名:
        #       + 要素: 型(値)
        title = "%s:\n" % self.__class__.__name__
        elems = []
        for member in self.get_struct().get_members():
            name = member.get_name()
            elem = getattr(self, name)
            content = repr(elem)
            output = '%s: %s' % (name, content)

            def is_StructMeta(elem):
                return isinstance(elem, StructMeta)
            def is_List_of_StructMeta(elem):
                return (hasattr(elem, 'array') and
                        issubclass(elem.__class__.elem_t, StructMeta))

            if is_StructMeta(elem) or is_List_of_StructMeta(elem):
                # 要素のStructMetaは出力が複数行になるので、その要素をインデントさせる
                output = textwrap.indent(output, prefix="  ").strip()
            else:
                # その他の要素は出力が1行なので、コンソールの幅を超えないように折返し出力させる
                output = '\n  '.join(textwrap.wrap(output, width=70))
            elems.append('+ ' + output)
        return title + "\n".join(elems)

    def __eq__(self, other):
        self_members  = self.get_struct().get_members()
        other_members = other.get_struct().get_members()
        # 要素数の比較
        if len(self_members) != len(other_members):
            return False
        # 各要素の比較
        for self_member, other_member in zip(self_members, other_members):
            self_member_name  = self_member.get_name()
            other_member_name = other_member.get_name()
            if self_member_name != other_member_name:
                return False
            self_elem  = getattr(self, self_member_name)
            other_elem = getattr(other, other_member_name)
            if self_elem != other_elem:
                return False
        return True

    def __len__(self):
        return len(bytes(self))

# 構造体の要素を表すクラス
class Member:
    def __init__(self, type, name, default=None):
        assert isinstance(type, Select) or issubclass(type, Type)
        assert isinstance(name, str)
        assert (default is None) or callable(default) or isinstance(default, Type)
        self.type = type
        self.name = name
        self.default = default

    def get_type(self):
        return self.type

    def get_name(self):
        return self.name

    # StructMetaクラスのインスタンス初期化時にキーワード引数で与えられなかった時に呼び出される。
    # 普通は .default の値を返すが、.default がラムダ関数であれば、評価した値を返す。
    # ラムダ関数を評価する際は、キーワード引数から導出するもの(例えば length など)があるので、
    # キーワード引数の辞書をラムダの引数として与える。
    def get_default(self, args_dict=None):
        if callable(self.default):
            # ラムダのときは、ラムダを評価した値をデフォルト値として返す。
            return self.default(args_dict)
        else:
            # それ以外のときは、設定したデフォルト値を返す。
            return self.default

# 構造体の要素の集合を表すクラス
class Members:
    def __init__(self, members=[]):
        self.members = members # array

    def get_members(self):
        return self.members

    # メタ構造を元に与えられた引数をthisのプロパティとして格納する。
    # 構造体からバイト列を構築する時はlazy_eval=Falseにする。
    # バイト列から構造体を構築する時はlazy_eval=Trueにする(デフォルト値を求める必要がないため)。
    def set_props(self, this, lazy_eval=False, **kwargs):
        assert isinstance(this, StructMeta)
        for member in self.get_members():
            # プロパティの追加
            name = member.get_name()
            if lazy_eval: # lazy_evalが有効のときは、デフォルト値の導出を行わない
                value = None
            elif name in kwargs.keys():
                value = kwargs.get(name)
            else:
                value = member.get_default(kwargs)
            setattr(this, name, value)
        return self

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

            class Sample1(StructMeta):
                struct = Members([
                    Member(Uint16, 'fieldA'),
                    Member(OpaqueUint8, 'fieldB'),
                    Member(ListUint8OpaqueUint8, 'fieldC'),
                ])

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

            class Sample1(StructMeta):
                struct = Members([
                    Member(Uint8, 'fieldA'),
                    Member(Uint8, 'fieldB'),
                ])

            s1 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
            s2 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
            s3 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x21))

            self.assertEqual(s1, s2)
            self.assertNotEqual(s1, s3)

        def test_structmeta_default_value(self):

            class Sample1(StructMeta):
                struct = Members([
                    Member(Uint8, 'fieldA', Uint8(0x01)),
                    Member(Uint8, 'fieldB'),
                ])

            s1 = Sample1(fieldA=Uint8(0x01), fieldB=Uint8(0x12))
            s2 = Sample1(fieldB=Uint8(0x12))

            self.assertEqual(s1, s2)

        def test_structmeta_default_lambda(self):

            class Sample1(StructMeta):
                struct = Members([
                    Member(Uint8, 'length',
                        lambda args: Uint8(len(bytes(args.get('fragment'))))),
                    Member(Opaque(Uint8), 'fragment'),
                ])

            s1 = Sample1(fragment=Opaque(Uint8)(b'test'))

            self.assertEqual(s1.length, Uint8(5))

        def test_structmeta_recursive(self):

            class Sample1(StructMeta):
                struct = Members([
                    Member(Uint16, 'fieldC'),
                    Member(Uint16, 'fieldD'),
                ])

            class Sample2(StructMeta):
                struct = Members([
                    Member(Uint16, 'fieldA'),
                    Member(Sample1, 'fieldB'),
                ])

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

            class Sample1(StructMeta):
                struct = Members([
                    Member(Uint16, 'fieldA'),
                    Member(OpaqueUint8, 'fieldB'),
                    Member(ListUint8OpaqueUint8, 'fieldC'),
                ])

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

            class Sample1(StructMeta):
                struct = Members([
                    Member(Opaque(Uint16), 'field'),
                ])

            class Sample2(StructMeta):
                struct = Members([
                    Member(Uint8, 'type'),
                    Member(Select('type', cases={
                        Uint8(0xaa): Opaque(0),
                        Uint8(0xbb): Sample1,
                    }), 'fragment')
                ])

            s1 = Sample2(type=Uint8(0xaa), fragment=Opaque(0)(b''))
            self.assertEqual(bytes(s1), bytes.fromhex('aa'))
            self.assertEqual(Sample2.from_bytes(bytes(s1)), s1)

        def test_structmeta_parent(self):

            class Sample1(StructMeta):
                struct = Members([
                    Member(Select('Sample2.parent_field', cases={
                        Uint8(0xaa): Uint8,
                        Uint8(0xbb): Uint16,
                    }), 'child_field')
                ])

            class Sample2(StructMeta):
                struct = Members([
                    Member(Uint8, 'parent_field'),
                    Member(Sample1, 'fragment')
                ])

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

            class Sample1(StructMeta):
                struct = Members([
                    Member(Select('Sample3.parent_fieldA', cases={
                        Uint8(0xaa): Uint8,
                        Uint8(0xbb): Uint16,
                    }), 'child_field')
                ])

            class Sample2(StructMeta):
                struct = Members([
                    Member(Uint8, 'parent_fieldB'),
                    Member(Sample1, 'fragment')
                ])

            class Sample3(StructMeta):
                struct = Members([
                    Member(Uint8, 'parent_fieldA'),
                    Member(Sample2, 'fragment')
                ])

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

            class Sample1(StructMeta):
                struct = Members([
                    Member(Select('UnknownClass.parent_field', cases={
                        Uint8(0xaa): Uint8,
                        Uint8(0xbb): Uint16,
                    }), 'child_field')
                ])

            class Sample2(StructMeta):
                struct = Members([
                    Member(Uint8, 'parent_field'),
                    Member(Sample1, 'fragment')
                ])

            s1_byte = bytes.fromhex('aa ff')

            with self.assertRaisesRegex(Exception, 'UnknownClass') as cm:
                a = Sample2.from_bytes(bytes(s1_byte))

        def test_structmeta_invalid_switch(self):

            with self.assertRaisesRegex(Exception, 'Select') as cm:
                class Sample1(StructMeta):
                    struct = Members([
                        Member(Select('.parent_field', cases={
                            Uint8(0xaa): Uint8,
                            Uint8(0xbb): Uint16,
                        }), 'child_field')
                    ])

            with self.assertRaisesRegex(Exception, 'Select') as cm:
                class Sample2(StructMeta):
                    struct = Members([
                        Member(Select('Handshake#parent_field', cases={
                            Uint8(0xaa): Uint8,
                            Uint8(0xbb): Uint16,
                        }), 'child_field')
                    ])

    unittest.main()
