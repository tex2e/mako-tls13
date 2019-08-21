
import io # バイトストリーム操作
import textwrap # テキストの折り返しと詰め込み
from type import Type
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
    def __init__(self, **kwargs):
        self.__class__.struct.set_props(self, **kwargs)

    def __bytes__(self):
        f = io.BytesIO()
        for member in self.get_struct().get_members():
            name = member.get_name()
            elem = getattr(self, name)
            f.write(bytes(elem))
        return f.getvalue()

    @classmethod
    def from_fs(cls, fs):
        dict = {}
        for member in cls.get_struct().get_members():
            name = member.get_name()
            elem_t = member.get_type()
            # 型がSelectのときは、状況に応じて型が変わる
            if isinstance(elem_t, Select):
                # 既に格納した値(typeなど)から型を決定する場合
                if elem_t.is_depend_on_props():
                    value = dict.get(elem_t.switch)
                # クラス変数の値から型を決定する場合
                elif elem_t.is_depend_on_class():
                    value = getattr(cls, elem_t.switch)
                elem_t = elem_t.select_type(value)
            elem = elem_t.from_fs(fs)
            dict[name] = elem
        return cls(**dict)

    @classmethod
    def get_struct(cls):
        return cls.struct

    def __repr__(self):
        # 出力は次のようにする
        # 1. 各要素を表示するときは次のようにし、出力幅が80を超えないようにする
        #     + 要素名: 型(値)
        # 2. 要素もStructMetaのときは、次のようにする。
        #     + 要素名: StructMeta名:
        #       + 要素: 型(値)...
        title = "%s:\n" % self.__class__.__name__
        elems = []
        for member in self.get_struct().get_members():
            name = member.get_name()
            elem = getattr(self, name)
            content = repr(elem)
            output = '%s: %s' % (name, content)
            # 要素のStructMetaは出力が複数行になるので、その要素をインデントさせる
            if isinstance(elem, StructMeta):
                output = textwrap.indent(output, prefix="  ").strip()
            # その他の要素は出力が1行になるので、コンソールの幅を超えないように出力させる
            else:
                output = '\n  '.join(textwrap.wrap(output, width=70))
            elems.append('+ ' + output)
        return title + "\n".join(elems)

    def __eq__(self, other):
        self_members  = self.get_struct().get_members()
        other_members = other.get_struct().get_members()
        if len(self_members) != len(other_members):
            return False
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
        self.type = type # class
        self.name = name # str
        self.default = default # default value

    def get_type(self):
        return self.type

    def get_name(self):
        return self.name

    # キーワード引数で与えられなかった時に呼び出される。
    # 普通は .default の値を返すが、.default がラムダ関数であれば、評価した値を返す。
    # ラムダ関数を評価する際は、キーワード引数から導出するもの(例えば length など)があるので、
    # キーワード引数の辞書をラムダの引数として与える。
    def get_default(self, args_dict=None):
        # ラムダのときは、ラムダを評価した値をデフォルト値として返す。
        if callable(self.default):
            return self.default(args_dict)
        # それ以外のときは、設定したデフォルト値を返す。
        return self.default

# 構造体の要素の集合を表すクラス
class Members:
    def __init__(self, members=[]):
        self.members = members # array

    def get_members(self):
        return self.members

    # メタ構造を元に与えられた引数をthisのプロパティとして格納する。
    def set_props(self, this, **kwargs):
        assert isinstance(this, StructMeta)
        for member in self.get_members():
            name = member.get_name()
            if name in kwargs.keys():
                value = kwargs.get(name)
            else:
                value = member.get_default(kwargs)
            setattr(this, name, value)
        return self

# 状況に応じて型を選択するためのクラス
class Select:
    def __init__(self, switch, cases, depend_on_class=False):
        assert isinstance(switch, str)
        assert isinstance(cases, dict)
        self.switch = switch
        self.cases = cases
        self.depend_on_class = depend_on_class

    def select_type(self, switch_value):
        return self.cases.get(switch_value)

    def is_depend_on_props(self):
        return not self.depend_on_class

    def is_depend_on_class(self):
        return self.depend_on_class


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

        def test_structmeta_select_depend_on_props(self):

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

        def test_structmeta_select_depend_on_class(self):

            def Sample1(peer_name):

                class Sample1(StructMeta):
                    peer_name = None # 'client' or 'server'
                    struct = Members([
                        Member(Select('peer_name', depend_on_class=True, cases={
                            'client': Uint8,
                            'server': Uint16,
                        }), 'fragment')
                    ])

                Sample1.peer_name = peer_name
                return Sample1

            SampleClient = Sample1('client')
            SampleServer = Sample1('server')

            s1 = SampleClient(fragment=Uint8(0x01))
            s2 = SampleClient(fragment=Uint16(0x0112))
            s1_byte = b'\x01'
            s2_byte = b'\x01\x12'

            self.assertEqual(bytes(s1), s1_byte)
            self.assertEqual(bytes(s2), s2_byte)

            self.assertEqual(SampleClient.from_bytes(s1_byte), s1)
            self.assertEqual(SampleServer.from_bytes(s2_byte), s2)


    unittest.main()
