
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
        self.set_struct(self.__class__.struct.set_args(self, **kwargs))

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
        for member in cls.get_structmeta().get_members():
            name = member.get_name()
            elem = member.get_type().from_fs(fs)
            dict[name] = elem
        return cls(**dict)

    # 構造体のメタ情報は class.struct に格納する
    @classmethod
    def get_structmeta(cls):
        return cls.struct

    # 構造体に値を代入したものは self._struct に格納する
    def get_struct(self):
        return self._struct

    def set_struct(self, mystruct):
        self._struct = mystruct

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
        return self.get_struct() == other.get_struct()

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

    def get_default(self):
        return self.default

# 構造体の要素の集合を表すクラス
class Members:
    def __init__(self, members=[]):
        self.members = members # array

    def get_members(self):
        return self.members

    # メタ構造を元に与えられた引数を自身のプロパティとして保存する
    def set_args(self, this, **kwargs):
        assert isinstance(this, StructMeta)
        for member in self.get_members():
            name = member.get_name()
            if name in kwargs.keys():
                value = kwargs.get(name)
            else:
                value = member.get_default()
            setattr(this, name, value)
        return self

class Select:
    def __init__(self, switch, cases):
        assert isinstance(switch, str)
        assert isinstance(cases, dict)
        self.switch = switch
        self.cases = cases


if __name__ == '__main__':

    from type import Uint8, Uint16, Opaque, List
    import unittest

    class TestUint(unittest.TestCase):

        def test_metastruct(self):

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

        def test_metastruct_recursive(self):

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

        def test_metastruct_keep_rest_bytes(self):
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

        def test_clienthello(self):

            ProtocolVersion = Uint16
            Random = Opaque(32)
            OpaqueUint8 = Opaque(size_t=Uint8)
            CipherSuite = Uint16
            CipherSuites = List(size_t=Uint16, elem_t=CipherSuite)
            Extensions = List(size_t=Uint16, elem_t=Opaque(0))

            class ClientHello(StructMeta):
                struct = Members([
                    Member(ProtocolVersion, 'legacy_version', ProtocolVersion(0x0303)),
                    Member(Random, 'random'),
                    Member(OpaqueUint8, 'legacy_session_id'),
                    Member(CipherSuites, 'cipher_suites'),
                    Member(OpaqueUint8, 'legacy_compression_methods'),
                    Member(Extensions, 'extensions', Extensions([]))
                ])
                def __init__(self, **kwargs):
                    self.set_struct(ClientHello.struct.set_args(self, **kwargs))

            ch = ClientHello(
                random=Random(bytes.fromhex(
                    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')),
                legacy_session_id=OpaqueUint8(bytes.fromhex(
                    'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB')),
                cipher_suites=CipherSuites([
                    CipherSuite(0x1302), CipherSuite(0x1303),
                    CipherSuite(0x1301), CipherSuite(0x00ff)]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            )

            expected = bytes.fromhex(
                '03 03 AA AA AA AA AA AA  AA AA AA AA AA AA AA AA' \
                'AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA' \
                'AA AA 20 BB BB BB BB BB  BB BB BB BB BB BB BB BB' \
                'BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB' \
                'BB BB BB 00 08 13 02 13  03 13 01 00 FF 01 00 00' \
                '00                                              ' )

            self.assertEqual(bytes(ch), expected)

            ch2 = ClientHello.from_bytes(bytes(ch))
            self.assertEqual(ch, ch2)

    unittest.main()
