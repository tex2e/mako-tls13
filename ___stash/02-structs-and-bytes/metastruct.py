
import abc # 抽象基底クラス
import io # バイトストリーム操作
from type import Uint8, Uint16, Opaque, List
from disp import hexdump

# TLSメッセージの構造体を表すためのクラス群
# 使い方：
#
#   class ClientHello(MetaStruct):
#     struct = Members([
#       Member(ProtocolVersion, 'legacy_version'),
#       Member(Random, 'random'),
#       Member(Opaque(size_t=Uint8), 'legacy_session_id'),
#       Member(List(size_t=Uint16, elem_t=CipherSuite), 'cipher_suites'),
#       Member(List(size_t=Uint16, elem_t=Uint8), 'legacy_compression_methods'),
#       Member(List(size_t=Uint16, elem_t=Extension), 'extensions'),
#     ])
#

class MetaStruct(abc.ABC):
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
    def from_bytes(cls, data):
        pass
        # TODO:

    def __repr__(self):
        title = "%s:\n" % self.__class__.__name__
        elems = []
        for member in self.get_struct().get_members():
            name = member.get_name()
            elem = getattr(self, name)
            elems.append('+ %s: %s' % (name, repr(elem)))
        return title + "\n".join(elems)

    def get_struct(self):
        return self._struct

    def set_struct(self, struct):
        self._struct = struct

class Member:
    def __init__(self, type, name, default=None):
        self.type = type # class
        self.name = name # str
        self.default = default # default value

    def get_name(self):
        return self.name

    def get_default(self):
        return self.default

class Members:
    def __init__(self, members=[]):
        self.members = members # array

    def get_members(self):
        return self.members

    def set_args(self, this, **kwargs):
        assert(isinstance(this, MetaStruct))
        # this == instance pointer (self)
        for member in self.get_members():
            name = member.get_name()
            if name in kwargs.keys():
                value = kwargs.get(name)
            else:
                value = member.get_default()
            setattr(this, name, value)
        return self


if __name__ == '__main__':

    ProtocolVersion = Uint16
    Random = Opaque(32)
    OpaqueUint8 = Opaque(size_t=Uint8)
    CipherSuite = Uint16
    CipherSuites = List(size_t=Uint16, elem_t=CipherSuite)
    Extensions = List(size_t=Uint16, elem_t=Opaque(0))

    class ClientHello(MetaStruct):
        struct = Members([
            Member(ProtocolVersion, 'legacy_version', ProtocolVersion(0x0303)),
            Member(Random, 'random'),
            Member(OpaqueUint8, 'legacy_session_id'),
            Member(CipherSuites, 'cipher_suites'),
            Member(OpaqueUint8, 'legacy_compression_methods'),
            Member(Extensions, 'extensions', Extensions([]))
        ])

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

    print("---")
    print(ch)
    print("---")
    print(hexdump(bytes(ch)))


    import unittest

    class TestUint(unittest.TestCase):

        def test_metastruct(self):

            OpaqueUint8 = Opaque(size_t=Uint8)
            ListUint8OpaqueUint8 = List(size_t=Uint8, elem_t=Opaque(size_t=Uint8))

            class Sample1(MetaStruct):
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

        def test_clienthello(self):

            ProtocolVersion = Uint16
            Random = Opaque(32)
            OpaqueUint8 = Opaque(size_t=Uint8)
            CipherSuite = Uint16
            CipherSuites = List(size_t=Uint16, elem_t=CipherSuite)
            Extensions = List(size_t=Uint16, elem_t=Opaque(0))

            class ClientHello(MetaStruct):
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

    unittest.main()
