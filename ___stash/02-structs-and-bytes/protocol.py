
from enum import Enum
from type import Uint8, Uint16, Opaque, List
from structmeta import StructMeta, Members, Member

# ------------------------------------------------------------------------------
# Record Layer

class ContentType(Enum):
    size = 1
    size_t = Uint8

    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)

# ------------------------------------------------------------------------------
# Key Exchange Layer

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

class ServerHello(StructMeta):
    struct = Members([
        Member(ProtocolVersion, 'legacy_version', ProtocolVersion(0x0303)),
        Member(Random, 'random'),
        Member(OpaqueUint8, 'legacy_session_id_echo'),
        Member(CipherSuite, 'cipher_suite'),
        Member(OpaqueUint8, 'legacy_compression_methods'),
        Member(Extensions, 'extensions', Extensions([]))
    ])


if __name__ == '__main__':
    import unittest

    class TestUint(unittest.TestCase):

        def test_clienthello(self):

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
