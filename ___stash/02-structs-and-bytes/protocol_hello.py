
import os
from type import Uint8, Uint16, Opaque, OpaqueUint8, List
import structmeta as meta

from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extension, Extensions

# ------------------------------------------------------------------------------
# Key Exchange Layer

ProtocolVersion = Uint16
Random = Opaque(32)
Opaque1 = Opaque(1)

@meta.struct
class ClientHello(meta.StructMeta):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suites: CipherSuites
    legacy_compression_methods: OpaqueUint8 = OpaqueUint8(b'\x00')
    extensions: Extensions

@meta.struct
class ServerHello(meta.StructMeta):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id_echo: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suite: CipherSuite
    legacy_compression_method: Opaque1 = Opaque1(b'\x00')
    extensions: Extensions


if __name__ == '__main__':
    import unittest

    class TestUint(unittest.TestCase):

        def test_clienthello(self):

            ch = ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            )

            expected = bytes.fromhex(
                '03 03 AA AA AA AA AA AA  AA AA AA AA AA AA AA AA'
                'AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA'
                'AA AA 20 BB BB BB BB BB  BB BB BB BB BB BB BB BB'
                'BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB'
                'BB BB BB 00 08 13 02 13  03 13 01 00 FF 01 00 00'
                '00                                              ')

            self.assertEqual(bytes(ch), expected)
            self.assertEqual(ClientHello.from_bytes(bytes(ch)), ch)

        def test_serverhello(self):

            sh = ServerHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id_echo=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suite=CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                legacy_compression_method=Opaque1(b'\x00'),
                extensions=Extensions([]),
            )

            expected = bytes.fromhex(
                '03 03 AA AA AA AA AA AA  AA AA AA AA AA AA AA AA'
                'AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA'
                'AA AA 20 BB BB BB BB BB  BB BB BB BB BB BB BB BB'
                'BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB'
                'BB BB BB 13 03 00 00 00                         ')

            self.assertEqual(bytes(sh), expected)
            self.assertEqual(ServerHello.from_bytes(bytes(sh)), sh)

        def test_clienthello_has_extensions(self):

            from protocol_extensions import ExtensionType
            from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup

            ch = ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=NamedGroups([
                                NamedGroup.x25519, NamedGroup.secp256r1,
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=NamedGroups([
                                NamedGroup.x25519, NamedGroup.secp256r1,
                            ])
                        )
                    ),
                ]),
            )

            self.assertEqual(ClientHello.from_bytes(bytes(ch)), ch)

    unittest.main()
