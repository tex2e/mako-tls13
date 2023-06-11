# protocol_handshake.pyの単体テスト
# python -m unittest -v tests.test_protocol_handshake

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_handshake import *
from protocol_hello import Random, OpaqueUint8, CipherSuite, CipherSuites
from protocol_extensions import ExtensionType, Extensions, Extension

class TestUint(unittest.TestCase):

    def test_handshake(self):

        h = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            ))

        h2 = Handshake.from_bytes(bytes(h))
        self.assertEqual(h2, h)

    def test_handshake_has_ext_version(self):

        from protocol_ext_version import \
            SupportedVersions, ProtocolVersions, ProtocolVersion

        h = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([
                    Extension(
                        extension_type=ExtensionType.supported_versions,
                        extension_data=SupportedVersions(
                            versions=ProtocolVersions([
                                ProtocolVersion.TLS13, ProtocolVersion.TLS12])
                        )
                    ),
                ])
            ))

        self.assertEqual(Handshake.from_bytes(bytes(h)), h)

if __name__ == '__main__':
    unittest.main()
