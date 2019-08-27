
from type import Uint8, Uint16, Uint24, Opaque, List, Enum
import structmeta as meta

from protocol_types import HandshakeType
from protocol_hello import ClientHello, ServerHello
from protocol_extensions import EncryptedExtensions
from protocol_authentication import Certificate, CertificateVerify, Finished
from protocol_ticket import NewSessionTicket

# ------------------------------------------------------------------------------
# Handshake Layer

@meta.struct
class Handshake(meta.StructMeta):
    msg_type: HandshakeType
    length: Uint24 = lambda self: Uint24(len(bytes(self.msg)))
    msg: meta.Select('msg_type', cases={
        HandshakeType.client_hello: ClientHello,
        HandshakeType.server_hello: ServerHello,
        HandshakeType.encrypted_extensions: EncryptedExtensions,
        HandshakeType.certificate: Certificate,
        HandshakeType.certificate_verify: CertificateVerify,
        HandshakeType.finished: Finished,
        HandshakeType.new_session_ticket: NewSessionTicket,
    })


if __name__ == '__main__':

    from protocol_hello import Random, OpaqueUint8, CipherSuite, CipherSuites
    from protocol_extensions import ExtensionType, Extensions, Extension

    import unittest

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

    unittest.main()
