
from type import Uint16
import structmeta as meta

from protocol_types import ContentType
from protocol_handshake import Handshake

# ------------------------------------------------------------------------------
# Record Layer

ProtocolVersion = Uint16

@meta.struct
class TLSPlaintext(meta.StructMeta):
    type: ContentType
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(self.fragment))
    fragment: meta.Select('type', cases={
        ContentType.handshake: Handshake,
    })

if __name__ == '__main__':

    from type import Uint24
    from protocol_hello import \
        ClientHello, Random, OpaqueUint8, CipherSuites, CipherSuite, Extensions
    from protocol_handshake import Handshake, HandshakeType

    import unittest

    class TestUint(unittest.TestCase):

        def test_recordlayer(self):

            ch = ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            )

            h = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=ch)

            plain = TLSPlaintext(
                type=ContentType.handshake,
                fragment=h)

            self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

    unittest.main()
