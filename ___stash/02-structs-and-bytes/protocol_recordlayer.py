
from type import Uint8, Uint16, Opaque, List, Enum
from structmeta import StructMeta, Members, Member, Select

from protocol_types import ContentType
from protocol_handshake import Handshake

# ------------------------------------------------------------------------------
# Record Layer

ProtocolVersion = Uint16

class TLSPlaintext(StructMeta):
    struct = Members([
        Member(ContentType, 'type'),
        Member(ProtocolVersion, 'legacy_record_version', ProtocolVersion(0x0303)),
        Member(Uint16, 'length', lambda args: Uint16(len(args.get('fragment')))),
        Member(Select('type', cases={
            ContentType.handshake: Handshake,
        }), 'fragment'),
    ])

if __name__ == '__main__':

    from type import Uint24
    from protocol_hello import ClientHello
    from protocol_handshake import Handshake, HandshakeType

    import unittest

    class TestUint(unittest.TestCase):

        def test_recordlayer(self):

            Random = Opaque(32)
            OpaqueUint8 = Opaque(size_t=Uint8)
            CipherSuite = Uint16
            CipherSuites = List(size_t=Uint16, elem_t=CipherSuite)
            Extensions = List(size_t=Uint16, elem_t=Opaque(0))

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

            h = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=ch)

            plain = TLSPlaintext(
                type=ContentType.handshake,
                fragment=h)

            self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

    unittest.main()
