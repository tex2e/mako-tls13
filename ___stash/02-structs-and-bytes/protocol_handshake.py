
from type import Uint8, Uint16, Uint24, Opaque, List, Enum
from structmeta import StructMeta, Members, Member, Select

from protocol_types import HandshakeType
from protocol_hello import ClientHello

# ------------------------------------------------------------------------------
# Handshake Layer

class Handshake(StructMeta):
    struct = Members([
        Member(HandshakeType, 'msg_type'),
        Member(Uint24, 'length', lambda args: Uint24(len(args.get('msg')))),
        Member(Select('msg_type', cases={
            HandshakeType.client_hello: ClientHello,
        }), 'msg'),
    ])


if __name__ == '__main__':

    import unittest

    class TestUint(unittest.TestCase):

        def test_handshake(self):

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

            h2 = Handshake.from_bytes(bytes(h))
            self.assertEqual(h2, h)

    unittest.main()
