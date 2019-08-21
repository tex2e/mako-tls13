
from type import Uint8, Uint16, Uint24, Opaque, List, Enum
from structmeta import StructMeta, Members, Member, Select

from protocol_keyexchange import ClientHello

# ------------------------------------------------------------------------------
# Handshake Layer

class HandshakeType(Enum):
    elem_t = Uint8

    hello_request_RESERVED = Uint8(0)
    client_hello = Uint8(1)
    server_hello = Uint8(2)
    hello_verify_request_RESERVED = Uint8(3)
    new_session_ticket = Uint8(4)
    end_of_early_data = Uint8(5)
    hello_retry_request_RESERVED = Uint8(6)
    encrypted_extensions = Uint8(8)
    certificate = Uint8(11)
    server_key_exchange_RESERVED = Uint8(12)
    certificate_request = Uint8(13)
    server_hello_done_RESERVED = Uint8(14)
    certificate_verify = Uint8(15)
    client_key_exchange_RESERVED = Uint8(16)
    finished = Uint8(20)
    key_update = Uint8(24)
    message_hash = Uint8(254)

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
