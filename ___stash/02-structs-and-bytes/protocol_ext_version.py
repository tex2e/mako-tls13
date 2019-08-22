
from type import Uint8, Uint16, Opaque, List, Enum
from structmeta import StructMeta, Members, Member, Select

from protocol_types import HandshakeType

class ProtocolVersion(Enum):
    elem_t = Uint16

    SSL3  = Uint16(0x0300)
    TLS10 = Uint16(0x0301)
    TLS11 = Uint16(0x0302)
    TLS12 = Uint16(0x0303)
    TLS13 = Uint16(0x0304)

ProtocolVersions = List(size_t=Uint8, elem_t=ProtocolVersion)

class SupportedVersions(StructMeta):
    struct = Members([
        Member(Select('Handshake.msg_type', cases={
            HandshakeType.client_hello: List(size_t=Uint8, elem_t=ProtocolVersion),
            HandshakeType.server_hello: ProtocolVersion,
        }), 'version'),
    ])


if __name__ == '__main__':

    from protocol_handshake import Handshake

    import unittest

    class TestUint(unittest.TestCase):

        def test_ext_supported_versions_client_hello(self):

            class Handshake(StructMeta):
                struct = Members([
                    Member(HandshakeType, 'msg_type'),
                    Member(SupportedVersions, 'msg'),
                ])

            h = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=SupportedVersions(version=ProtocolVersions([
                    ProtocolVersion.TLS13, ProtocolVersion.TLS12,
                    ProtocolVersion.TLS11,
                ])),)

            self.assertEqual(bytes(h), bytes.fromhex('01 06 0304 0303 0302'))
            self.assertEqual(Handshake.from_bytes(bytes(h)), h)

        def test_ext_supported_versions_server_hello(self):

            class Handshake(StructMeta):
                struct = Members([
                    Member(HandshakeType, 'msg_type'),
                    Member(SupportedVersions, 'msg'),
                ])

            h = Handshake(
                msg_type=HandshakeType.server_hello,
                msg=SupportedVersions(version=ProtocolVersion.TLS13),)

            self.assertEqual(bytes(h), bytes.fromhex('02 0304'))
            self.assertEqual(Handshake.from_bytes(bytes(h)), h)

    unittest.main()
