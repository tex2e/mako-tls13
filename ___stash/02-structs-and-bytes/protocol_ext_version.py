
from type import Uint8, Uint16, List, Enum
import structmeta as meta

from protocol_types import HandshakeType

class ProtocolVersion(Enum):
    elem_t = Uint16

    SSL3  = Uint16(0x0300)
    TLS10 = Uint16(0x0301)
    TLS11 = Uint16(0x0302)
    TLS12 = Uint16(0x0303)
    TLS13 = Uint16(0x0304)

ProtocolVersions = List(size_t=Uint8, elem_t=ProtocolVersion)

@meta.struct
class SupportedVersions(meta.StructMeta):
    versions: meta.Select('Handshake.msg_type', cases={
        HandshakeType.client_hello: ProtocolVersions,
        HandshakeType.server_hello: ProtocolVersion,
    })


if __name__ == '__main__':

    from protocol_handshake import Handshake

    import unittest

    class TestUint(unittest.TestCase):

        def test_ext_supported_versions_client_hello(self):

            @meta.struct
            class Handshake(meta.StructMeta):
                msg_type: HandshakeType
                msg: SupportedVersions

            h = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=SupportedVersions(versions=ProtocolVersions([
                    ProtocolVersion.TLS13, ProtocolVersion.TLS12,
                    ProtocolVersion.TLS11,
                ])),)

            self.assertEqual(bytes(h), bytes.fromhex('01 06 0304 0303 0302'))
            self.assertEqual(Handshake.from_bytes(bytes(h)), h)

        def test_ext_supported_versions_server_hello(self):

            @meta.struct
            class Handshake(meta.StructMeta):
                msg_type: HandshakeType
                msg: SupportedVersions

            h = Handshake(
                msg_type=HandshakeType.server_hello,
                msg=SupportedVersions(versions=ProtocolVersion.TLS13),)

            self.assertEqual(bytes(h), bytes.fromhex('02 0304'))
            self.assertEqual(Handshake.from_bytes(bytes(h)), h)

    unittest.main()
