
from type import Uint16, OpaqueUint16, List
import structmeta as meta

from protocol_types import HandshakeType
from protocol_ext_supportedgroups import NamedGroup

@meta.struct
class KeyShareEntry(meta.StructMeta):
    group: NamedGroup
    key_exchange: OpaqueUint16

KeyShareEntrys = List(size_t=Uint16, elem_t=KeyShareEntry)

@meta.struct
class KeyShareHello(meta.StructMeta):
    shares: meta.Select('Handshake.msg_type', cases={
        HandshakeType.client_hello: KeyShareEntrys,
        HandshakeType.server_hello: KeyShareEntry,
    })


if __name__ == '__main__':
    import unittest

    class TestUnit(unittest.TestCase):

        def test_keyshare_clienthello(self):

            @meta.struct
            class Handshake(meta.StructMeta):
                msg_type: HandshakeType = HandshakeType.client_hello
                fragment: KeyShareHello

            handshake = Handshake(
                fragment=KeyShareHello(
                    shares=KeyShareEntrys([
                        KeyShareEntry(
                            group=NamedGroup.x25519,
                            key_exchange=OpaqueUint16(bytes.fromhex('01234567'))
                        ),
                        KeyShareEntry(
                            group=NamedGroup.secp256r1,
                            key_exchange=OpaqueUint16(bytes.fromhex('89abcdef'))
                        )
                    ])
                )
            )
            ksh = handshake.fragment
            ksh_byte = bytes.fromhex('0010 001d 0004 01234567 0017 0004 89abcdef')
            self.assertEqual(bytes(ksh), ksh_byte)
            self.assertEqual(Handshake.from_bytes(bytes(handshake)), handshake)

        def test_keyshare_serverhello(self):

            @meta.struct
            class Handshake(meta.StructMeta):
                msg_type: HandshakeType = HandshakeType.server_hello
                fragment: KeyShareHello

            handshake = Handshake(
                fragment=KeyShareHello(
                    shares=KeyShareEntry(
                        group=NamedGroup.x25519,
                        key_exchange=OpaqueUint16(bytes.fromhex('01234567'))
                    )
                )
            )
            ksh = handshake.fragment
            ksh_byte = bytes.fromhex('001d 0004 01234567')
            self.assertEqual(bytes(ksh), ksh_byte)
            self.assertEqual(Handshake.from_bytes(bytes(handshake)), handshake)

    unittest.main()
