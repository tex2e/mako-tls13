
from type import Uint16, Opaque, List
import structmeta as meta

from protocol_ext_supportedgroups import NamedGroup

OpaqueUint16 = Opaque(Uint16)

@meta.struct
class KeyShareEntry(meta.StructMeta):
    group: NamedGroup
    key_exchange: OpaqueUint16

KeyShareEntrys = List(size_t=Uint16, elem_t=KeyShareEntry)

@meta.struct
class KeyShareClientHello(meta.StructMeta):
    client_shares: KeyShareEntrys

@meta.struct
class KeyShareServerHello(meta.StructMeta):
    server_share: KeyShareEntry


if __name__ == '__main__':
    import unittest

    class TestUnit(unittest.TestCase):

        def test_keyshare_clienthello(self):

            ksch = KeyShareClientHello(
                client_shares=KeyShareEntrys([
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

            ksch_byte = bytes.fromhex('0010 001d 0004 01234567 0017 0004 89abcdef')
            self.assertEqual(bytes(ksch), ksch_byte)
            self.assertEqual(KeyShareClientHello.from_bytes(bytes(ksch)), ksch)

        def test_keyshare_serverhello(self):

            ksch = KeyShareServerHello(
                server_share=KeyShareEntry(
                    group=NamedGroup.x25519,
                    key_exchange=OpaqueUint16(bytes.fromhex('01234567'))
                )
            )

            ksch_byte = bytes.fromhex('001d 0004 01234567')
            self.assertEqual(bytes(ksch), ksch_byte)
            self.assertEqual(KeyShareServerHello.from_bytes(bytes(ksch)), ksch)

    unittest.main()
