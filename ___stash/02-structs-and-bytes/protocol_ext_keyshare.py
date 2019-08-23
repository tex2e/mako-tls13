
from type import Uint16, Opaque, List
from structmeta import StructMeta, Members, Member

from protocol_ext_supportedgroups import NamedGroup

OpaqueUint16 = Opaque(Uint16)

class KeyShareEntry(StructMeta):
    struct = Members([
        Member(NamedGroup, 'group'),
        Member(OpaqueUint16, 'key_exchange')
    ])

KeyShareEntrys = List(size_t=Uint16, elem_t=KeyShareEntry)

class KeyShareClientHello(StructMeta):
    struct = Members([
        Member(KeyShareEntrys, 'client_shares'),
    ])

class KeyShareServerHello(StructMeta):
    struct = Members([
        Member(KeyShareEntry, 'server_share'),
    ])


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
