# ------------------------------------------------------------------------------
# Key Share
#   - RFC 8446 #section-4.2.8
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
# ------------------------------------------------------------------------------

from metatype import Uint16, OpaqueUint16, List
import metastruct as meta
from protocol_types import HandshakeType
from protocol_ext_supportedgroups import NamedGroup

### KeyShareEntry ###
# struct {
#     NamedGroup group;
#     opaque key_exchange<1..2^16-1>;
# } KeyShareEntry;
#
@meta.struct
class KeyShareEntry(meta.MetaStruct):
    group: NamedGroup
    key_exchange: OpaqueUint16

KeyShareEntrys = List(size_t=Uint16, elem_t=KeyShareEntry)

### KeyShareClientHello / KeyShareServerHello ###
# struct {
#     KeyShareEntry client_shares<0..2^16-1>;
# } KeyShareClientHello;
#
# struct {
#     KeyShareEntry server_share;
# } KeyShareServerHello;
#
@meta.struct
class KeyShareHello(meta.MetaStruct):
    shares: meta.Select('Handshake.msg_type', cases={
        HandshakeType.client_hello: KeyShareEntrys,
        HandshakeType.server_hello: KeyShareEntry,
    })


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    import unittest

    class TestUnit(unittest.TestCase):

        def test_keyshare_clienthello(self):

            @meta.struct
            class Handshake(meta.MetaStruct):
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
            class Handshake(meta.MetaStruct):
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
