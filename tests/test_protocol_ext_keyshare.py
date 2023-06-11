# protocol_ext_keyshare.pyの単体テスト
# python -m unittest -v tests.test_protocol_ext_keyshare

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_ext_keyshare import *

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


if __name__ == '__main__':
    unittest.main()
