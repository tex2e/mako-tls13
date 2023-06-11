# protocol_recordlayer.pyの単体テスト
# python -m unittest -v tests.test_protocol_recordlayer

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_recordlayer import *
from metatype import Uint24
from protocol_hello import \
    ClientHello, ServerHello, \
    Random, Opaque1, OpaqueUint8, CipherSuites, CipherSuite, Extensions
from protocol_handshake import Handshake, HandshakeType

class TestUint(unittest.TestCase):

    def test_recordlayer(self):

        h = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            ))

        plain = TLSPlaintext(
            type=ContentType.handshake,
            fragment=OpaqueLength(bytes(h)))

        plain_bytes = bytes.fromhex('''
            16 03 03 00 53 01 00 00  4F 03 03 AA AA AA AA AA
            AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA
            AA AA AA AA AA AA AA AA  AA AA AA 20 BB BB BB BB
            BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB
            BB BB BB BB BB BB BB BB  BB BB BB BB 00 06 13 02
            13 03 00 FF 01 00 00 00
        ''')

        self.assertEqual(bytes(plain), plain_bytes)
        self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

        messages = plain.get_messages()
        self.assertEqual(messages[0], h)

    def test_recordlayer_multiple_messages(self):

        h1 = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            ))
        h2 = Handshake(
            msg_type=HandshakeType.server_hello,
            msg=ServerHello(
                random=Random(bytes.fromhex('CC' * 32)),
                legacy_session_id_echo=OpaqueUint8(bytes.fromhex('DD' * 32)),
                cipher_suite=CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                legacy_compression_method=Opaque1(b'\x00'),
                extensions=Extensions([]),
            ))

        plain = TLSPlaintext(
            type=ContentType.handshake,
            fragment=OpaqueLength(bytes(h1) + bytes(h2)))

        plain_bytes = bytes.fromhex('''
            16 03 03 00 9F
            01 00 00 4F 03 03 AA AA  AA AA AA AA AA AA AA AA
            AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA
            AA AA AA AA AA AA 20 BB  BB BB BB BB BB BB BB BB
            BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB
            BB BB BB BB BB BB BB 00  06 13 02 13 03 00 FF 01
            00 00 00
            02 00 00 48 03 03 CC CC  CC CC CC CC CC CC CC CC
            CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC
            CC CC CC CC CC CC 20 DD  DD DD DD DD DD DD DD DD
            DD DD DD DD DD DD DD DD  DD DD DD DD DD DD DD DD
            DD DD DD DD DD DD DD 13  03 00 00 00
        ''')

        self.assertEqual(bytes(plain), plain_bytes)
        self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

        messages = plain.get_messages()
        self.assertEqual(messages[0], h1)
        self.assertEqual(messages[1], h2)


if __name__ == '__main__':
    unittest.main()
