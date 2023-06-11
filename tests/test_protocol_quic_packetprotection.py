# protocol_quic_packetprotection.pyの単体テスト
# python -m unittest -v tests.test_protocol_quic_packetprotection

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_quic_packetprotection import *

class TestUint(unittest.TestCase):

    def test_enc_dec_payload(self):
        plaintext_payload = b'\x01\x02\x03\x04\x05' + (b'\x00' * 30)
        cs_key = b'\x11' * 16
        cs_iv  = b'\x22' * 12
        aad    = b'unittest label'
        packet_number = 999999
        tmp = encrypt_payload(plaintext_payload, cs_key, cs_iv, aad, packet_number)
        tmp = decrypt_payload(tmp,               cs_key, cs_iv, aad, packet_number)
        self.assertEqual(tmp, plaintext_payload)

if __name__ == '__main__':
    unittest.main()
