# protocol_authentication.pyの単体テスト
# python -m unittest -v tests.test_protocol_authentication

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_authentication import *

class TestUint(unittest.TestCase):

    def test_certificate(self):
        c = Certificate(
            certificate_request_context=OpaqueUint8(b'\xaa\xaa'),
            certificate_list=CertificateEntrys([
                CertificateEntry(
                    cert_data=OpaqueUint24(b'\xbb\xbb'),
                    extensions=Extensions([])),
                CertificateEntry(
                    cert_data=OpaqueUint24(b'\xcc\xcc'),
                    extensions=Extensions([])),
            ])
        )
        c_bytes = bytes.fromhex('''
            02 AA AA 00 00 0E 00 00  02 BB BB 00 00 00 00 02
            CC CC 00 00
        ''')

        self.assertEqual(bytes(c), c_bytes)
        self.assertEqual(Certificate.from_bytes(bytes(c)), c)

    def test_finished_to_bytes(self):
    
        finished = Finished(verify_data=OpaqueHash(b'\xAA' * 32))
        finished_byte = b'\xAA' * 32
        self.assertEqual(bytes(finished), finished_byte)

    def test_finished_from_bytes(self):
        finished = Finished(verify_data=OpaqueHash(b'\xAA' * 32))

        # suppress stdout
        import io
        sys.stderr = io.StringIO()
        with self.assertRaises(Exception) as cm:
            Finished.from_bytes(bytes(finished))
        sys.stderr = sys.__stderr__

        Hash.length = 32
        finished2 = Finished.from_bytes(bytes(finished))
        self.assertEqual(finished, finished2)

if __name__ == '__main__':
    unittest.main()