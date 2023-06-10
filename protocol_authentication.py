
from metatype import Uint8, Uint16, Uint24, Opaque, List, Enum, \
    OpaqueUint8, OpaqueUint16, OpaqueUint24
import metastruct as meta

from protocol_extensions import Extensions, Extension
from protocol_ext_signature import SignatureScheme

# --- Certificate --------------------------------------------------------------

class CertificateType(Enum):
    elem_t = Uint8

    X509 = Uint8(0)
    RawPublicKey = Uint8(2)

@meta.struct
class CertificateEntry(meta.MetaStruct):
    cert_data: OpaqueUint24
    extensions: Extensions

CertificateEntrys = List(size_t=Uint24, elem_t=CertificateEntry)

@meta.struct
class Certificate(meta.MetaStruct):
    certificate_request_context: OpaqueUint8
    certificate_list: CertificateEntrys

@meta.struct
class CertificateVerify(meta.MetaStruct):
    algorithm: SignatureScheme
    signature: OpaqueUint16

# --- Finished -----------------------------------------------------------------

### TLS Finished ###

class Hash:
    length = None

OpaqueHash = Opaque(lambda self: Hash.length)

@meta.struct
class Finished(meta.MetaStruct):
    verify_data: OpaqueHash


### QUIC Finished ###

@meta.struct
class FinishedQuic(meta.MetaStruct):
    verify_data: OpaqueUint24

def replace_to_quic_finished():
    global Finished
    Finished = FinishedQuic


# ------------------------------------------------------------------------------
if __name__ == '__main__':

    import unittest

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

        # def test_finished_to_bytes(self):
        #
        #     finished = Finished(verify_data=OpaqueHash(b'\xAA' * 32))
        #     finished_byte = b'\xAA' * 32
        #     self.assertEqual(bytes(finished), finished_byte)

        # def test_finished_from_bytes(self):
        #     finished = Finished(verify_data=OpaqueHash(b'\xAA' * 32))
        #
        #     with self.assertRaises(Exception) as cm:
        #         Finished.from_bytes(bytes(finished))
        #
        #     Hash.length = 32
        #     finished2 = Finished.from_bytes(bytes(finished))
        #     self.assertEqual(finished, finished2)


    unittest.main()
