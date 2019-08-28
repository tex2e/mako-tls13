
from type import Uint16, List, Enum
from crypto_chacha20poly1305 import Chacha20Poly1305

class CipherSuite(Enum):
    elem_t = Uint16

    TLS_AES_128_GCM_SHA256       = Uint16(0x1301)
    TLS_AES_256_GCM_SHA384       = Uint16(0x1302)
    TLS_CHACHA20_POLY1305_SHA256 = Uint16(0x1303)
    TLS_AES_128_CCM_SHA256       = Uint16(0x1304)
    TLS_AES_128_CCM_8_SHA256     = Uint16(0x1305)
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = Uint16(0x00FF)

    @classmethod
    def get_cipher_class(cls, cipher_suite):
        ciphercuite2class = {
            CipherSuite.TLS_AES_128_GCM_SHA256: None,
            CipherSuite.TLS_AES_256_GCM_SHA384: None,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256: Chacha20Poly1305,
            CipherSuite.TLS_AES_128_CCM_SHA256: None,
            CipherSuite.TLS_AES_128_CCM_8_SHA256: None,
        }
        return ciphercuite2class.get(cipher_suite)

    @classmethod
    def get_hash_name(cls, cipher_suite):
        if cipher_suite == CipherSuite.TLS_AES_256_GCM_SHA384:
            return 'sha384'
        else:
            return 'sha256'

    @classmethod
    def get_hash_size(cls, cipher_suite):
        if cipher_suite == CipherSuite.TLS_AES_256_GCM_SHA384:
            return 48
        else:
            return 32

CipherSuites = List(size_t=Uint16, elem_t=CipherSuite)
