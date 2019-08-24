
from type import Uint16, List, Enum

class CipherSuite(Enum):
    elem_t = Uint16

    TLS_AES_128_GCM_SHA256       = Uint16(0x1301)
    TLS_AES_256_GCM_SHA384       = Uint16(0x1302)
    TLS_CHACHA20_POLY1305_SHA256 = Uint16(0x1303)
    TLS_AES_128_CCM_SHA256       = Uint16(0x1304)
    TLS_AES_128_CCM_8_SHA256     = Uint16(0x1305)
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = Uint16(0x00FF)

CipherSuites = List(size_t=Uint16, elem_t=CipherSuite)
