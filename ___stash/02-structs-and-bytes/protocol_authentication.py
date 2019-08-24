
from type import Uint8, Uint16, Uint24, Opaque, List, Enum
import structmeta as meta

from protocol_extensions import Extensions, Extension
from protocol_ext_signature import SignatureScheme

class CertificateType(Enum):
    elem_t = Uint8

    X509 = Uint8(0)
    RawPublicKey = Uint8(2)

OpaqueUint24 = Opaque(Uint24)

@meta.struct
class CertificateEntry(meta.StructMeta):
    cert_data: OpaqueUint24
    extensions: Extensions

OpaqueUint8 = Opaque(Uint8)
CertificateEntrys = List(size_t=Uint24, elem_t=CertificateEntry)

@meta.struct
class Certificate(meta.StructMeta):
    certificate_request_context: OpaqueUint8
    certificate_list: CertificateEntrys

OpaqueUint16 = Opaque(Uint16)

@meta.struct
class CertificateVerify(meta.StructMeta):
    algorithm: SignatureScheme
    signature: OpaqueUint16
