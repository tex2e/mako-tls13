
from type import Uint16, List, Enum
import structmeta as meta

class SignatureScheme(Enum):
    elem_t = Uint16

    # RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = Uint16(0x0401)
    rsa_pkcs1_sha384 = Uint16(0x0501)
    rsa_pkcs1_sha512 = Uint16(0x0601)

    # ECDSA algorithms
    ecdsa_secp256r1_sha256 = Uint16(0x0403)
    ecdsa_secp384r1_sha384 = Uint16(0x0503)
    ecdsa_secp512r1_sha512 = Uint16(0x0603)

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = Uint16(0x0804)
    rsa_pss_rsae_sha384 = Uint16(0x0805)
    rsa_pss_rsae_sha512 = Uint16(0x0806)

    # EdDSA algorithms
    ed25519 = Uint16(0x0807)
    ed448 = Uint16(0x0808)

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = Uint16(0x0809)
    rsa_pss_pss_sha384 = Uint16(0x080a)
    rsa_pss_pss_sha512 = Uint16(0x080b)

    # Legacy algorithms
    rsa_pkcs1_sha1 = Uint16(0x0201)
    ecdsa_sha1 = Uint16(0x0203)

    # Reserved Code Points
    # private_use = Uint16(0xFE00)..Uint16(0xFFFF)

SignatureSchemes = List(size_t=Uint16, elem_t=SignatureScheme)

@meta.struct
class SignatureSchemeList(meta.StructMeta):
    supported_signature_algorithms: SignatureSchemes
