
import hmac
import hashlib

from type import Uint8, Uint16, Opaque
OpaqueUint8 = Opaque(Uint8)

def divceil(n, d) -> int:
    q, r = divmod(n, d)
    return q + bool(r)

def secure_hash(data, hash_name='sha256') -> bytearray:
    h = hashlib.new(hash_name)
    h.update(data)
    return bytearray(h.digest())

def secure_HMAC(key, msg, hash_name='sha256') -> bytearray:
    return bytearray(hmac.new(key, msg, getattr(hashlib, hash_name)).digest())

def HKDF_extract(salt, IKM, hash_name='sha256') -> bytearray:
    # HKDF (https://tools.ietf.org/html/rfc5869#section-2.2)
    #
    #     HKDF-Extract(salt, IKM) -> PRK
    #     Options:
    #        Hash     a hash function; HashLen denotes the length of the
    #                 hash function output in octets
    #     Inputs:
    #        salt     optional salt value (a non-secret random value);
    #                 if not provided, it is set to a string of HashLen zeros.
    #        IKM      input keying material
    #     Output:
    #        PRK      a pseudorandom key (of HashLen octets)
    #     The output PRK is calculated as follows:
    #     PRK = HMAC-Hash(salt, IKM)
    #
    return secure_HMAC(salt, IKM, hash_name)

def HKDF_expand(PRK, info, L, hash_name='sha256') -> bytearray:
    # HKDF (https://tools.ietf.org/html/rfc5869#section-2.3)
    #
    #     HKDF-Expand(PRK, info, L) -> OKM
    #     Options:
    #        Hash     a hash function; HashLen denotes the length of the
    #                 hash function output in octets
    #     Inputs:
    #        PRK      a pseudorandom key of at least HashLen octets
    #                 (usually, the output from the extract step)
    #        info     optional context and application specific information
    #                 (can be a zero-length string)
    #        L        length of output keying material in octets
    #                 (<= 255*HashLen)
    #     Output:
    #        OKM      output keying material (of L octets)
    #     The output OKM is calculated as follows:
    #     N = ceil(L/HashLen)
    #     T = T(1) | T(2) | T(3) | ... | T(N)
    #     OKM = first L octets of T
    #     where:
    #     T(0) = empty string (zero length)
    #     T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    #     T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    #     T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    #     ...
    #
    N = divceil(L, getattr(hashlib, hash_name)().digest_size)
    T      = bytearray()
    T_prev = bytearray()
    for x in range(1, N+2):
        T += T_prev
        T_prev = secure_HMAC(PRK, T_prev + info + bytearray([x]), hash_name)
    return T[:L]

def HKDF_expand_label(secret, label, hash_value, length,
                      hash_name='sha256') -> bytearray:
    # HKDF-Expand-Label (https://tools.ietf.org/html/rfc8446#section-7.1)
    #
    #     HKDF-Expand-Label(Secret, Label, Context, Length) =
    #         HKDF-Expand(Secret, HkdfLabel, Length)
    #
    #     Where HkdfLabel is specified as:
    #
    #     struct {
    #         uint16 length = Length;
    #         opaque label<7..255> = "tls13 " + Label;
    #         opaque context<0..255> = Context;
    #     } HkdfLabel;
    #
    hkdf_label = b''
    hkdf_label += bytes(Uint16(length))
    hkdf_label += bytes(OpaqueUint8(b'tls13 ' + label))
    hkdf_label += bytes(OpaqueUint8(hash_value))

    return HKDF_expand(secret, hkdf_label, length, hash_name)

def derive_secret(secret, label, messages, hash_name='sha256') -> bytearray:
    # Derive-Secret (https://tools.ietf.org/html/rfc8446#section-7.1)
    #
    #     Derive-Secret(Secret, Label, Messages) =
    #         HKDF-Expand-Label(Secret, Label,
    #                           Transcript-Hash(Messages), Hash.length)
    #
    hash_value = transcript_hash(messages, hash_name)
    hash_len = getattr(hashlib, hash_name)().digest_size
    return HKDF_expand_label(secret, label, hash_value, hash_len, hash_name)

def transcript_hash(messages, hash_name='sha256') -> bytearray:
    # Transcript Hash (https://tools.ietf.org/html/rfc8446#section-4.4.1)
    #
    #     Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
    #
    # 注意：Record層（TLSPlaintext）は含めないで Handshake の部分だけを結合してハッシュを求める
    assert isinstance(messages, (bytes, bytearray))
    return secure_hash(messages, hash_name)
