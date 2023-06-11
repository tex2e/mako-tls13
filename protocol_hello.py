# ------------------------------------------------------------------------------
# Client Hello / Server Hello
#   - RFC 8446 #section-4.1.2 (Client Hello)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
#   - RFC 8446 #section-4.1.3 (Server Hello)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
# ------------------------------------------------------------------------------

import os
from metatype import Uint8, Uint16, Opaque, OpaqueUint8, List
import metastruct as meta
from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extension, Extensions

ProtocolVersion = Uint16
Random = Opaque(32)
Opaque1 = Opaque(1)

### ClientHello ###
# uint16 ProtocolVersion;
# opaque Random[32];
#
# uint8 CipherSuite[2];    /* Cryptographic suite selector */
#
# struct {
#     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
#     Random random;
#     opaque legacy_session_id<0..32>;
#     CipherSuite cipher_suites<2..2^16-2>;
#     opaque legacy_compression_methods<1..2^8-1>;
#     Extension extensions<8..2^16-1>;
# } ClientHello;
#
@meta.struct
class ClientHello(meta.MetaStruct):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suites: CipherSuites
    legacy_compression_methods: OpaqueUint8 = lambda self: OpaqueUint8(b'\x00')
    extensions: Extensions

### ServerHello ###
# struct {
#     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
#     Random random;
#     opaque legacy_session_id_echo<0..32>;
#     CipherSuite cipher_suite;
#     uint8 legacy_compression_method = 0;
#     Extension extensions<6..2^16-1>;
# } ServerHello;
#
@meta.struct
class ServerHello(meta.MetaStruct):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id_echo: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suite: CipherSuite
    legacy_compression_method: Opaque1 = lambda self: Opaque1(b'\x00')
    extensions: Extensions
