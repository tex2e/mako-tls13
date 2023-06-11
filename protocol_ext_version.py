# ------------------------------------------------------------------------------
# Supported Versions
#   - RFC 8446 #section-4.2.1
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
# ------------------------------------------------------------------------------

from metatype import Uint8, Uint16, List, Enum
import metastruct as meta
from protocol_types import HandshakeType

### ProtocolVersion ###
# uint16 ProtocolVersion;
#
class ProtocolVersion(Enum):
    elem_t = Uint16

    SSL3  = Uint16(0x0300)
    TLS10 = Uint16(0x0301)
    TLS11 = Uint16(0x0302)
    TLS12 = Uint16(0x0303)
    TLS13 = Uint16(0x0304)

ProtocolVersions = List(size_t=Uint8, elem_t=ProtocolVersion)

### SupportedVersions ###
# struct {
#     select (Handshake.msg_type) {
#         case client_hello:
#             ProtocolVersion versions<2..254>;
#
#         case server_hello: /* and HelloRetryRequest */
#             ProtocolVersion selected_version;
#     };
# } SupportedVersions;
#
@meta.struct
class SupportedVersions(meta.MetaStruct):
    versions: meta.Select('Handshake.msg_type', cases={
        HandshakeType.client_hello: ProtocolVersions,
        HandshakeType.server_hello: ProtocolVersion,
    })
