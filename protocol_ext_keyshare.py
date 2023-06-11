# ------------------------------------------------------------------------------
# Key Share
#   - RFC 8446 #section-4.2.8
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
# ------------------------------------------------------------------------------

from metatype import Uint16, OpaqueUint16, List
import metastruct as meta
from protocol_types import HandshakeType
from protocol_ext_supportedgroups import NamedGroup

### KeyShareEntry ###
# struct {
#     NamedGroup group;
#     opaque key_exchange<1..2^16-1>;
# } KeyShareEntry;
#
@meta.struct
class KeyShareEntry(meta.MetaStruct):
    group: NamedGroup
    key_exchange: OpaqueUint16

KeyShareEntrys = List(size_t=Uint16, elem_t=KeyShareEntry)

### KeyShareClientHello / KeyShareServerHello ###
# struct {
#     KeyShareEntry client_shares<0..2^16-1>;
# } KeyShareClientHello;
#
# struct {
#     KeyShareEntry server_share;
# } KeyShareServerHello;
#
@meta.struct
class KeyShareHello(meta.MetaStruct):
    shares: meta.Select('Handshake.msg_type', cases={
        HandshakeType.client_hello: KeyShareEntrys,
        HandshakeType.server_hello: KeyShareEntry,
    })
