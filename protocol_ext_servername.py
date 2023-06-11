# ------------------------------------------------------------------------------
# Server Name Indication
#   - RFC 6066 #section-3
#     * https://datatracker.ietf.org/doc/html/rfc6066#section-3
# ------------------------------------------------------------------------------

from metatype import Uint8, Uint16, OpaqueUint16, List, Enum
import metastruct as meta
from protocol_types import HandshakeType
from protocol_ext_supportedgroups import NamedGroup

### NameType ###
# enum {
#     host_name(0), (255)
# } NameType;
#
class ServerNameIndicationType(Enum):
    enum_t = Uint8  # (255)

    host_name = Uint8(0)

### ServerName ###
# struct {
#     NameType name_type;
#     select (name_type) {
#         case host_name: HostName;
#     } name;
# } ServerName;
#
# opaque HostName<1..2^16-1>;
#
@meta.struct
class ServerNameIndication(meta.MetaStruct):
    name_type: NamedGroup
    host_name: OpaqueUint16

### ServerNameIndications ###
# struct {
#     ServerName server_name_list<1..2^16-1>
# } ServerNameList;
#
ServerNameIndications = List(size_t=Uint16, elem_t=ServerNameIndication)
