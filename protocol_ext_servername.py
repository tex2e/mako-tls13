
from metatype import Uint8, Uint16, OpaqueUint16, List, Enum
import metastruct as meta

from protocol_types import HandshakeType
from protocol_ext_supportedgroups import NamedGroup

class ServerNameIndicationType(Enum):
    enum_t = Uint8

    host_name = Uint8(0)

# ServerName
@meta.struct
class ServerNameIndication(meta.MetaStruct):
    name_type: NamedGroup
    host_name: OpaqueUint16

ServerNameIndications = List(size_t=Uint16, elem_t=ServerNameIndication)
