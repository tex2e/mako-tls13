
from type import Uint8, Uint16, Opaque, List, Enum
from structmeta import StructMeta, Members, Member, Select

from protocol_handshake import Handshake

# ------------------------------------------------------------------------------
# Record Layer

class ContentType(Enum):
    size = 1
    size_t = Uint8

    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)

ProtocolVersion = Uint16

class TLSPlaintext(StructMeta):
    struct = Members([
        Member(ContentType, 'type'),
        Member(ProtocolVersion, 'legacy_record_version'),
        Member(Uint16, 'length'),
        Member(Select(switch='type', cases={
            ContentType.handshake: Handshake,
        }), 'fragment'),
    ])
