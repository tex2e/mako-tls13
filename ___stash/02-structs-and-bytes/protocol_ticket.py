
from type import Uint16, Uint32, OpaqueUint8, OpaqueUint16
import structmeta as meta

from protocol_extensions import Extensions

@meta.struct
class NewSessionTicket(meta.StructMeta):
    ticket_lifetime: Uint32
    ticket_age_add: Uint32
    ticket_nonce: OpaqueUint8
    ticket: OpaqueUint16
    extensions: Extensions
