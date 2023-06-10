
from metatype import Uint16, Uint32, OpaqueUint8, OpaqueUint16
import metastruct as meta

from protocol_extensions import Extensions

@meta.struct
class NewSessionTicket(meta.MetaStruct):
    ticket_lifetime: Uint32
    ticket_age_add: Uint32
    ticket_nonce: OpaqueUint8
    ticket: OpaqueUint16
    extensions: Extensions
