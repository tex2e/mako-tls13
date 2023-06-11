# ------------------------------------------------------------------------------
# Post-Handshake Messages
#   - RFC 8446 #section-4.6.1 (New Session Ticket Message)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
# ------------------------------------------------------------------------------

from metatype import Uint32, OpaqueUint8, OpaqueUint16
import metastruct as meta
from protocol_extensions import Extensions

### NewSessionTicket ###
# struct {
#     uint32 ticket_lifetime;
#     uint32 ticket_age_add;
#     opaque ticket_nonce<0..255>;
#     opaque ticket<1..2^16-1>;
#     Extension extensions<0..2^16-2>;
# } NewSessionTicket;
#
@meta.struct
class NewSessionTicket(meta.MetaStruct):
    ticket_lifetime: Uint32
    ticket_age_add: Uint32
    ticket_nonce: OpaqueUint8
    ticket: OpaqueUint16
    extensions: Extensions
