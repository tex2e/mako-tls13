# ------------------------------------------------------------------------------
# Handshake Protocol
#   - RFC 8446 #section-4
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4
# ------------------------------------------------------------------------------

from metatype import Uint24
import metastruct as meta
from protocol_types import HandshakeType
from protocol_hello import ClientHello, ServerHello
from protocol_extensions import EncryptedExtensions
from protocol_authentication import Certificate, CertificateVerify, Finished
from protocol_ticket import NewSessionTicket

### Handshake ###
# struct {
#     HandshakeType msg_type;    /* handshake type */
#     uint24 length;             /* remaining bytes in message */
#     select (Handshake.msg_type) {
#         case client_hello:          ClientHello;
#         case server_hello:          ServerHello;
#         case end_of_early_data:     EndOfEarlyData;
#         case encrypted_extensions:  EncryptedExtensions;
#         case certificate_request:   CertificateRequest;
#         case certificate:           Certificate;
#         case certificate_verify:    CertificateVerify;
#         case finished:              Finished;
#         case new_session_ticket:    NewSessionTicket;
#         case key_update:            KeyUpdate;
#     };
# } Handshake;
#
@meta.struct
class Handshake(meta.MetaStruct):
    msg_type: HandshakeType
    length: Uint24 = lambda self: Uint24(len(bytes(self.msg)))
    msg: meta.Select('msg_type', cases={
        HandshakeType.client_hello: ClientHello,
        HandshakeType.server_hello: ServerHello,
        HandshakeType.encrypted_extensions: EncryptedExtensions,
        HandshakeType.certificate: Certificate,
        HandshakeType.certificate_verify: CertificateVerify,
        HandshakeType.finished: Finished,
        HandshakeType.new_session_ticket: NewSessionTicket,
        # TODO: 一部の構造体はまだ未実装です
    })
