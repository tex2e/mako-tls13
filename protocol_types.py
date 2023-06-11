# ------------------------------------------------------------------------------
# 構造体に代入する定数群。
# 循環参照(循環import)を回避するためにファイルを分離した。
# ------------------------------------------------------------------------------

from metatype import Uint8, Enum

# ------------------------------------------------------------------------------
# Record Layer
#   - RFC 8446 #section-5.1
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
# ------------------------------------------------------------------------------

### ContentType ###
# enum {
#     invalid(0),
#     change_cipher_spec(20),
#     alert(21),
#     handshake(22),
#     application_data(23),
#     (255)
# } ContentType;
#
class ContentType(Enum):
    elem_t = Uint8  # (255)

    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)

# ------------------------------------------------------------------------------
# Handshake Protocol
#   - RFC 8446 #section-4
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4
# ------------------------------------------------------------------------------

### HandshakeType ###
# enum {
#     client_hello(1),
#     server_hello(2),
#     ...
#     (255)
# } HandshakeType;
#
class HandshakeType(Enum):
    elem_t = Uint8  # (255)

    #hello_request_RESERVED = Uint8(0)
    client_hello = Uint8(1)
    server_hello = Uint8(2)
    #hello_verify_request_RESERVED = Uint8(3)
    new_session_ticket = Uint8(4)
    end_of_early_data = Uint8(5)
    #hello_retry_request_RESERVED = Uint8(6)
    encrypted_extensions = Uint8(8)
    certificate = Uint8(11)
    #server_key_exchange_RESERVED = Uint8(12)
    certificate_request = Uint8(13)
    #server_hello_done_RESERVED = Uint8(14)
    certificate_verify = Uint8(15)
    #client_key_exchange_RESERVED = Uint8(16)
    finished = Uint8(20)
    #certificate_url_RESERVED = Uint(21)
    #certificate_status_RESERVED = Uint(22)
    #supplemental_data_RESERVED = Uint(23)
    key_update = Uint8(24)
    message_hash = Uint8(254)
