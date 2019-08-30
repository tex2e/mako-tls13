
from type import Uint8, Enum
import structmeta as meta

class AlertLevel(Enum):
    elem_t = Uint8

    warning = Uint8(1)
    fatal = Uint8(2)

class AlertDescription(Enum):
    elem_t = Uint8

    close_notify = Uint8(0)
    unexpected_message = Uint8(10)
    bad_record_mac = Uint8(20)
    record_overflow = Uint8(22)
    handshake_failure = Uint8(40)
    bad_certificate = Uint8(42)
    unsupported_certificate = Uint8(43)
    certificate_revoked = Uint8(44)
    certificate_expired = Uint8(45)
    certificate_unknown = Uint8(46)
    illegal_parameter = Uint8(47)
    unknown_ca = Uint8(48)
    access_denied = Uint8(49)
    decode_error = Uint8(50)
    decrypt_error = Uint8(51)
    protocol_version = Uint8(70)
    insufficient_security = Uint8(71)
    internal_error = Uint8(80)
    inappropriate_fallback = Uint8(86)
    user_canceled = Uint8(90)
    missing_extension = Uint8(109)
    unsupported_extension = Uint8(110)
    unrecognized_name = Uint8(112)
    bad_certificate_status_response = Uint8(113)
    unknown_psk_identity = Uint8(115)
    certificate_required = Uint8(116)
    no_application_protocol = Uint8(120)

@meta.struct
class Alert(meta.StructMeta):
    level: AlertLevel
    description: AlertDescription
