

from metatype import Uint8, List, Enum, VarLenIntEncoding, Opaque
import metastruct as meta

class QuicTransportParamType(Enum):
    elem_t = VarLenIntEncoding

    original_destination_connection_id = VarLenIntEncoding(Uint8(0x00))
    max_idle_timeout = VarLenIntEncoding(Uint8(0x01))
    stateless_reset_token = VarLenIntEncoding(Uint8(0x02))
    max_udp_payload_size = VarLenIntEncoding(Uint8(0x03))
    initial_max_data = VarLenIntEncoding(Uint8(0x04))
    initial_max_stream_data_bidi_local = VarLenIntEncoding(Uint8(0x05))
    initial_max_stream_data_bidi_remote = VarLenIntEncoding(Uint8(0x06))
    initial_max_stream_data_uni = VarLenIntEncoding(Uint8(0x07))
    initial_max_streams_bidi = VarLenIntEncoding(Uint8(0x08))
    initial_max_streams_uni = VarLenIntEncoding(Uint8(0x09))
    ack_delay_exponent = VarLenIntEncoding(Uint8(0x0a))
    max_ack_delay = VarLenIntEncoding(Uint8(0x0b))
    disable_active_migration = VarLenIntEncoding(Uint8(0x0c))
    preferred_address = VarLenIntEncoding(Uint8(0x0d))
    active_connection_id_limit = VarLenIntEncoding(Uint8(0x0e))
    initial_source_connection_id = VarLenIntEncoding(Uint8(0x0f))
    retry_source_connection_id = VarLenIntEncoding(Uint8(0x10))

# Transport Parameter {
#   Transport Parameter ID (i),
#   Transport Parameter Length (i),
#   Transport Parameter Value (..),
# }
@meta.struct
class QuicTransportParam(meta.MetaStruct):
    param_id: QuicTransportParamType
    param_value: Opaque(VarLenIntEncoding)


QuicTransportParams = List(size_t=lambda parent: parent.length, elem_t=QuicTransportParam)
