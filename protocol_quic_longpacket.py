
from metatype import Type, Enum
from metatype import Uint32, Opaque, OpaqueUint8, VarLenIntEncoding, OpaqueVarLenIntEncoding
import metastruct as meta
from utils import hexdump
from protocol_quic import HeaderForm

class PacketType(Enum):
    INITIAL   = 0x00
    a0RTT     = 0x01
    HANDSHAKE = 0x02
    RETRY     = 0x03

# Long Header Packet {
#   Header Form (1) = 1,
#   Fixed Bit (1) = 1,
#   Long Packet Type (2),
#   Type-Specific Bits (4),
#   ...
# }
class LongPacketFlags(Type):
    def __init__(self, header_form=HeaderForm.LONG, fixed_bit=1,
                       long_packet_type=0, type_specific_bits=0,
                       type_specific_bits_msb2bit=None, type_specific_bits_lsb2bit=None):
        self.header_form = header_form
        self.fixed_bit = fixed_bit
        self.long_packet_type = int(long_packet_type)
        if (type_specific_bits_msb2bit is None) and (type_specific_bits_lsb2bit is None):
            self.type_specific_bits = type_specific_bits
            self.type_specific_bits_msb2bit = (type_specific_bits & 0b1100) >> 2
            self.type_specific_bits_lsb2bit = (type_specific_bits & 0b0011) >> 0
        else:
            self.type_specific_bits_msb2bit = type_specific_bits_msb2bit
            self.type_specific_bits_lsb2bit = type_specific_bits_lsb2bit
            self.type_specific_bits = type_specific_bits_msb2bit << 2 + type_specific_bits_lsb2bit

    @classmethod
    def from_stream(cls, fs, parent=None):
        flags = fs.read(1)
        header_form        = (ord(flags) & 0b10000000) >> 7
        fixed_bit          = (ord(flags) & 0b01000000) >> 6
        long_packet_type   = (ord(flags) & 0b00110000) >> 4
        type_specific_bits = (ord(flags) & 0b00001111) >> 0
        return LongPacketFlags(header_form, fixed_bit,
                               long_packet_type, type_specific_bits)

    def __bytes__(self):
        res = 0
        res |= self.header_form        << 7
        res |= self.fixed_bit          << 6
        res |= self.long_packet_type   << 4
        res |= self.type_specific_bits << 0
        return bytes([res])

    def __repr__(self):
        res = "LongPacketFlags("
        res += "header_form={0:1b}({1}), ".format(self.header_form,
                LongPacketFlags.get_name_of_header_form(self.header_form))
        res += "fixed_bit={0:1b}, ".format(self.fixed_bit)
        res += "long_packet_type={0:02b}({1}), ".format(self.long_packet_type,
                LongPacketFlags.get_name_of_packet_type(self.long_packet_type))
        res += "type_specific_bits={0:04b}".format(self.type_specific_bits)
        res += ")"
        return res

    @staticmethod
    def get_name_of_header_form(value):
        if value == 0: return "Short"
        if value == 1: return "Long"

    @staticmethod
    def get_name_of_packet_type(value):
        if value == 0x00: return "Initial"
        if value == 0x01: return "0-RTT"
        if value == 0x02: return "Handshake"
        if value == 0x03: return "Retry"


# Initial Packet {
#   Header Form (1) = 1,
#   Fixed Bit (1) = 1,
#   Long Packet Type (2) = 0,
#   Reserved Bits (2),         # Protected
#   Packet Number Length (2),  # Protected
#   Version (32),
#   DCID Len (8),
#   Destination Connection ID (0..160),
#   SCID Len (8),
#   Source Connection ID (0..160),
#   Token Length (i),
#   Token (..),
#   Length (i),
#   Packet Number (8..32),     # Protected
#   Protected Payload (0..24), # Skipped Part
#   Protected Payload (128),   # Sampled Part
#   Protected Payload (..)     # Remainder
# }

# Initial Packet Payload
@meta.struct
class InitialPacketPayload(meta.MetaStruct):
    token: OpaqueVarLenIntEncoding
    length: VarLenIntEncoding
    protected_payload: Opaque(lambda self: self.length) # Protected

# Retry Packet Payload
class RetryPacketPayload(Type):
    def __init__(self, retry_token, retry_integrity_tag):
        self.retry_token = retry_token
        self.retry_integrity_tag = retry_integrity_tag

    @classmethod
    def from_stream(cls, fs, parent=None):
        byte = fs.read() # read rest of all bytes
        retry_token = byte[:-16]
        retry_integrity_tag = byte[-16:]
        return cls(retry_token, retry_integrity_tag)

    def __bytes__(self):
        return bytes(self.retry_token) + bytes(self.retry_integrity_tag)

    def __repr__(self):
        return "RetryPacketPayload(retry_token=%s, retry_integrity_tag=%s)" % \
               (self.retry_token, self.retry_integrity_tag)

# 0-RTT Packet Payload
@meta.struct
class A0RTTPacketPayload(meta.MetaStruct):
    length: VarLenIntEncoding
    protected_payload: Opaque(lambda self: self.length) # Protected

# Handshake Packet Payload
@meta.struct
class HandshakePacketPayload(meta.MetaStruct):
    length: VarLenIntEncoding
    protected_payload: Opaque(lambda self: self.length) # Protected

# Long Packet
@meta.struct
class LongPacket(meta.MetaStruct):
    flags: LongPacketFlags # Protected
    version: Uint32
    dest_conn_id: OpaqueUint8
    src_conn_id: OpaqueUint8
    payload: meta.Select('self.flags.long_packet_type', cases={
        int(PacketType.INITIAL): InitialPacketPayload,
        int(PacketType.a0RTT): A0RTTPacketPayload,
        int(PacketType.HANDSHAKE): HandshakePacketPayload,
        int(PacketType.RETRY): RetryPacketPayload
    })


# Initial Packet
@meta.struct
class InitialPacket(meta.MetaStruct):
    flags: LongPacketFlags
    version: Uint32
    dest_conn_id: OpaqueUint8
    src_conn_id: OpaqueUint8
    token: OpaqueVarLenIntEncoding
    length: VarLenIntEncoding
    packet_number: Opaque(lambda self: self.flags.type_specific_bits_lsb2bit + 1)
    packet_payload: Opaque(lambda self: int(self.length) - self.packet_number.get_size())

    def get_header_bytes(self):
        return create_aad(self.flags, self.version, self.dest_conn_id, self.src_conn_id, \
                          self.token, self.length, self.packet_number)

    def get_packet_number_int(self):
        return int.from_bytes(bytes(self.packet_number), 'big')

def create_aad(flags: LongPacketFlags, version: Uint32, dest_conn_id: OpaqueUint8,
               src_conn_id: OpaqueUint8, token: OpaqueVarLenIntEncoding,
               length: VarLenIntEncoding, packet_number):
    assert flags is not None
    assert version is not None
    assert dest_conn_id is not None
    assert src_conn_id is not None
    assert token is not None
    assert length is not None
    assert packet_number is not None
    return bytes(flags) + bytes(version) + bytes(dest_conn_id) + \
           bytes(src_conn_id) + bytes(token) + bytes(length) + \
           bytes(packet_number)



# Handshake Packet
@meta.struct
class HandshakePacket(meta.MetaStruct):
    flags: LongPacketFlags
    version: Uint32
    dest_conn_id: OpaqueUint8
    src_conn_id: OpaqueUint8
    length: VarLenIntEncoding
    packet_number: Opaque(lambda self: self.flags.type_specific_bits_lsb2bit + 1)
    packet_payload: Opaque(lambda self: int(self.length) - self.packet_number.get_size())

    def get_header_bytes(self):
        return create_aad(self.flags, self.version, self.dest_conn_id, self.src_conn_id, \
                          b'', self.length, self.packet_number)

    def get_packet_number_int(self):
        return int.from_bytes(bytes(self.packet_number), 'big')


