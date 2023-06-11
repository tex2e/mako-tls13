
import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import socket
import io

# TLS 1.3のFinished構造体とQUICのFinished構造体は長さ要素の有無で違いがあるため、
# QUICの場合は既存のFinished構造体を上書きする
from protocol_authentication import replace_to_quic_finished
replace_to_quic_finished()


class ClientConn:
    def __init__(self, host, port=443):
        self.server_address = (host, port)
        # ソケット作成
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # メッセージの送信
    def sendto(self, message: bytes):
        return self.sock.sendto(message, self.server_address)

    # メッセージの受信
    def recvfrom(self, buffer_size=2048): # 1024
        data, addr = self.sock.recvfrom(buffer_size)
        return data, addr


# conn = ClientConn('127.0.0.1', 4433)
# res = conn.sendto(b'12345')
# print(res)
# res = conn.recvfrom()
# print(res)


from utils import hexdump
from metatype import Uint8, Uint16, Uint32, Opaque, OpaqueUint8, OpaqueUint16, OpaqueLength, VarLenIntEncoding, OpaqueVarLenIntEncoding, List
from protocol_quic import QUICVersions, HeaderForm
from protocol_quic_longpacket import InitialPacket, LongPacket, LongPacketFlags, PacketType, HandshakePacket
from protocol_quic_packetprotection import get_key_iv_hp, get_client_server_key_iv_hp, header_protection, encrypt_payload, decrypt_payload
from protocol_quic_frame import Frame, FrameType, CryptoFrame, FrameSplit
from protocol_handshake import Handshake, HandshakeType
from protocol_hello import ClientHello
from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType
from protocol_ext_version import SupportedVersions, ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareHello, KeyShareEntrys, KeyShareEntry
from protocol_ext_servername import ServerNameIndications, ServerNameIndication, ServerNameIndicationType
from protocol_ext_alpn import ALPNProtocols
from protocol_ext_quic_transportparam import QuicTransportParam, QuicTransportParams, QuicTransportParamType
from protocol_tlscontext import TLSContext
from crypto_ecdhe import x25519

ctx = TLSContext('client')

peer_ipaddr = '127.0.0.1'
peer_port = 4433
peer = (peer_ipaddr, peer_port)

dhkex_class = x25519
secret_key = bytes.fromhex('6923bcdc7b80831a7f0d6fdfddb8e1b5e2f042cb1991cb19fd7ad9bce444fe63')
public_key = dhkex_class(secret_key)

dhkex_classes = {
    NamedGroup.x25519: dhkex_class
}
secret_keys = {
    NamedGroup.x25519: secret_key
}

client_dst_connection_id = bytes.fromhex('1a26dc5bd9625e2bcd0efd3a329ce83136a32295')
client_src_connection_id = bytes.fromhex('c6b336557f9128bef8a099a10d320c26e9c8d1ab')

crypto_frame = Frame(
    frame_type=FrameType.CRYPTO,
    frame_content=CryptoFrame(
        offset=VarLenIntEncoding(Uint8(0)),
        data=Handshake(
            msg_type=HandshakeType.client_hello,
            msg=ClientHello(
                legacy_version=Uint16(0x0303),
                legacy_session_id=OpaqueUint8(b''),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_128_GCM_SHA256,
                    # CipherSuite.TLS_AES_256_GCM_SHA384,
                    # CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                ]),
                extensions=Extensions([
                    Extension(
                        extension_type=ExtensionType.supported_versions,
                        extension_data=SupportedVersions(
                            versions=ProtocolVersions([
                                ProtocolVersion.TLS13
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=NamedGroups([
                                NamedGroup.x25519
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.application_layer_protocol_negotiation,
                        extension_data=ALPNProtocols([
                            OpaqueUint8(b'h3')
                        ])
                    ),
                    Extension(
                        extension_type=ExtensionType.signature_algorithms,
                        extension_data=SignatureSchemeList(
                            supported_signature_algorithms=SignatureSchemes([
                                SignatureScheme.rsa_pss_rsae_sha256,
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.key_share,
                        extension_data=KeyShareHello(
                            shares=KeyShareEntrys([
                                KeyShareEntry(
                                    group=NamedGroup.x25519,
                                    key_exchange=OpaqueUint16(public_key)
                                )
                            ])
                        )
                    ),
                    Extension(
                        extension_type=ExtensionType.quic_transport_parameters,
                        extension_data=QuicTransportParams([
                            QuicTransportParam(
                                param_id=QuicTransportParamType.max_idle_timeout,
                                param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint32(30000))))
                            ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.max_udp_payload_size,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint16(1350)))) # defaultはUDPの最大ペイロード長の65527bytes
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.initial_max_data,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint32(10000000))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.initial_max_stream_data_bidi_local,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint32(1000000))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.initial_max_stream_data_bidi_remote,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint32(1000000))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.initial_max_stream_data_uni,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint32(1000000))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.initial_max_streams_bidi,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint16(100))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.initial_max_streams_uni,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint16(100))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.ack_delay_exponent,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint8(3))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.max_ack_delay,
                            #     param_value=OpaqueVarLenIntEncoding(bytes(VarLenIntEncoding(Uint8(25))))
                            # ),
                            # QuicTransportParam(
                            #     param_id=QuicTransportParamType.disable_active_migration,
                            #     param_value=OpaqueVarLenIntEncoding(b'')
                            # ),
                            QuicTransportParam(
                                param_id=QuicTransportParamType.initial_source_connection_id,
                                param_value=OpaqueUint8(client_src_connection_id)
                            ),
                        ])
                    )
                ])
            )
        )
    )
)
crypto_frame_len = len(bytes(crypto_frame))
ctx.append_msg(crypto_frame.frame_content.data) # Add Client Hello

# --- 1回目 ---------------------------------------------------------------------
packet_number = 1
initial_packet = InitialPacket(
    flags=LongPacketFlags(header_form=HeaderForm.LONG, fixed_bit=1,
                          long_packet_type=PacketType.INITIAL, type_specific_bits=0b0011),
    version=QUICVersions.QUICv1,
    dest_conn_id=OpaqueUint8(client_dst_connection_id),
    src_conn_id=OpaqueUint8(client_src_connection_id),
    token=OpaqueVarLenIntEncoding(b''),
    length=None,
    packet_number=Uint32(packet_number),
    packet_payload=None
)

aead_tag_len = 16
LengthType = Uint16
length_len = LengthType.size

def calc_padding_frame_len(initial_packet):
    packet_number_len = (initial_packet.flags.type_specific_bits & 0x03) + 1  # バケット番号長
    # Clientが送信するInitial Packetを含むUDPペイロードは1200バイト以上にしないといけない (MUST)
    padding_frame_len = 1200 - 5 - len(bytes(initial_packet.dest_conn_id)) - len(bytes(initial_packet.src_conn_id)) - len(bytes(initial_packet.token)) - length_len - packet_number_len - crypto_frame_len - aead_tag_len - 1
    return padding_frame_len

padding_frame_len = calc_padding_frame_len(initial_packet)
print('[+] padding_frame_len:', padding_frame_len)

# 1200バイト以上になるようにパディング追加
padding_frame = Frame(
    frame_type=FrameType.PADDING,
    frame_content=b'\x00' * padding_frame_len
)
Frames = List(size_t=lambda x: None, elem_t=Frame)
frames = Frames([
    crypto_frame,
    padding_frame,
])
plaintext_payload_bytes = bytes(frames)
packet_number_len = (initial_packet.flags.type_specific_bits & 0x03) + 1  # バケット番号長
initial_packet.length = VarLenIntEncoding(LengthType(len(plaintext_payload_bytes) + packet_number_len + aead_tag_len))
initial_packet.update()
# print('=== Send packet ===')
# print(initial_packet)

client_key, client_iv, client_hp_key, server_key, server_iv, server_hp_key = \
    get_client_server_key_iv_hp(client_dst_connection_id)

aad = initial_packet.get_header_bytes()
print('aad:')
print(hexdump(aad))

ciphertext_payload_bytes = encrypt_payload(plaintext_payload_bytes, client_key, client_iv, aad, packet_number)

# print('encrypted:')
# print(hexdump(ciphertext_payload_bytes))

initial_packet.length = VarLenIntEncoding(LengthType(len(ciphertext_payload_bytes) + packet_number_len))
initial_packet.packet_payload = OpaqueLength(ciphertext_payload_bytes)
initial_packet.update()
print(initial_packet)

send_packet = LongPacket.from_bytes(bytes(initial_packet))
send_packet_bytes = header_protection(send_packet, client_hp_key, mode='encrypt', debug=True)
# print('encrypted packet:')
# print(hexdump(send_packet_bytes))
print('[+] len(send_packet_bytes):', len(send_packet_bytes))

conn = ClientConn(peer_ipaddr, peer_port)
res = conn.sendto(send_packet_bytes)
# print(res)
res = conn.recvfrom()
# print(res)
recv_msg, addr = res

recv_packet = LongPacket.from_bytes(recv_msg)
recv_packet_bytes = bytes(recv_packet)
print('=== Recv Packet ===')
print(recv_packet)
# print(hexdump(recv_packet_bytes))

# 受信したパケットがRetry Packetの場合
if PacketType(recv_packet.flags.long_packet_type) == PacketType.RETRY:
    # --- 2回目 -----------------------------------------------------------------
    # 受信したRetryパケットからtokenを取り出して、ClientHelloを含むQUICパケットを作って送る
    # print('---')
    retry_token = recv_packet.payload.retry_token
    client_dst_connection_id = recv_packet.src_conn_id.byte
    # print('[+] server conn id:')
    # print(hexdump(recv_packet.src_conn_id.byte))
    # print('[+] retry_token:', retry_token)

    # Send InitailPacket after Retry

    packet_number = 2
    initial_packet = InitialPacket(
        flags=LongPacketFlags(header_form=HeaderForm.LONG, fixed_bit=1,
                            long_packet_type=PacketType.INITIAL, type_specific_bits=0b0011),
        version=QUICVersions.QUICv1,
        dest_conn_id=OpaqueUint8(client_dst_connection_id),
        src_conn_id=OpaqueUint8(client_src_connection_id),
        token=OpaqueVarLenIntEncoding(retry_token),
        length=None,
        packet_number=Uint32(packet_number),
        packet_payload=None
    )

    padding_frame_len = calc_padding_frame_len(initial_packet)
    print('[+] padding_frame_len:', padding_frame_len)

    # 1200バイト以上になるようにパディング追加
    padding_frame = Frame(
        frame_type=FrameType.PADDING,
        frame_content=b'\x00' * padding_frame_len
    )
    Frames = List(size_t=lambda x: None, elem_t=Frame)
    frames = Frames([
        crypto_frame,
        padding_frame,
    ])
    plaintext_payload_bytes = bytes(frames)
    packet_number_len = (initial_packet.flags.type_specific_bits & 0x03) + 1  # バケット番号長
    # initial_packet.packet_payload = plaintext_payload_bytes
    initial_packet.length = VarLenIntEncoding(LengthType(len(plaintext_payload_bytes) + packet_number_len + aead_tag_len))
    initial_packet.update()

    # print('=== Send packet ===')
    # print(initial_packet)

    client_key, client_iv, client_hp_key, server_key, server_iv, server_hp_key = \
        get_client_server_key_iv_hp(client_dst_connection_id)

    aad = initial_packet.get_header_bytes()
    print('aad:')
    print(hexdump(aad))

    ciphertext_payload_bytes = encrypt_payload(plaintext_payload_bytes, client_key, client_iv, aad, packet_number)
    # print('encrypted:')
    # print(hexdump(ciphertext_payload_bytes))
    initial_packet.length = VarLenIntEncoding(LengthType(len(ciphertext_payload_bytes) + packet_number_len))
    initial_packet.packet_payload = OpaqueLength(ciphertext_payload_bytes)
    initial_packet.update()
    print(initial_packet)

    send_packet = LongPacket.from_bytes(bytes(initial_packet))
    send_packet_bytes = header_protection(send_packet, client_hp_key, mode='encrypt')
    # print('encrypted packet:')
    # print(hexdump(send_packet_bytes))
    print('[+] len(send_packet_bytes):', len(send_packet_bytes))

    conn = ClientConn(peer_ipaddr, peer_port)
    res = conn.sendto(send_packet_bytes)
    res = conn.recvfrom()
    recv_msg, addr = res
    # print('<<< Recv')
    # print(hexdump(recv_msg))

    #print(hexdump(recv_msg)) # ここには ServerInitialPacket と Handshake(CRYPTO[EE]の前半部分) が含まれている
    recv_msg_stream = io.BytesIO(recv_msg)
    recv_packet = LongPacket.from_stream(recv_msg_stream)
    print('=== Recv Packet1 ===')
    print(recv_packet)
    print(hexdump(bytes(recv_packet)))
    recv_packet2 = LongPacket.from_stream(recv_msg_stream)
    print('=== Recv Packet2 ===')
    print(recv_packet2)
    print(hexdump(bytes(recv_packet2)))
    print('rest:')
    print(recv_msg_stream.read())


if PacketType(recv_packet.flags.long_packet_type) != PacketType.INITIAL:
    print("Error!")
    sys.exit(1)

print('---')
print('client_key:')
print(hexdump(client_key))
print('client_iv:')
print(hexdump(client_iv))
print('client_hp_key:')
print(hexdump(client_hp_key))
print('server_key:')
print(hexdump(server_key))
print('server_iv:')
print(hexdump(server_iv))
print('server_hp_key:')
print(hexdump(server_hp_key))

print('=== Recv Server Initial Packet ===')
server_initial_packet_bytes = header_protection(recv_packet, server_hp_key, mode='decrypt')
server_initial_packet = InitialPacket.from_bytes(server_initial_packet_bytes)
server_initial_packet_bytes = bytes(server_initial_packet)
print(server_initial_packet)
# print(hexdump(server_initial_packet_bytes))

ciphertext_payload_bytes = bytes(server_initial_packet.packet_payload)
aad = server_initial_packet.get_header_bytes()  # Additional Auth Data
packet_number = server_initial_packet.get_packet_number_int()
plaintext_payload_bytes = decrypt_payload(ciphertext_payload_bytes, server_key, server_iv, aad, packet_number)
# print('decrypted:')
# print(hexdump(plaintext_payload_bytes))

# Framesの解析
print('-----')
Frames = List(size_t=lambda self: len(plaintext_payload_bytes), elem_t=Frame)
frames = Frames.from_bytes(plaintext_payload_bytes)
print(frames)

print('-----')
server_hello = frames[1].frame_content.data
print('>>>', server_hello.msg.cipher_suite)
ctx.append_msg(server_hello)
# 共有鍵の導出
ctx.set_key_exchange(dhkex_classes, secret_keys)
ctx.key_schedule_in_handshake()
# print('shared_key:')
# print(hexdump(ctx.shared_key))
print('client_hs_traffic_secret:')
print(hexdump(ctx.client_hs_traffic_secret))
print('server_hs_traffic_secret:')
print(hexdump(ctx.server_hs_traffic_secret))

client_hs_key, client_hs_iv, client_hs_hp_key = \
    get_key_iv_hp(ctx.client_hs_traffic_secret)
print('client_hs_key:')
print(hexdump(client_hs_key))
print('client_hs_iv:')
print(hexdump(client_hs_iv))
print('client_hs_hp_key:')
print(hexdump(client_hs_hp_key))
server_hs_key, server_hs_iv, server_hs_hp_key = \
    get_key_iv_hp(ctx.server_hs_traffic_secret)
print('server_hs_key:')
print(hexdump(server_hs_key))
print('server_hs_iv:')
print(hexdump(server_hs_iv))
print('server_hs_hp_key:')
print(hexdump(server_hs_hp_key))

print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print('=== Recv Server Handshake Packet1 ===')
print(recv_packet2)
server_handshake_packet_bytes = header_protection(recv_packet2, server_hs_hp_key, mode='decrypt', debug=True)
print('---')
print(hexdump(server_handshake_packet_bytes))

server_handshake_packet = HandshakePacket.from_bytes(server_handshake_packet_bytes)
server_handshake_packet_bytes = bytes(server_handshake_packet)
print(server_handshake_packet)
print(hexdump(server_handshake_packet_bytes))

ciphertext_payload_bytes = bytes(server_handshake_packet.packet_payload)
aad = server_handshake_packet.get_header_bytes()  # Additional Auth Data
packet_number = server_handshake_packet.get_packet_number_int()
plaintext_payload_bytes = decrypt_payload(ciphertext_payload_bytes, server_hs_key, server_hs_iv, aad, packet_number, debug=True)
print('decrypted:')
print(hexdump(plaintext_payload_bytes))

crypto_frame_split_bytes = b''
crypto_frame = FrameSplit.from_bytes(plaintext_payload_bytes)
print('crypto_frame.frame_content.offset:', crypto_frame.frame_content.offset)
print('crypto_frame.frame_content.length:', crypto_frame.frame_content.length)
crypto_frame_split_bytes += bytes(crypto_frame.frame_content.data)

print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
res = conn.recvfrom()
recv_msg, addr = res
recv_msg_stream = io.BytesIO(recv_msg)
recv_packet = LongPacket.from_stream(recv_msg_stream)
recv_packet_bytes = bytes(recv_packet)
print('=== Recv Packet ===')
print(recv_packet)

print('=== Recv Server Handshake Packet2 ===')
server_handshake_packet_bytes = header_protection(recv_packet, server_hs_hp_key, mode='decrypt')
print(hexdump(server_handshake_packet_bytes))

# print('---')
# # FIXME: EncryptedExtension を受信時に CRYPTO の Offset=0x3C3 で、Length=0x194 となっていて、
# #        実際のHandshakeデータはオフセット 0x73 から始まっているのだが、どう解釈すべきか...
#
## => CRYPTO Frameは分割して送信されるため。1つ目が offset=0, length=0x3c3 で、2つ目が offset=0x3c3, length=0x194
## => とりあえず、CRYPTO FrameのData部分はTLSメッセージが途切れている可能性があるので、
##    そこを考慮して、OffsetとLengthを確認しながら、全てのCryptoDataが集まったときに、
##    初めてTLSメッセージとして解析するようにしないといけないことがわかった。
#
server_handshake_packet = HandshakePacket.from_bytes(server_handshake_packet_bytes)
server_handshake_packet_bytes = bytes(server_handshake_packet)
print(server_handshake_packet)
print(hexdump(server_handshake_packet_bytes))

ciphertext_payload_bytes = bytes(server_handshake_packet.packet_payload)
aad = server_handshake_packet.get_header_bytes()  # Additional Auth Data
packet_number = server_handshake_packet.get_packet_number_int()
plaintext_payload_bytes = decrypt_payload(ciphertext_payload_bytes, server_hs_key, server_hs_iv, aad, packet_number)
print('decrypted:')
print(hexdump(plaintext_payload_bytes))

crypto_frame = FrameSplit.from_bytes(plaintext_payload_bytes)
print('crypto_frame.frame_content.offset:', crypto_frame.frame_content.offset)
print('crypto_frame.frame_content.length:', crypto_frame.frame_content.length)
crypto_frame_split_bytes += bytes(crypto_frame.frame_content.data)

print("--- TLS Messages ---")
print(hexdump(crypto_frame_split_bytes))

crypto_frame_split_stream_len = len(crypto_frame_split_bytes)
crypto_frame_split_stream = io.BytesIO(crypto_frame_split_bytes)
# EncryptedExtensions, Certificate, CertificateVerify, Finished
while crypto_frame_split_stream.tell() < crypto_frame_split_stream_len:
    handshake = Handshake.from_stream(crypto_frame_split_stream)
    print(handshake)




# # print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
# # res = conn.recvfrom()
# # # print(res)
# # recv_msg, addr = res
# # recv_packet = LongPacket.from_bytes(recv_msg)
# # recv_packet_bytes = bytes(recv_packet)
# # print('=== Recv Packet ===')
# # print(recv_packet)
