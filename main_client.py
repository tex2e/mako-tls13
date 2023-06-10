# ------------------------------------------------------------------------------
# TLS 1.3 Client
# ------------------------------------------------------------------------------

import os
import sys
import io
import threading
import queue

import connection
from type import Uint8, Uint16, OpaqueUint16
from disp import hexdump

from protocol_tlscontext import TLSContext
from protocol_types import ContentType, HandshakeType
from protocol_recordlayer import TLSPlaintext, TLSCiphertext
from protocol_handshake import Handshake
from protocol_hello import ClientHello
from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType
from protocol_ext_version import SupportedVersions, \
    ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, \
    SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareHello, KeyShareEntrys, KeyShareEntry
from protocol_authentication import Finished, Hash, OpaqueHash
from protocol_alert import Alert, AlertLevel, AlertDescription

from crypto_ecdhe import x25519
from crypto_ffdhe import FFDHE
import crypto_hkdf as hkdf

ctx = TLSContext('client')

# === Key Exchange Parameters ===
dhkex_class1 = x25519
secret_key1 = os.urandom(32)
public_key1 = dhkex_class1(secret_key1)

ffdhe4096 = FFDHE('ffdhe4096')
secret_key2 = ffdhe4096.get_secret_key()
public_key2 = ffdhe4096.gen_public_key()
dhkex_class2 = FFDHE.get_dhkey(ffdhe4096)

dhkex_classes = {
    NamedGroup.x25519: dhkex_class1,
    NamedGroup.ffdhe4096: dhkex_class2
}
secret_keys = {
    NamedGroup.x25519: secret_key1,
    NamedGroup.ffdhe4096: secret_key2
}

# === Client Hello ====
client_hello = Handshake(
    msg_type=HandshakeType.client_hello,
    msg=ClientHello(
        cipher_suites=CipherSuites([
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
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
                        NamedGroup.x25519,
                        NamedGroup.ffdhe4096,
                    ])
                )
            ),
            Extension(
                extension_type=ExtensionType.signature_algorithms,
                extension_data=SignatureSchemeList(
                    supported_signature_algorithms=SignatureSchemes([
                        SignatureScheme.rsa_pss_rsae_sha256,
                        SignatureScheme.rsa_pss_rsae_sha384,
                        SignatureScheme.rsa_pss_rsae_sha512,
                    ])
                )
            ),
            Extension(
                extension_type=ExtensionType.key_share,
                extension_data=KeyShareHello(
                    shares=KeyShareEntrys([
                        KeyShareEntry(
                            group=NamedGroup.x25519,
                            key_exchange=OpaqueUint16(public_key1)
                        ),
                        KeyShareEntry(
                            group=NamedGroup.ffdhe4096,
                            key_exchange=OpaqueUint16(public_key2)
                        ),
                    ])
                )
            )
        ])
    )
)
ctx.append_msg(client_hello)

tlsplaintext = TLSPlaintext.create(ContentType.handshake, client_hello)
print(tlsplaintext)
print('[>>>] Send:')
print(hexdump(bytes(tlsplaintext)))
client_conn = connection.ClientConnection('localhost', 50007)
# client_conn = connection.ClientConnection('enabled.tls13.com', 443)
# '''
# GET / HTTP/1.1
# Host: enabled.tls13.com
# '''
client_conn.send_msg(bytes(tlsplaintext))

is_recv_serverhello = False
is_recv_finished = False

print("=== Handshake ===")
while True:
    buf = None
    while not buf:
        buf = client_conn.recv_msg(setblocking=True)

    print('[<<<] Recv:')
    print(hexdump(buf))

    stream = io.BytesIO(buf)

    while True:
        firstbyte = stream.read(1)
        if firstbyte == b'':
            break
        stream.seek(-1, io.SEEK_CUR)

        content_type = ContentType(Uint8(int.from_bytes(firstbyte, byteorder='big')))

        # Alert受信時
        if content_type == ContentType.alert:
            tlsplaintext = TLSPlaintext.from_fs(stream)
            for alert in tlsplaintext.get_messages():
                print('[-] Recv Alert!')
                print(alert)
            sys.exit(1)

        # 最初のデータはServerHello
        elif not is_recv_serverhello:
            # ServerHello
            tlsplaintext = TLSPlaintext.from_fs(stream)
            for msg in tlsplaintext.get_messages():
                print('[*] ServerHello!')
                print(msg)
                ctx.append_msg(msg)

            ctx.set_key_exchange(dhkex_classes, secret_keys)
            Hash.length = ctx.hash_size

            print('[+] shared key:', ctx.shared_key.hex())

            # Key Schedule
            ctx.key_schedule_in_handshake()

            is_recv_serverhello = True

        # ChangeCipherSpecはTLS 1.3では無視する
        elif content_type == ContentType.change_cipher_spec:
            # ChangeCipherSpec
            change_cipher_spec = TLSPlaintext.from_fs(stream)
            print(change_cipher_spec)

        # 暗号化されたHandshakeメッセージ
        elif content_type == ContentType.application_data:
            # EncryptedExtensions, Certificate, CertificateVerify, Finished
            print("Got!")

            tlsplaintext = TLSCiphertext.from_fs(stream) \
                                        .decrypt(ctx.server_traffic_crypto)
            # print(tlsplaintext)
            for msg in tlsplaintext.get_messages():
                ctx.append_msg(msg)
                print(msg)

                if msg.msg_type == HandshakeType.finished:
                    print('[*] Received Finished!')
                    is_recv_finished = True
                    break

    if is_recv_finished:
        break

# verify received Finished
msgs_byte = b''.join(ctx.tls_messages_bytes[:-1]) # 最後の受信したFinished以外のメッセージ
finished_key = hkdf.HKDF_expand_label(
    ctx.server_hs_traffic_secret, b'finished', b'', ctx.hash_size, ctx.hash_name)
expected_verify_data = hkdf.secure_HMAC(
    finished_key, hkdf.transcript_hash(msgs_byte, ctx.hash_name), ctx.hash_name)
actual_verify_data = \
    ctx.tls_messages.get(HandshakeType.finished).msg.verify_data.get_raw_bytes()

if actual_verify_data != expected_verify_data:
    print('decrypt_error!')
    # TODO: create and send Alert msg
    sys.exit(0)

# Finished
msgs_byte = ctx.get_messages_byte()
finished_key = hkdf.HKDF_expand_label(
    ctx.client_hs_traffic_secret, b'finished', b'', ctx.hash_size, ctx.hash_name)
verify_data = hkdf.secure_HMAC(
    finished_key, hkdf.transcript_hash(msgs_byte, ctx.hash_name), ctx.hash_name)

finished = Handshake(
    msg_type=HandshakeType.finished,
    msg=Finished(
        verify_data=OpaqueHash(bytes(verify_data))
    )
)
print(finished)

tlsciphertext = TLSPlaintext.create(ContentType.handshake, finished) \
    .encrypt(ctx.client_traffic_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))
client_conn.send_msg(bytes(tlsciphertext))

# Key Schedule
ctx.key_schedule_in_app_data()

loop_keyboard_input = True

def read_keyboard_input(inputQueue):
    print('Ready for keyboard input:')
    while loop_keyboard_input:
        input_str = input()
        inputQueue.put(input_str + "\n")

inputQueue = queue.Queue()
inputThread = threading.Thread(target=read_keyboard_input,
                               args=(inputQueue,), daemon=True)
inputThread.start()

print("=== Application Data ===")
try:
    while True:

        buf = None
        while not buf:
            buf = client_conn.recv_msg(setblocking=False)

            # 受信待機時にクライアント側から入力があれば送信する
            if inputQueue.qsize() > 0:
                input_byte = inputQueue.get().encode()
                tlsciphertext = \
                    TLSPlaintext.create(ContentType.application_data, input_byte) \
                    .encrypt(ctx.client_app_data_crypto)
                print(tlsciphertext)
                print('[>>>] Send:')
                print(hexdump(bytes(tlsciphertext)))

                client_conn.send_msg(bytes(tlsciphertext))

        print('[<<<] Recv:')
        print(hexdump(buf))

        stream = io.BytesIO(buf)

        while True:
            firstbyte = stream.read(1)
            if firstbyte == b'':
                break
            stream.seek(-1, io.SEEK_CUR)

            content_type = \
                ContentType(Uint8(int.from_bytes(firstbyte, byteorder='big')))

            # Alert受信時
            if content_type == ContentType.alert:
                tlsplaintext = TLSPlaintext.from_fs(stream)
                for alert in tlsplaintext.get_messages():
                    print('[-] Recv Alert!')
                    print(alert)
                sys.exit(1)

            # ApplicationData(暗号化データ)受信時
            elif content_type == ContentType.application_data:
                obj = TLSCiphertext.from_fs(stream) \
                    .decrypt(ctx.server_app_data_crypto)
                print(obj)

                if isinstance(obj.fragment, Handshake):
                    # New Session Ticket
                    print('[+] New Session Ticket arrived!')
                    ctx.append_msg(obj)

                else:
                    print(bytes(obj.fragment))

except KeyboardInterrupt:
    print('\nBye!')

# Closure Alert
closure_alert = Alert(
    level=AlertLevel.fatal,
    description=AlertDescription.close_notify
)

tlsciphertext = TLSPlaintext.create(ContentType.alert, closure_alert) \
    .encrypt(ctx.client_app_data_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))
client_conn.send_msg(bytes(tlsciphertext))

loop_keyboard_input = False

client_conn.close()

# memo:
#
# openssl_server
#   ~/local/bin/openssl s_server -accept 50007 \
#     -cert ./cert/server.crt -key ./cert/server.key -tls1_3 -state -debug
# openssl_make
#   cd ~/local/download/openssl-OpenSSL_1_1_1c/build
#   make -j4 && make install_runtime install_dev
# client
#   python client.py
