
# python 3.7 >= is required!

import os
import io

import connection
from type import Uint8, Uint16, OpaqueUint16, OpaqueLength
from disp import hexdump

from protocol_types import ContentType, HandshakeType
from protocol_recordlayer import TLSPlaintext, TLSCiphertext, TLSInnerPlaintext
from protocol_handshake import Handshake
from protocol_hello import ClientHello
from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType
from protocol_ext_version import SupportedVersions, \
    ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, \
    SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareHello, \
    KeyShareEntrys, KeyShareEntry, OpaqueUint16
from protocol_authentication import Finished, Hash, OpaqueHash

from crypto_x25519 import x25519
import crypto_hkdf as hkdf

messages = bytearray(0)
tls_messages = {}

secret_key = os.urandom(32)
public_key = x25519(secret_key)

client_hello = TLSPlaintext(
    type=ContentType.handshake,
    fragment=Handshake(
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
                            NamedGroup.x25519
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
                                key_exchange=OpaqueUint16(public_key)
                            )
                        ])
                    )
                )
            ])
        )
    )
)
tls_messages['ClientHello'] = client_hello
messages += bytes(client_hello.fragment)

print(client_hello)
print('[>>>] Send:')
print(hexdump(bytes(client_hello)))

client_conn = connection.ClientConnection('localhost', 50007)
client_conn.send_msg(bytes(client_hello))

buf = None
while not buf:
    buf = client_conn.recv_msg()
print('[<<<] Recv:')
print(hexdump(buf))

stream = io.BytesIO(buf)

# Server Hello
server_hello = TLSPlaintext.from_fs(stream)
print(server_hello)
tls_messages['ServerHello'] = server_hello
messages += bytes(server_hello.fragment)

cipher_suite = server_hello.fragment.msg.cipher_suite
for ext in server_hello.fragment.msg.extensions:
    if ext.extension_type == ExtensionType.key_share:
        server_share = ext.extension_data.shares

client_share = client_hello.fragment.msg \
    .extensions.find(lambda ext: ext.extension_type == ExtensionType.key_share) \
    .extension_data.shares.find(lambda keyshare: keyshare.group == server_share.group)

shared_key = x25519(secret_key, server_share.key_exchange.get_raw_bytes())
print('[+] shared key:', shared_key.hex())

# --- Key Schedule ---
# https://tools.ietf.org/html/rfc8446#section-7.1

hash_name   = CipherSuite.get_hash_name(cipher_suite)
secret_size = CipherSuite.get_hash_size(cipher_suite)
secret = bytearray(secret_size)
psk    = bytearray(secret_size)

hash_size = hkdf.hash_size(hash_name)
Hash.length = hash_size

# early secret
secret = hkdf.HKDF_extract(secret, psk, hash_name)
print('[+] early secret:', secret.hex())

# handshake secret
secret = hkdf.derive_secret(secret, b'derived', b'', hash_name)
secret = hkdf.HKDF_extract(secret, shared_key, hash_name)
print('[+] handshake secret:', secret.hex())

client_hs_traffic_secret = \
    hkdf.derive_secret(secret, b'c hs traffic', messages, hash_name)
server_hs_traffic_secret = \
    hkdf.derive_secret(secret, b's hs traffic', messages, hash_name)
print('[+] c hs traffic:', client_hs_traffic_secret.hex())
print('[+] s hs traffic:', server_hs_traffic_secret.hex())

from crypto_chacha20poly1305 import Chacha20Poly1305

if cipher_suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
    cipher_class = Chacha20Poly1305
    key_size   = cipher_class.key_size
    nonce_size = cipher_class.nonce_size
    tag_size   = cipher_class.tag_size

client_write_key, client_write_iv = \
    hkdf.gen_key_and_iv(client_hs_traffic_secret, key_size, nonce_size, hash_name)
client_traffic_crypto = cipher_class(key=client_write_key, nonce=client_write_iv)

server_write_key, server_write_iv = \
    hkdf.gen_key_and_iv(server_hs_traffic_secret, key_size, nonce_size, hash_name)
server_traffic_crypto = cipher_class(key=server_write_key, nonce=server_write_iv)

print('[+] client_write_key:', client_write_key.hex())
print('[+] client_write_iv:', client_write_iv.hex())
print('[+] server_write_key:', server_write_key.hex())
print('[+] server_write_iv:', server_write_iv.hex())

while True:
    firstbyte = stream.read(1)
    if firstbyte == b'':
        break
    stream.seek(-1, io.SEEK_CUR)

    content_type = ContentType(Uint8(int.from_bytes(firstbyte, byteorder='big')))

    if content_type == ContentType.change_cipher_spec:
        # ChangeCipherSpec
        change_cipher_spec = TLSPlaintext.from_fs(stream)
        print(change_cipher_spec)
        # tls_messages['ChangeCipherSpec'] = change_cipher_spec

    elif content_type in (ContentType.handshake, ContentType.application_data):
        # EncryptedExtensions, Certificate, CertificateVerify, Finished

        obj = TLSCiphertext.from_fs(stream).decrypt(server_traffic_crypto)
        print(obj)
        tls_messages[obj.fragment.msg.__class__.__name__] = obj
        messages += bytes(obj.fragment)

# Finished
finished_key = hkdf.HKDF_expand_label(client_hs_traffic_secret,
                                      b'finished', b'', hash_size, hash_name)
verify_data = hkdf.secure_HMAC(finished_key,
                               hkdf.transcript_hash(messages, hash_name),
                               hash_name)
finished = TLSPlaintext(
    type=ContentType.handshake,
    fragment=Handshake(
        msg_type=HandshakeType.finished,
        msg=Finished(
            verify_data=OpaqueHash(bytes(verify_data))
        )
    )
)
print(finished)
print(hexdump(bytes(finished)))

tlsciphertext = finished.encrypt(client_traffic_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))

client_conn.send_msg(bytes(tlsciphertext))

# --- Key Schedule ---

# master secret
secret = hkdf.derive_secret(secret, b'derived', b'')
secret = hkdf.HKDF_extract(secret, bytearray(secret_size), hash_name)
print('[+] master secret:', secret.hex())

client_app_traffic_secret = \
    hkdf.derive_secret(secret, b'c ap traffic', messages, hash_name)
server_app_traffic_secret = \
    hkdf.derive_secret(secret, b's ap traffic', messages, hash_name)

print('[+] c ap traffic:', client_app_traffic_secret.hex())
print('[+] s ap traffic:', server_app_traffic_secret.hex())

client_app_write_key, client_app_write_iv = \
    hkdf.gen_key_and_iv(client_app_traffic_secret, key_size, nonce_size, hash_name)
server_app_write_key, server_app_write_iv = \
    hkdf.gen_key_and_iv(server_app_traffic_secret, key_size, nonce_size, hash_name)

client_app_data_crypto = cipher_class(
        key=client_app_write_key, nonce=client_app_write_iv)
server_app_data_crypto = cipher_class(
        key=server_app_write_key, nonce=server_app_write_iv)

print('[+] client_app_write_key:', client_app_write_key.hex())
print('[+] client_app_write_iv:', client_app_write_iv.hex())
print('[+] server_app_write_key:', server_app_write_key.hex())
print('[+] server_app_write_iv:', server_app_write_iv.hex())

buf = None
while not buf:
    buf = client_conn.recv_msg()
print('[<<<] Recv:')
print(hexdump(buf))

stream = io.BytesIO(buf)

# New Session Ticket
print('--- (1) ------------------------------------------------------------')
obj = TLSCiphertext.from_fs(stream).decrypt(server_app_data_crypto)
print(obj)
tls_messages[obj.fragment.msg.__class__.__name__] = obj
messages += bytes(obj.fragment)

# TODO: derive_secret
# handshake_hash.update() # .fragment のバイト列を追加していく方法

# import time
# time.sleep(1)

print("=== Application Data ===")

# GET / HTTP/1.1

app_data = TLSPlaintext(
    type=ContentType.application_data,
    fragment=OpaqueLength(b'GET / HTTP/1.1\n')
)
print(app_data)
print(hexdump(bytes(app_data)))

tlsciphertext = app_data.encrypt(client_app_data_crypto)
print(tlsciphertext)
print(hexdump(bytes(tlsciphertext)))

client_conn.send_msg(bytes(tlsciphertext))

# Recv html file

# data = client_conn.recv_msg()
buf = None
while not buf:
    buf = client_conn.recv_msg()
print('[<<<] Recv:')
print(hexdump(buf))

stream = io.BytesIO(buf)

# OpanSSLのTLS 1.3サーバはNewSessionTicketを2回送るという謎の挙動をするので
# New Session Ticket
print('--- (2) ------------------------------------------------------------')
obj = TLSCiphertext.from_fs(stream).decrypt(server_app_data_crypto)
print(obj)

buf = None
while not buf:
    buf = client_conn.recv_msg()
print('[<<<] Recv:')
print(hexdump(buf))

stream = io.BytesIO(buf)

obj = TLSCiphertext.from_fs(stream).decrypt(server_app_data_crypto)
print(obj.fragment)


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
