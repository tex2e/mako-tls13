
# python 3.7 >= is required!

import os
import sys
import io
import threading
import queue
import ssl

import connection
from type import Uint8, Uint16, OpaqueUint8, OpaqueUint16, OpaqueUint24, OpaqueLength
from disp import hexdump

from protocol_tlscontext import TLSContext
from protocol_types import ContentType, HandshakeType
from protocol_recordlayer import TLSPlaintext, TLSCiphertext, TLSInnerPlaintext
from protocol_handshake import Handshake
from protocol_hello import ServerHello
from protocol_ciphersuite import CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType, \
    EncryptedExtensions
from protocol_ext_version import SupportedVersions, \
    ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, \
    SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareHello, KeyShareEntrys, KeyShareEntry
from protocol_authentication import Certificate, \
    CertificateEntrys, CertificateEntry, \
    CertificateVerify, \
    Finished, Hash, OpaqueHash
from protocol_alert import Alert

from crypto_x25519 import x25519
import crypto_hkdf as hkdf

ctx = TLSContext('server')

dhkex_class = x25519

secret_key = os.urandom(32)
public_key = dhkex_class(secret_key)

server_conn = connection.ServerConnection('localhost', 50007)

buf = server_conn.recv_msg(setblocking=True)
print('[<<<] Recv:')
print(hexdump(buf))

stream = io.BytesIO(buf)

# 最初のデータはClientHello
for msg in TLSPlaintext.from_fs(stream).get_messages():
    print('[*] ClientHello!')
    print(msg)
    print(hexdump(bytes(msg)))
    ctx.append_msg(msg)

# CipherSuite は chacha20poly1305 しか対応していないので
client_hello = ctx.tls_messages.get(HandshakeType.client_hello)
has_chacha20poly1305 = client_hello.msg.cipher_suites \
    .find(lambda suite: suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256)
if not has_chacha20poly1305:
    print('handshake_failure')
    sys.exit(0)

server_hello = Handshake(
    msg_type=HandshakeType.server_hello,
    msg=ServerHello(
        cipher_suite=CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        legacy_session_id_echo=client_hello.msg.legacy_session_id,
        extensions=Extensions([
            Extension(
                extension_type=ExtensionType.supported_versions,
                extension_data=SupportedVersions(
                    versions=ProtocolVersion.TLS13
                )
            ),
            Extension(
                extension_type=ExtensionType.key_share,
                extension_data=KeyShareHello(
                    shares=KeyShareEntry(
                        group=NamedGroup.x25519,
                        key_exchange=OpaqueUint16(public_key)
                    )
                )
            )
        ])
    )
)
ctx.append_msg(server_hello)
print(server_hello)

# Key Schedule
ctx.set_key_exchange(dhkex_class, secret_key)
ctx.key_schedule_in_handshake()
Hash.length = ctx.hash_size

tlsplaintext = TLSPlaintext(
    type=ContentType.handshake,
    fragment=OpaqueLength(bytes(server_hello))
)
print('[>>>] Send:')
print(hexdump(bytes(tlsplaintext)))

server_conn.send_msg(bytes(tlsplaintext))

# create EncryptedExtensions
encrypted_extensions = Handshake(
    msg_type=HandshakeType.encrypted_extensions,
    msg=EncryptedExtensions(extensions=Extensions([]))
)
ctx.append_msg(encrypted_extensions)
print(encrypted_extensions)

# create Certificate
with open('cert/server.crt', 'r') as f:
    cert_data = ssl.PEM_cert_to_DER_cert(f.read())

certificate = Handshake(
    msg_type=HandshakeType.certificate,
    msg=Certificate(
        certificate_request_context=OpaqueUint8(b''),
        certificate_list=CertificateEntrys([
            CertificateEntry(
                cert_data=OpaqueUint24(cert_data),
                extensions=Extensions([])
            )
        ])
    )
)
ctx.append_msg(certificate)
print(certificate)
print(hexdump(bytes(certificate)))

# create CertificateVerify
# 秘密鍵 cert/server.key を使って証明書に署名する
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
key = RSA.importKey(open('cert/server.key').read())
client_signature_scheme_list = \
    ctx.tls_messages.get(HandshakeType.client_hello).msg.extensions \
    .find(lambda ext: ext.extension_type == ExtensionType.signature_algorithms) \
    .extension_data.supported_signature_algorithms
print(client_signature_scheme_list)

if SignatureScheme.rsa_pss_rsae_sha256 in client_signature_scheme_list:
    server_signature_scheme = SignatureScheme.rsa_pss_rsae_sha256
    from Crypto.Signature import PKCS1_PSS
    message = b'\x20' * 64 + b'TLS 1.3, server CertificateVerify' \
        + b'\x00' + hkdf.transcript_hash(ctx.get_messages_byte(), ctx.hash_name)
    print("message:")
    print(hexdump(message))
    h = SHA256.new(message)
    certificate_signature = PKCS1_PSS.new(key).sign(h)
else:
    raise NotImplementedError()

certificate_verify = Handshake(
    msg_type=HandshakeType.certificate_verify,
    msg=CertificateVerify(
        algorithm=server_signature_scheme,
        signature=OpaqueUint16(certificate_signature)
    )
)
ctx.append_msg(certificate_verify)
print(certificate_verify)

# TODO: create Finished
msgs_byte = ctx.get_messages_byte()
finished_key = hkdf.HKDF_expand_label(
    ctx.server_hs_traffic_secret, b'finished', b'', ctx.hash_size, ctx.hash_name)
verify_data = hkdf.secure_HMAC(
    finished_key, hkdf.transcript_hash(msgs_byte, ctx.hash_name), ctx.hash_name)
finished = Handshake(
    msg_type=HandshakeType.finished,
    msg=Finished(
        verify_data=OpaqueHash(bytes(verify_data))
    )
)
ctx.append_msg(finished)
print(finished)


tlsplaintext = TLSPlaintext(
    type=ContentType.handshake,
    fragment=OpaqueLength(
        bytes(encrypted_extensions) + bytes(certificate) +
        bytes(certificate_verify) + bytes(finished)
    )
)
tlsciphertext = tlsplaintext.encrypt(ctx.server_traffic_crypto)
print('[>>>] Send:')
print(hexdump(bytes(tlsciphertext)))

server_conn.send_msg(bytes(tlsciphertext))


while True:
    pass

server_conn.close()


# ~/local/bin/openssl s_client -connect 127.0.0.1:50007 -state -debug -tls1_3
