
# python 3.7 >= is required!

import os
import sys
import io
import threading
import queue

import connection
from type import Uint8, Uint16, OpaqueUint16, OpaqueLength
from disp import hexdump

from protocol_tlscontext import TLSContext
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
from protocol_alert import Alert

from crypto_x25519 import x25519
import crypto_hkdf as hkdf

ctx = TLSContext()

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
    ctx.append_msg(msg)

server_conn.close()
