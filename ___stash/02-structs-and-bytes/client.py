
import os

import connection
from disp import hexdump

from protocol_types import ContentType, HandshakeType
from protocol_recordlayer import TLSPlaintext
from protocol_handshake import Handshake
from protocol_hello import ClientHello
from protocol_ciphersuite import CipherSuites, CipherSuite
from protocol_extensions import Extensions, Extension, ExtensionType
from protocol_ext_version import SupportedVersions, \
    ProtocolVersions, ProtocolVersion
from protocol_ext_supportedgroups import NamedGroupList, NamedGroups, NamedGroup
from protocol_ext_signature import SignatureSchemeList, \
    SignatureSchemes, SignatureScheme
from protocol_ext_keyshare import KeyShareClientHello, \
    KeyShareEntrys, KeyShareEntry, OpaqueUint16

from crypto_x25519 import x25519

messages = bytearray(0)

secretkey = os.urandom(32)
publickey = x25519(secretkey)

client_hello = TLSPlaintext(
    type=ContentType.handshake,
    fragment=Handshake(
        msg_type=HandshakeType.client_hello,
        msg=ClientHello(
            cipher_suites=CipherSuites([
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            ]),
            extensions=Extensions([
                Extension(
                    extension_type=ExtensionType.supported_versions,
                    extension_data=SupportedVersions(
                        version=ProtocolVersions([
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
                            SignatureScheme.ed25519
                        ])
                    )
                ),
                Extension(
                    extension_type=ExtensionType.key_share,
                    extension_data=KeyShareClientHello(
                        client_shares=KeyShareEntrys([
                            KeyShareEntry(
                                group=NamedGroup.x25519,
                                key_exchange=OpaqueUint16(publickey)
                            )
                        ])
                    )
                )
            ])
        )
    )
)

print(client_hello)
print(hexdump(bytes(client_hello)))

client_conn = connection.ClientConnection('tls13.pinterjann.is', 443)
client_conn.send_msg(bytes(client_hello))
data = client_conn.recv_msg()
print('Received:')
print(hexdump(data))

client_conn.close()
