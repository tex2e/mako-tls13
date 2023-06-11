# ------------------------------------------------------------------------------
# TLS Extensions
#   - RFC 8446 #section-4.2 (Extensions)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
#   - RFC 8446 #section-4.3.1 (Encrypted Extensions)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
# ------------------------------------------------------------------------------

from metatype import Uint16, List, EnumUnknown, OpaqueLength
import metastruct as meta

from protocol_ext_version import SupportedVersions
from protocol_ext_supportedgroups import NamedGroupList
from protocol_ext_keyshare import KeyShareHello
from protocol_ext_signature import SignatureSchemeList
from protocol_ext_quic_transportparam import QuicTransportParams  # [QUIC]

### ExtensionType ###
# enum {
#     server_name(0),
#     max_fragment_length(1),
#     status_request(5),
#     ...
#     (65535)
# } ExtensionType;
#
class ExtensionType(EnumUnknown):
    elem_t = Uint16  # (65535)

    server_name = Uint16(0)
    max_fragment_length = Uint16(1)
    status_request = Uint16(5)
    supported_groups = Uint16(10)
    signature_algorithms = Uint16(13)
    use_srtp = Uint16(14)
    heartbeat = Uint16(15)
    application_layer_protocol_negotiation = Uint16(16)
    signed_certificate_timestamp = Uint16(18)
    client_certificate_type = Uint16(19)
    server_certificate_type = Uint16(20)
    padding = Uint16(21)
    #RESERVED = Uint16(40)
    pre_shared_key = Uint16(41)
    early_data = Uint16(42)
    supported_versions = Uint16(43)
    cookie = Uint16(44)
    psk_key_exchange_modes = Uint16(45)
    #RESERVED = Uint16(46)
    certificate_authorities = Uint16(47)
    oid_filters = Uint16(48)
    post_handshake_auth = Uint16(49)
    signature_algorithms_cert = Uint16(50)
    key_share = Uint16(51)
    renegotiation_info = Uint16(0xff01) # 再ネゴシエーションに対応済みを表す (RFC 5746)

    quic_transport_parameters = Uint16(0x39)  # QUIC Transport Parameters Extension

### Extension ###
# struct {
#     ExtensionType extension_type;
#     opaque extension_data<0..2^16-1>;
# } Extension;
#
@meta.struct
class Extension(meta.MetaStruct):
    extension_type: ExtensionType
    length: Uint16 = lambda self: Uint16(len(bytes(self.extension_data)))
    extension_data: meta.Select('extension_type', cases={
        ExtensionType.supported_versions: SupportedVersions,
        ExtensionType.supported_groups: NamedGroupList,
        ExtensionType.key_share: KeyShareHello,
        ExtensionType.signature_algorithms: SignatureSchemeList,
        ExtensionType.quic_transport_parameters: QuicTransportParams,  # [QUIC]
        meta.Otherwise: OpaqueLength,
    })

Extensions = List(size_t=Uint16, elem_t=Extension)


# ------------------------------------------------------------------------------
# Server Parameters

### EncryptedExtensions ###
# struct {
#     Extension extensions<0..2^16-1>;
# } EncryptedExtensions;
#
@meta.struct
class EncryptedExtensions(meta.MetaStruct):
    extensions: Extensions


# ------------------------------------------------------------------------------
if __name__ == '__main__':

    from protocol_ext_supportedgroups import NamedGroups, NamedGroup

    import unittest

    class TestUint(unittest.TestCase):

        def test_extension(self):

            e = Extension(
                extension_type=ExtensionType.supported_groups,
                extension_data=NamedGroupList(
                    named_group_list=NamedGroups([
                        NamedGroup.x25519, NamedGroup.secp256r1,
                    ])
                )
            )

            self.assertEqual(bytes(e)[:2], bytes(ExtensionType.supported_groups))
            self.assertEqual(Extension.from_bytes(bytes(e)), e)

        def test_encrypted_extensions(self):

            ee = EncryptedExtensions(
                extensions=Extensions([
                    Extension(
                        extension_type=ExtensionType.supported_groups,
                        extension_data=NamedGroupList(
                            named_group_list=NamedGroups([
                                NamedGroup.x25519, NamedGroup.secp256r1,
                            ])
                        )
                    )
                ])
            )

            self.assertEqual(EncryptedExtensions.from_bytes(bytes(ee)), ee)

    unittest.main()
