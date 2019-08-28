
from type import Uint8, Uint16, Opaque, OpaqueUint16, OpaqueLength
import structmeta as meta

from protocol_types import ContentType
from protocol_handshake import Handshake, HandshakeType
from protocol_alert import Alert

# ------------------------------------------------------------------------------
# Record Layer

ProtocolVersion = Uint16

@meta.struct
class TLSPlaintext(meta.StructMeta):
    type: ContentType
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(self.fragment))
    fragment: meta.Select('type', cases={
        ContentType.handshake: Handshake,
        ContentType.change_cipher_spec: OpaqueLength,
        ContentType.alert: Alert,
    })

    def encrypt(self, cipher_instance):
        msg_pad = TLSInnerPlaintext.append_pad(self)
        tag_size = cipher_instance.__class__.tag_size
        aad = bytes.fromhex('170303') + bytes(Uint16(len(bytes(msg_pad)) + tag_size))
        encrypted_record = cipher_instance.encrypt_and_tag(msg_pad, aad)
        return TLSCiphertext(
            encrypted_record=OpaqueUint16(bytes(encrypted_record))
        )

@meta.struct
class TLSCiphertext(meta.StructMeta):
    opaque_type: ContentType = ContentType.application_data
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    encrypted_record: Opaque(Uint16)

    def decrypt(self, cipher_instance):
        encrypted_record = self.encrypted_record.get_raw_bytes()
        aad = bytes.fromhex('170303') + bytes(Uint16(len(encrypted_record)))
        plaindata = cipher_instance.decrypt_and_verify(encrypted_record, aad)
        plaindata, content_type = TLSInnerPlaintext.split_pad(plaindata)
        # print(hexdump(bytes(plaindata)))
        if content_type == ContentType.application_data:
            return self._decrypt_app_data(plaindata, content_type)

        return TLSPlaintext(
            type=content_type,
            fragment=Handshake.from_bytes(plaindata)
        )

    # Application Data を受信したとき
    def _decrypt_app_data(self, plaindata, content_type):
        # NewSessionTicketを受け取った場合
        if plaindata[:2] == bytes(HandshakeType.new_session_ticket) + b'\x00':
            return TLSPlaintext(
                type=content_type,
                fragment=Handshake.from_bytes(plaindata)
            )
        # それ以外は通信データ
        else:
            return TLSPlaintext(
                type=content_type,
                length=len(plaindata),
                fragment=OpaqueLength(bytes(plaindata))
            )

class TLSInnerPlaintext:
    @staticmethod
    def append_pad(tlsplaintext):
        data = bytes(tlsplaintext.fragment) + bytes(tlsplaintext.type)
        length_of_padding = 16 - len(data) % 16
        pad = b'\x00' * length_of_padding
        return data + pad

    @staticmethod
    def split_pad(data):
        for pos, value in zip(reversed(range(len(data))), reversed(data)):
            if value != 0:
                break
        return data[:pos], ContentType(Uint8(value)) #, data[pos+1:]
        # content, type, zeros


if __name__ == '__main__':

    from type import Uint24
    from protocol_hello import \
        ClientHello, Random, OpaqueUint8, CipherSuites, CipherSuite, Extensions
    from protocol_handshake import Handshake, HandshakeType

    import unittest

    class TestUint(unittest.TestCase):

        def test_recordlayer(self):

            ch = ClientHello(
                random=Random(bytes.fromhex('AA' * 32)),
                legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                cipher_suites=CipherSuites([
                    CipherSuite.TLS_AES_256_GCM_SHA384,
                    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                legacy_compression_methods=OpaqueUint8(b'\x00'),
                extensions=Extensions([]),
            )

            h = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=ch)

            plain = TLSPlaintext(
                type=ContentType.handshake,
                fragment=h)

            self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

    unittest.main()
