
import io
from type import Uint8, Uint16, Opaque, OpaqueLength, OpaqueLength
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
    length: Uint16 = lambda self: Uint16(len(bytes(self.fragment)))
    fragment: OpaqueLength

    @classmethod
    def create(self, content_type, *messages):
        assert isinstance(content_type, ContentType)
        messages_byte = b''.join(bytes(msg) for msg in messages)
        return TLSPlaintext(
            type=content_type,
            fragment=OpaqueLength(messages_byte)
        )

    def encrypt(self, cipher_instance):
        msg_pad = TLSInnerPlaintext.append_pad(self)
        tag_size = cipher_instance.__class__.tag_size
        aad = bytes.fromhex('170303') + bytes(Uint16(len(bytes(msg_pad)) + tag_size))
        encrypted_record = cipher_instance.encrypt_and_tag(msg_pad, aad)
        return TLSCiphertext(
            encrypted_record=OpaqueLength(bytes(encrypted_record))
        )

    def get_messages(self):
        contenttype2class = {
            ContentType.handshake:          Handshake,
            ContentType.change_cipher_spec: OpaqueLength,
            ContentType.alert:              Alert,
        }
        elem_t = contenttype2class.get(self.type)

        # 複数のHandshakeメッセージは結合して一つのTLSPlaintextで送ることができる
        # https://tools.ietf.org/html/rfc8446#section-5.1
        messages = []
        stream_len = len(self.fragment.get_raw_bytes())
        stream = io.BytesIO(self.fragment.get_raw_bytes())
        while stream.tell() < stream_len:
            messages.append(elem_t.from_fs(stream))
        return messages

@meta.struct
class TLSCiphertext(meta.StructMeta):
    opaque_type: ContentType = ContentType.application_data
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.encrypted_record)))
    encrypted_record: OpaqueLength

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
            fragment=OpaqueLength(bytes(plaindata))
        )

    # Application Data を受信したとき
    def _decrypt_app_data(self, plaindata, content_type):
        # NewSessionTicketを受け取った場合
        if plaindata[:2] == bytes(HandshakeType.new_session_ticket) + b'\x00':
            return TLSPlaintext(
                type=content_type,
                fragment=OpaqueLength(bytes(plaindata))
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
        ClientHello, ServerHello, \
        Random, Opaque1, OpaqueUint8, CipherSuites, CipherSuite, Extensions
    from protocol_handshake import Handshake, HandshakeType

    import unittest

    class TestUint(unittest.TestCase):

        def test_recordlayer(self):

            h = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=ClientHello(
                    random=Random(bytes.fromhex('AA' * 32)),
                    legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                    cipher_suites=CipherSuites([
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                    legacy_compression_methods=OpaqueUint8(b'\x00'),
                    extensions=Extensions([]),
                ))

            plain = TLSPlaintext(
                type=ContentType.handshake,
                fragment=OpaqueLength(bytes(h)))

            plain_bytes = bytes.fromhex('''
                16 03 03 00 53 01 00 00  4F 03 03 AA AA AA AA AA
                AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA
                AA AA AA AA AA AA AA AA  AA AA AA 20 BB BB BB BB
                BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB
                BB BB BB BB BB BB BB BB  BB BB BB BB 00 06 13 02
                13 03 00 FF 01 00 00 00
            ''')

            self.assertEqual(bytes(plain), plain_bytes)
            self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

            messages = plain.get_messages()
            self.assertEqual(messages[0], h)

        def test_recordlayer_multiple_messages(self):

            h1 = Handshake(
                msg_type=HandshakeType.client_hello,
                msg=ClientHello(
                    random=Random(bytes.fromhex('AA' * 32)),
                    legacy_session_id=OpaqueUint8(bytes.fromhex('BB' * 32)),
                    cipher_suites=CipherSuites([
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
                    legacy_compression_methods=OpaqueUint8(b'\x00'),
                    extensions=Extensions([]),
                ))
            h2 = Handshake(
                msg_type=HandshakeType.server_hello,
                msg=ServerHello(
                    random=Random(bytes.fromhex('CC' * 32)),
                    legacy_session_id_echo=OpaqueUint8(bytes.fromhex('DD' * 32)),
                    cipher_suite=CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    legacy_compression_method=Opaque1(b'\x00'),
                    extensions=Extensions([]),
                ))

            plain = TLSPlaintext(
                type=ContentType.handshake,
                fragment=OpaqueLength(bytes(h1) + bytes(h2)))

            plain_bytes = bytes.fromhex('''
                16 03 03 00 9F
                01 00 00 4F 03 03 AA AA  AA AA AA AA AA AA AA AA
                AA AA AA AA AA AA AA AA  AA AA AA AA AA AA AA AA
                AA AA AA AA AA AA 20 BB  BB BB BB BB BB BB BB BB
                BB BB BB BB BB BB BB BB  BB BB BB BB BB BB BB BB
                BB BB BB BB BB BB BB 00  06 13 02 13 03 00 FF 01
                00 00 00
                02 00 00 48 03 03 CC CC  CC CC CC CC CC CC CC CC
                CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC
                CC CC CC CC CC CC 20 DD  DD DD DD DD DD DD DD DD
                DD DD DD DD DD DD DD DD  DD DD DD DD DD DD DD DD
                DD DD DD DD DD DD DD 13  03 00 00 00
            ''')

            self.assertEqual(bytes(plain), plain_bytes)
            self.assertEqual(TLSPlaintext.from_bytes(bytes(plain)), plain)

            messages = plain.get_messages()
            self.assertEqual(messages[0], h1)
            self.assertEqual(messages[1], h2)

    unittest.main()
