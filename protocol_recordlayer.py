# ------------------------------------------------------------------------------
# Record Layer
#   - RFC 8446 #section-5.1 (Record Layer)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
#   - RFC 8446 #section-5.2 (Record Payload Protection)
#     * https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
# ------------------------------------------------------------------------------

import io
from metatype import Uint8, Uint16, Opaque, OpaqueLength, OpaqueLength
import metastruct as meta
from protocol_types import ContentType
from protocol_handshake import Handshake, HandshakeType
from protocol_alert import Alert

ProtocolVersion = Uint16

### TLSPlaintext ###
# struct {
#     ContentType type;
#     ProtocolVersion legacy_record_version;
#     uint16 length;
#     opaque fragment[TLSPlaintext.length];
# } TLSPlaintext;
#
@meta.struct
class TLSPlaintext(meta.MetaStruct):
    type: ContentType
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.fragment)))
    fragment: OpaqueLength

    @classmethod
    def create(self, content_type: ContentType, *messages) -> meta.MetaStruct:
        assert isinstance(content_type, ContentType)
        messages_byte = b''.join(bytes(msg) for msg in messages)
        return TLSPlaintext(
            type=content_type,
            fragment=OpaqueLength(messages_byte)
        )

    def encrypt(self, cipher_instance) -> meta.MetaStruct:
        msg_pad = TLSInnerPlaintext.append_pad(self)
        tag_size = cipher_instance.__class__.tag_size
        aad = bytes.fromhex('170303') + bytes(Uint16(len(bytes(msg_pad)) + tag_size))
        encrypted_record = cipher_instance.encrypt_and_tag(msg_pad, aad)
        return TLSCiphertext(
            encrypted_record=OpaqueLength(bytes(encrypted_record))
        )

    def get_messages(self) -> list:
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
            messages.append(elem_t.from_stream(stream))
        return messages


### TLSCiphertext ###
# struct {
#     ContentType opaque_type = application_data; /* 23 */
#     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
#     uint16 length;
#     opaque encrypted_record[TLSCiphertext.length];
# } TLSCiphertext;
#
@meta.struct
class TLSCiphertext(meta.MetaStruct):
    opaque_type: ContentType = ContentType.application_data
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.encrypted_record)))
    encrypted_record: OpaqueLength

    def decrypt(self, cipher_instance) -> TLSPlaintext:
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
    def _decrypt_app_data(self, plaindata, content_type) -> TLSPlaintext:
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


### TLSInnerPlaintext ###
# struct {
#     opaque content[TLSPlaintext.length];
#     ContentType type;
#     uint8 zeros[length_of_padding];
# } TLSInnerPlaintext;
#
class TLSInnerPlaintext:
    @staticmethod
    def append_pad(tlsplaintext) -> bytes:
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
