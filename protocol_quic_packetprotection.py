
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # pip install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_hkdf import HKDF_extract, HKDF_expand_label
from protocol_quic_longpacket import PacketType
from utils import hexdump, bytexor

# QUIC version 1
initial_salt = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')

# --- 鍵導出 ---

def get_key_iv_hp(cs_initial_secret):
    cs_key = HKDF_expand_label(cs_initial_secret, b'quic key', b'', 16)
    cs_iv = HKDF_expand_label(cs_initial_secret, b'quic iv', b'', 12)
    cs_hp = HKDF_expand_label(cs_initial_secret, b'quic hp', b'', 16)
    return cs_key, cs_iv, cs_hp

def get_client_server_key_iv_hp(client_dst_connection_id):
    initial_secret = HKDF_extract(initial_salt, client_dst_connection_id)
    client_initial_secret = HKDF_expand_label(initial_secret, b'client in', b'', 32)
    server_initial_secret = HKDF_expand_label(initial_secret, b'server in', b'', 32)
    client_key, client_iv, client_hp = get_key_iv_hp(client_initial_secret)
    server_key, server_iv, server_hp = get_key_iv_hp(server_initial_secret)
    return (client_key, client_iv, client_hp,
            server_key, server_iv, server_hp)

# --- ヘッダー保護・解除 ---

def header_protection(long_packet, sc_hp_key, mode=None, debug=False) -> bytes:
    assert mode in ('encrypt', 'decrypt')
    recv_packet_bytes = bytes(long_packet)

    def get_np_offset_and_sample_offset(long_packet) -> Tuple[int, int]:
        # pn_offset is the start of the Packet Number field.
        pn_offset = 7 + len(long_packet.dest_conn_id) + \
                        len(long_packet.src_conn_id) + \
                        len(long_packet.payload.length)
        if PacketType(long_packet.flags.long_packet_type) == PacketType.INITIAL:
            pn_offset += len(bytes(long_packet.payload.token))

        sample_offset = pn_offset + 4
        return pn_offset, sample_offset

    pn_offset, sample_offset = get_np_offset_and_sample_offset(long_packet)

    sample_length = 16
    sample = recv_packet_bytes[sample_offset:sample_offset+sample_length]
    if debug:
        print('sample:')
        print(hexdump(sample))

    def generate_mask(hp_key, sample) -> bytes:
        cipher = Cipher(algorithms.AES(key=hp_key), modes.ECB())
        encryptor = cipher.encryptor()
        ct = encryptor.update(sample) + encryptor.finalize()
        mask = bytearray(ct)[0:5]
        return mask

    mask = generate_mask(sc_hp_key, sample)
    if debug:
        print('mask:')
        print(hexdump(mask))

    if mode == 'encrypt':
        # ヘッダ保護前にパケット番号の長さ取得
        pn_length = (recv_packet_bytes[0] & 0x03) + 1

    recv_packet_bytes = bytearray(recv_packet_bytes)
    if (recv_packet_bytes[0] & 0x80) == 0x80:
        # Long header: 4 bits masked
        recv_packet_bytes[0] ^= mask[0] & 0x0f
    else:
        # Short header: 5 bits masked
        recv_packet_bytes[0] ^= mask[0] & 0x1f

    if mode == 'decrypt':
        # ヘッダ保護解除後にパケット番号の長さ取得
        pn_length = (recv_packet_bytes[0] & 0x03) + 1

    recv_packet_bytes[pn_offset:pn_offset+pn_length] = \
        bytexor(recv_packet_bytes[pn_offset:pn_offset+pn_length], mask[1:1+pn_length])

    return recv_packet_bytes

# --- Payload暗号化・復号 ---

def _enc_dec_payload(input_bytes, key, iv, aad, packet_number, mode='encrypt', debug=False):
    packet_number_bytes = packet_number.to_bytes(len(iv), 'big')
    nonce = bytexor(packet_number_bytes, iv)
    if debug:
        print('packet_number:')
        print(hexdump(packet_number_bytes))
        print('nonce:')
        print(hexdump(nonce))
        print('aad:')
        print(hexdump(aad))
    aesgcm = AESGCM(key=key)
    output_bytes = b''
    if mode == 'encrypt':
        output_bytes = aesgcm.encrypt(nonce, input_bytes, aad)
    else:
        output_bytes = aesgcm.decrypt(nonce, input_bytes, aad)
    return output_bytes

def decrypt_payload(payload: bytes, cs_key: bytes, cs_iv: bytes, aad: bytes,
                    packet_number: int, debug=False) -> bytes:
    return _enc_dec_payload(payload, cs_key, cs_iv, aad, packet_number, mode='decrypt', debug=debug)

def encrypt_payload(payload: bytes, cs_key: bytes, cs_iv: bytes, aad: bytes,
                    packet_number: int, debug=False) -> bytes:
    return _enc_dec_payload(payload, cs_key, cs_iv, aad, packet_number, mode='encrypt', debug=debug)



# ------------------------------------------------------------------------------
if __name__ == '__main__':

    import unittest

    class TestUint(unittest.TestCase):

        def test_enc_dec_payload(self):
            plaintext_payload = b'\x01\x02\x03\x04\x05' + (b'\x00' * 30)
            cs_key = b'\x11' * 16
            cs_iv  = b'\x22' * 12
            aad    = b'unittest label'
            packet_number = 999999
            tmp = encrypt_payload(plaintext_payload, cs_key, cs_iv, aad, packet_number)
            tmp = decrypt_payload(tmp,               cs_key, cs_iv, aad, packet_number)
            self.assertEqual(tmp, plaintext_payload)

    unittest.main()
