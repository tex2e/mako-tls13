
import struct
import binascii
import math
from typing import List

# --- chacha20 -----------------------------------------------------------------

# Finite field 2^32
class F2_32:
    def __init__(self, val: int):
        assert isinstance(val, int)
        self.val = val
    def __add__(self, other):
        return F2_32((self.val + other.val) & 0xffffffff)
    def __xor__(self, other):
        return F2_32(self.val ^ other.val)
    def __lshift__(self, nbit: int):
        left  = (self.val << nbit%32) & 0xffffffff
        right = (self.val & 0xffffffff) >> (32-(nbit%32))
        return F2_32(left | right)
    def __repr__(self):
        return hex(self.val)
    def __int__(self):
        return int(self.val)

def quarter_round(a: F2_32, b: F2_32, c: F2_32, d: F2_32):
    a += b; d ^= a; d <<= 16;
    c += d; b ^= c; b <<= 12;
    a += b; d ^= a; d <<= 8;
    c += d; b ^= c; b <<= 7;
    return a, b, c, d

def Qround(state: List[F2_32], idx1, idx2, idx3, idx4):
    state[idx1], state[idx2], state[idx3], state[idx4] = \
        quarter_round(state[idx1], state[idx2], state[idx3], state[idx4])

def inner_block(state: List[F2_32]):
    Qround(state, 0, 4, 8, 12)
    Qround(state, 1, 5, 9, 13)
    Qround(state, 2, 6, 10, 14)
    Qround(state, 3, 7, 11, 15)
    Qround(state, 0, 5, 10, 15)
    Qround(state, 1, 6, 11, 12)
    Qround(state, 2, 7, 8, 13)
    Qround(state, 3, 4, 9, 14)
    return state

def serialize(state: List[F2_32]) -> List[bytes]:
    return b''.join([ struct.pack('<I', int(s)) for s in state ])

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    # make a state matrix
    constants = [F2_32(x) for x in struct.unpack('<IIII', b'expand 32-byte k')]
    key       = [F2_32(x) for x in struct.unpack('<IIIIIIII', key)]
    counter   = [F2_32(counter)]
    nonce     = [F2_32(x) for x in struct.unpack('<III', nonce)]
    state = constants + key + counter + nonce
    initial_state = state[:]
    for i in range(10):
        state = inner_block(state)
    state = [ s + init_s for s, init_s in zip(state, initial_state) ]
    return serialize(state)

def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))

def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes):
    encrypted_message = bytearray(0)

    for j in range(len(plaintext) // 64):
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j*64 : (j+1)*64]
        encrypted_message += xor(block, key_stream)

    if len(plaintext) % 64 != 0:
        j = len(plaintext) // 64
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j*64 : ]
        encrypted_message += xor(block, key_stream)

    return encrypted_message

# --- poly1305 -----------------------------------------------------------------

def clamp(r: int) -> int:
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def le_bytes_to_num(byte) -> int:
    res = 0
    for i in range(len(byte) - 1, -1, -1):
        res <<= 8
        res += byte[i]
    return res

def num_to_16_le_bytes(num: int) -> bytes:
    res = []
    for i in range(16):
        res.append(num & 0xff)
        num >>= 8
    return bytearray(res)

def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    r = le_bytes_to_num(key[0:16])
    r = clamp(r)
    s = le_bytes_to_num(key[16:32])
    a = 0  # a is the accumulator
    p = (1<<130) - 5
    for i in range(1, math.ceil(len(msg)/16) + 1):
        n = le_bytes_to_num(msg[(i-1)*16 : i*16] + b'\x01')
        a += n
        a = (r * a) % p
    a += s
    return num_to_16_le_bytes(a)

# --- chacha20poly1305 ---------------------------------------------------------

def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    counter = 0
    block = chacha20_block(key, counter, nonce)
    return block[0:32]

def pad16(x: bytes) -> bytes:
    if len(x) % 16 == 0: return b''
    return b'\x00' * (16 - (len(x) % 16))

def num_to_8_le_bytes(num: int) -> bytes:
    return struct.pack('<Q', num)

def chacha20_aead_encrypt(aad: bytes, key: bytes, nonce: bytes, plaintext: bytes):
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += num_to_8_le_bytes(len(aad))
    mac_data += num_to_8_le_bytes(len(ciphertext))
    tag = poly1305_mac(mac_data, otk)
    return (ciphertext, tag)

def chacha20_aead_decrypt(aad: bytes, key: bytes, nonce: bytes, ciphertext: bytes):
    otk = poly1305_key_gen(key, nonce)
    plaintext = chacha20_encrypt(key, 1, nonce, ciphertext)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += num_to_8_le_bytes(len(aad))
    mac_data += num_to_8_le_bytes(len(ciphertext))
    tag = poly1305_mac(mac_data, otk)
    return (plaintext, tag)

def compare_const_time(a, b):
    """Compare strings in constant time."""
    if len(a) != len(b): return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

class Cipher:

    def get_nonce(self):
        nonce = bytes(self.nonce)
        seq_number = self.seq_number.to_bytes(len(nonce), 'big')
        res = self.xor(nonce, seq_number)

        self.seq_number += 1
        return res

    def xor(self, b1, b2):
        result = bytearray(b1)
        for i, b in enumerate(b2):
            result[i] ^= b
        return bytes(result)

class Chacha20Poly1305(Cipher):
    key_size = 32
    nonce_size = 12
    tag_size = 16

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.seq_number = 0

    def encrypt_and_tag(self, plaintext, aad):
        nonce = self.get_nonce()
        ciphertext, tag = chacha20_aead_encrypt(key=self.key, nonce=nonce,
                                                plaintext=plaintext, aad=aad)
        print('+ [+] cnt:', hex(self.seq_number))
        print('+ [+] aad:', aad.hex())
        print('+ [+] tag:', tag.hex())
        return bytes(ciphertext + tag)

    def decrypt_and_verify(self, ciphertext, aad, mac=None):
        if mac is None:
            mac = ciphertext[-16:]
            ciphertext = ciphertext[:-16]

        nonce = self.get_nonce()
        plaintext, tag = chacha20_aead_decrypt(key=self.key, nonce=nonce,
                                               ciphertext=ciphertext, aad=aad)

        from disp import hexdump
        print('+ [+] plaintext:')
        print(hexdump(plaintext))
        print('+ [+] cnt:', hex(self.seq_number))
        print('+ [+] aad:', aad.hex())
        print('+ [+] mac:', mac.hex())
        print('+ [+] tag:', tag.hex())

        if not compare_const_time(tag, mac):
            raise Exception('Poly1305: Bad Tag!')

        return plaintext


if __name__ == '__main__':
    import unittest

    class TestChacha20(unittest.TestCase):

        def test_quarter_round(self):
            a = F2_32(0x11111111)
            b = F2_32(0x01020304)
            c = F2_32(0x9b8d6f43)
            d = F2_32(0x01234567)
            a, b, c, d = quarter_round(a, b, c, d)
            self.assertEqual(int(a), 0xea2a92f4)
            self.assertEqual(int(b), 0xcb1cf8ce)
            self.assertEqual(int(c), 0x4581472e)
            self.assertEqual(int(d), 0x5881c4bb)

        def test_chacha20_block(self):
            key = bytes.fromhex(
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
            counter = 0x00000001
            nonce = bytes.fromhex('000000090000004a00000000')
            state = chacha20_block(key, counter, nonce)

            expected_bytes = bytes.fromhex('''
                10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
                c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
                d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
                b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e
            ''')

            self.assertEqual(state, expected_bytes)

        def test_chacha20_block_appendixA_1_1(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000')
            counter = 0
            nonce = bytes.fromhex('000000000000000000000000')
            state = chacha20_block(key, counter, nonce)

            expected_bytes = bytes.fromhex('''
                76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
                bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
                da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
                6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
            ''')

            self.assertEqual(state, expected_bytes)

        def test_chacha20_block_appendixA_1_2(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000')
            counter = 1
            nonce = bytes.fromhex('000000000000000000000000')
            state = chacha20_block(key, counter, nonce)

            expected_bytes = bytes.fromhex('''
                9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d
                cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed
                29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5
                31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f
            ''')

            self.assertEqual(state, expected_bytes)

        def test_chacha20_block_appendixA_1_3(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000001')
            counter = 1
            nonce = bytes.fromhex('000000000000000000000000')
            state = chacha20_block(key, counter, nonce)

            expected_bytes = bytes.fromhex('''
                3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd
                83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a
                8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd
                4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0
            ''')

            self.assertEqual(state, expected_bytes)

        def test_chacha20_block_appendixA_1_4(self):
            key = bytes.fromhex(
                '00ff000000000000000000000000000000000000000000000000000000000000')
            counter = 2
            nonce = bytes.fromhex('000000000000000000000000')
            state = chacha20_block(key, counter, nonce)

            expected_bytes = bytes.fromhex('''
                72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32
                8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca
                13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09
                24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96
            ''')

            self.assertEqual(state, expected_bytes)

        def test_chacha20_block_appendixA_1_5(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000')
            counter = 0
            nonce = bytes.fromhex('000000000000000000000002')
            state = chacha20_block(key, counter, nonce)

            expected_bytes = bytes.fromhex('''
                c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd
                1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7
                8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7
                5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d
            ''')

            self.assertEqual(state, expected_bytes)

        def test_chacha20_encrypt(self):
            key = bytes.fromhex(
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
            counter = 0x00000001
            nonce = bytes.fromhex('000000000000004a00000000')
            plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            encrypted_message = chacha20_encrypt(key, counter, nonce, plaintext)

            expected_bytes = bytes.fromhex('''
                6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
                e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
                f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
                16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
                07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
                52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
                5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
                87 4d
            ''')

            self.assertEqual(encrypted_message, expected_bytes)

        def test_chacha20_encrypt_appendixA_2_1(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000')
            counter = 0
            nonce = bytes.fromhex('000000000000000000000000')
            plaintext = bytes.fromhex('''
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            ''')
            encrypted_message = chacha20_encrypt(key, counter, nonce, plaintext)

            expected_bytes = bytes.fromhex('''
                76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
                bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
                da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
                6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
            ''')

            self.assertEqual(encrypted_message, expected_bytes)

        def test_chacha20_encrypt_appendixA_2_2(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000001')
            counter = 1
            nonce = bytes.fromhex('000000000000000000000002')
            plaintext = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
            encrypted_message = chacha20_encrypt(key, counter, nonce, plaintext)

            expected_bytes = bytes.fromhex('''
                a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
                41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
                2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
                0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
                40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
                20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
                42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
                68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
                d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
                42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
                c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
                e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
                08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
                a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
                cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
                a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
                c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
                8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
                58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
                be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
                98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
                14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
                7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
                c4 fd 80 6c 22 f2 21
            ''')

            self.assertEqual(encrypted_message, expected_bytes)

        def test_chacha20_encrypt_appendixA_2_3(self):
            key = bytes.fromhex(
                '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
            counter = 42
            nonce = bytes.fromhex('000000000000000000000002')
            plaintext = bytes.fromhex('''
                27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
                6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
                76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
                20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
                61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
                65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
                73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
                72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
            ''')
            encrypted_message = chacha20_encrypt(key, counter, nonce, plaintext)

            expected_bytes = bytes.fromhex('''
                62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df
                5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf
                16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71
                fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb
                f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6
                1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77
                04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1
                87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1
            ''')

            self.assertEqual(encrypted_message, expected_bytes)


    class TestPoly1305(unittest.TestCase):

        def test_poly1305_mac(self):
            msg = b'Cryptographic Forum Research Group'
            key = bytes.fromhex(
                '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('a8061dc1305136c6c22b8baf0c0127a9')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_1(self):
            msg = bytes.fromhex('00000000000000000000000000000000' * 4)
            key = bytes.fromhex('00000000000000000000000000000000' * 2)
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('00000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_2(self):
            msg = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
            key = bytes.fromhex(
                '0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('36e5f6b5c5e06070f0efca96227a863e')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_3(self):
            msg = b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
            key = bytes.fromhex(
                '36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('f3477e7cd95417af89a6b8794c310cf0')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_4(self):
            msg = bytes.fromhex('''
                27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
                6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
                76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
                20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
                61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
                65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
                73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
                72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
            ''')
            key = bytes.fromhex(
                '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('4541669a7eaaee61e708dc7cbcc5eb62')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_5(self):
            # If one uses 130-bit partial reduction, does the code
            # handle the case where partially reduced final result is not fully
            # reduced?
            msg = bytes.fromhex(
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            key = bytes.fromhex(
                '0200000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('03000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_6(self):
            # What happens if addition of s overflows modulo 2^128?
            msg = bytes.fromhex(
                '02000000000000000000000000000000')
            key = bytes.fromhex(
                '02000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('03000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_7(self):
            # What happens if data limb is all ones and there is
            # carry from lower limb?
            msg = bytes.fromhex('''
                FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            ''')
            key = bytes.fromhex(
                '0100000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('05000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_8(self):
            # What happens if final result from polynomial part is
            # exactly 2^130-5?
            msg = bytes.fromhex('''
                FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
                FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
                01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
            ''')
            key = bytes.fromhex(
                '0100000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('00000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_9(self):
            # What happens if final result from polynomial part is
            # exactly 2^130-6?
            msg = bytes.fromhex('''
                FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            ''')
            key = bytes.fromhex(
                '0200000000000000000000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_10(self):
            # What happens if 5*H+L-type reduction produces
            # 131-bit intermediate result?
            msg = bytes.fromhex('''
                E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
                33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            ''')
            key = bytes.fromhex(
                '0100000000000000040000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('14000000000000005500000000000000')

            self.assertEqual(tag, expected_tag)

        def test_poly1305_mac_appendixA_3_11(self):
            # What happens if 5*H+L-type reduction produces
            # 131-bit final result?
            msg = bytes.fromhex('''
                E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
                33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            ''')
            key = bytes.fromhex(
                '0100000000000000040000000000000000000000000000000000000000000000')
            tag = poly1305_mac(msg, key)

            expected_tag = bytes.fromhex('13000000000000000000000000000000')

            self.assertEqual(tag, expected_tag)


    class TestChacha20Poly1305(unittest.TestCase):

        def test_poly1305_key_gen(self):
            key = bytes.fromhex(
                '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
            nonce = bytes.fromhex('000000000001020304050607')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = bytes.fromhex('''
                8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
                a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
            ''')

            self.assertEqual(onetime_key, expected_bytes)

        def test_poly1305_key_gen_appendixA_4_1(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000')
            nonce = bytes.fromhex('000000000000000000000000')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = bytes.fromhex('''
                76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
                bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
            ''')

            self.assertEqual(onetime_key, expected_bytes)

        def test_poly1305_key_gen_appendixA_4_2(self):
            key = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000001')
            nonce = bytes.fromhex('000000000000000000000002')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = bytes.fromhex('''
                ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76
                06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39
            ''')

            self.assertEqual(onetime_key, expected_bytes)

        def test_poly1305_key_gen_appendixA_4_3(self):
            key = bytes.fromhex(
                '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0')
            nonce = bytes.fromhex('000000000000000000000002')
            onetime_key = poly1305_key_gen(key, nonce)

            expected_bytes = bytes.fromhex('''
                96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b
                13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae
            ''')

            self.assertEqual(onetime_key, expected_bytes)

        def test_chacha20_aead_encrypt(self):
            plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
            key = bytes.fromhex('''
                80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
                90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
            ''')
            iv = b'@ABCDEFG'
            constant = bytes.fromhex('07000000')
            nonce = constant + iv
            ciphertext, tag = chacha20_aead_encrypt(aad, key, nonce, plaintext)

            expected_ciphertext = bytes.fromhex('''
                d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
                a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
                3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
                1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
                92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
                fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
                3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
                61 16
            ''')
            expected_tag = bytes.fromhex('1ae10b594f09e26a7e902ecbd0600691')

            self.assertEqual(ciphertext, expected_ciphertext)
            self.assertEqual(tag, expected_tag)

        def test_chacha20poly1305_aead_decryption_appendixA_5_1(self):
            aad = bytes.fromhex('f33388860000000000004e91')
            key = bytes.fromhex('''
                1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
                47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
            ''')
            nonce = bytes.fromhex('000000000102030405060708')
            ciphertext = bytes.fromhex('''
                64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
                5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
                4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
                bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
                33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
                14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
                97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
                36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
                b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
                90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
                af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
                0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
                0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
                ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
                49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
                30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
                a6 ad 5c b4 02 2b 02 70 9b
            ''')

            plaintext, tag = chacha20_aead_decrypt(aad, key, nonce, ciphertext)

            expected_plaintext = bytes.fromhex('''
                49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20
                61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65
                6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20
                6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d
                6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65
                20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63
                65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64
                20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65
                6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e
                20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72
                69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65
                72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72
                65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61
                6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65
                6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20
                2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67
                72 65 73 73 2e 2f e2 80 9d
            ''')
            expected_tag = bytes.fromhex('eead9d67890cbb22392336fea1851f38')

            self.assertEqual(plaintext, expected_plaintext)
            self.assertEqual(tag, expected_tag)

    unittest.main()
