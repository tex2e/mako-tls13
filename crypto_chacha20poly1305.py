# ------------------------------------------------------------------------------
# ChaCha20-Poly1305
#   - RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols)
#     * https://datatracker.ietf.org/doc/html/rfc8439
# ------------------------------------------------------------------------------

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
    a += b; d ^= a; d <<= 16
    c += d; b ^= c; b <<= 12
    a += b; d ^= a; d <<= 8
    c += d; b ^= c; b <<= 7
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

        from utils import hexdump
        print('+ [+] plaintext:')
        print(hexdump(plaintext))
        print('+ [+] cnt:', hex(self.seq_number))
        print('+ [+] aad:', aad.hex())
        print('+ [+] mac:', mac.hex())
        print('+ [+] tag:', tag.hex())

        if not compare_const_time(tag, mac):
            raise Exception('Poly1305: Bad Tag!')

        return plaintext
