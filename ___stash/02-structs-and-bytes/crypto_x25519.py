
# RFC 7748
# Elliptic Curves for Security
#
# https://tools.ietf.org/html/rfc7748
# https://www.rfc-editor.org/errata_search.php?rfc=7748

# Usage:
#
#   # Secret key
#   alice_sec = bytes.fromhex(
#       '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
#   bob_sec = bytes.fromhex(
#       '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
#
#   # Create public key
#   alice_pub = x25519(alice_sec)
#   print('alice_pub', alice_pub)
#   bob_pub = x25519(bob_sec)
#   print('bob_pub', bob_pub)
#
#   # Their shared secret
#   alice_shared_secret = x25519(alice_sec, bob_pub)
#   bob_shared_secret = x25519(bob_sec, alice_pub)
#   print(alice_shared_secret)
#   print(bob_shared_secret)
#

# Finite field with p
def FiniteField(p):
    class Fp:
        def __init__(self, val: int):
            assert isinstance(val, int)
            self.val = val
        def __add__(self, other):
            return Fp((self.val + other.val) % Fp.p)
        def __sub__(self, other):
            return Fp((self.val - other.val) % Fp.p)
        def __mul__(self, other):
            return Fp((self.val * other.val) % Fp.p)
        def __rmul__(self, n):
            return Fp((self.val * n) % Fp.p)
        def __pow__(self, e):
            return Fp(pow(self.val, e, Fp.p))
        def __repr__(self):
            return hex(self.val)
        def __int__(self):
            return int(self.val)
    Fp.p = p
    return Fp

# 5.  The X25519 and X448 Functions

def decodeLittleEndian(b, bits=255):
    return sum([ b[i] << 8*i for i in range((bits+7)//8) ])

def decodeUCoordinate(u, bits=255):
    u_list = [b for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits=255):
    return bytearray([ (u >> 8*i) & 0xff for i in range((bits+7)//8) ])

def decodeScalar25519(k):
    k_list = [b for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

def decodeScalar448(k):
    k_list = [b for b in k]
    k_list[0] &= 252
    k_list[55] |= 128
    return decodeLittleEndian(k_list, 448)

def cswap(swap, x_2, x_3):
    "Conditional swap in constant time."
    dummy = swap * (x_2 - x_3)
    x_2 = x_2 - dummy
    x_3 = x_3 + dummy
    return x_2, x_3

def mul(k: int, u: int, bits: int, p: int, a24: int):
    Fp = FiniteField(p)
    x_1 = Fp(u)
    x_2 = Fp(1)
    z_2 = Fp(0)
    x_3 = Fp(u)
    z_3 = Fp(1)
    swap = 0

    for t in range(bits-1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        (x_2, x_3) = cswap(swap, x_2, x_3)
        (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t

        A = x_2 + z_2
        AA = A**2
        B = x_2 - z_2
        BB = B**2
        E = AA - BB
        C = x_3 + z_3
        D = x_3 - z_3
        DA = D * A
        CB = C * B
        x_3 = (DA + CB)**2
        z_3 = x_1 * (DA - CB)**2
        x_2 = AA * BB
        z_2 = E * (AA + a24 * E)

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    res = x_2 * (z_2**(p - 2))
    return res

# scala k (bytes), and base point u (bytes)
def x25519(k: bytes, u: bytes = encodeUCoordinate(9, bits=255)):
    # Curve25519 for the ~128-bit security level.
    # Computes u := k * u where k is the scalar and u is the u-coordinate.
    bits = 255
    k = decodeScalar25519(k)
    u = decodeUCoordinate(u, bits)
    p = 2**255 - 19
    a24 = 121665
    res = mul(k, u, bits, p, a24)
    return encodeUCoordinate(int(res), bits)

# scala k (bytes), and base point u (bytes)
def x448(k: bytes, u: bytes = encodeUCoordinate(5, bits=448)):
    # Curve448 for the ~224-bit security level.
    bits = 448
    k = decodeScalar448(k)
    u = decodeUCoordinate(u, bits)
    p = 2**448 - 2**224 - 1
    a24 = 39081
    res = mul(k, u, bits, p, a24)
    return encodeUCoordinate(int(res), bits)


if __name__ == '__main__':
    # Test Vectors
    # https://tools.ietf.org/html/rfc7748#section-5.2

    import unittest

    class TestUnit(unittest.TestCase):

        def test_keyshare_x25519_case1(self):
            k = bytes.fromhex(
                'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
            u = bytes.fromhex(
                'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
            r = bytes.fromhex(
                'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
            out = x25519(k, u)
            self.assertEqual(out, r)

        def test_keyshare_x25519_case2(self):
            k = bytes.fromhex(
                '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d')
            u = bytes.fromhex(
                'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413')
            r = bytes.fromhex(
                '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')
            out = x25519(k, u)
            self.assertEqual(out, r)

        def test_keyshare_x25519_case3(self):
            k = bytes.fromhex(
                '0900000000000000000000000000000000000000000000000000000000000000')
            u = bytes.fromhex(
                '0900000000000000000000000000000000000000000000000000000000000000')
            r1 = bytes.fromhex(
                '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079')
            r1000 = bytes.fromhex(
                '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51')
            for i in range(1, 1001):
                k, u = x25519(k, u), k
                if i == 1: self.assertEqual(k, r1)
                break # 1000 iteration takes about 10 sec.
                if i == 1000: self.assertEqual(k, r1000)

        def test_keyshare_x448_case1(self):
            k = bytes.fromhex(
                '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121'
                '700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3')
            u = bytes.fromhex(
                '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9'
                '814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086')
            r = bytes.fromhex(
                'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f'
                'e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f')
            out = x448(k, u)
            self.assertEqual(out, r)

        def test_keyshare_x448_case2(self):

            k = bytes.fromhex(
                '203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5'
                '38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f')
            u = bytes.fromhex(
                '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b'
                '165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db')
            r = bytes.fromhex(
                '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7'
                'ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d')
            out = x448(k, u)
            self.assertEqual(out, r)

        def test_keyshare_x448_case3(self):
            k = bytes.fromhex(
                '05000000000000000000000000000000000000000000000000000000'
                '00000000000000000000000000000000000000000000000000000000')
            u = bytes.fromhex(
                '05000000000000000000000000000000000000000000000000000000'
                '00000000000000000000000000000000000000000000000000000000')
            r1 = bytes.fromhex(
                '3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a'
                '4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113')
            r1000 = bytes.fromhex(
                'aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4'
                'af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38')
            for i in range(1, 1001):
                k, u = x448(k, u), k
                if i == 1: self.assertEqual(k, r1)
                break # 1000 iteration takes about 10 sec.
                if i == 1000: self.assertEqual(k, r1000)

    unittest.main()
