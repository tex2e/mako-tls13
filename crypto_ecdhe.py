# ------------------------------------------------------------------------------
# Ephemeral Elliptic Curve Diffie-Hellman
#   - RFC 7748 (Elliptic Curves for Security)
#     * https://datatracker.ietf.org/doc/html/rfc7748
# ------------------------------------------------------------------------------

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
