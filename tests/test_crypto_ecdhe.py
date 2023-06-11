# crypto_ecdhe.pyの単体テスト
# python -m unittest -v tests.test_crypto_ecdhe

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from crypto_ecdhe import *

# Test Vectors
# https://tools.ietf.org/html/rfc7748#section-5.2

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


if __name__ == '__main__':
    unittest.main()
