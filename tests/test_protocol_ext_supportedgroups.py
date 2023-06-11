# protocol_ext_supportedgroups.pyの単体テスト
# python -m unittest -v tests.test_protocol_ext_supportedgroups

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_ext_supportedgroups import *

class TestUnit(unittest.TestCase):

    def test_namedgrouplist(self):

        ngl = NamedGroupList(named_group_list=NamedGroups([
            NamedGroup.x25519, NamedGroup.secp256r1,
        ]))
        ngl_bytes = bytes.fromhex('0004 001D 0017')

        self.assertEqual(bytes(ngl), ngl_bytes)
        self.assertEqual(NamedGroupList.from_bytes(bytes(ngl)), ngl)


if __name__ == '__main__':
    unittest.main()
