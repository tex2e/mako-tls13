# protocol_extensions.pyの単体テスト
# python -m unittest -v tests.test_protocol_extensions

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_extensions import *
from protocol_ext_supportedgroups import NamedGroups, NamedGroup

class TestUint(unittest.TestCase):

    def test_extension(self):

        e = Extension(
            extension_type=ExtensionType.supported_groups,
            extension_data=NamedGroupList(
                named_group_list=NamedGroups([
                    NamedGroup.x25519, NamedGroup.secp256r1,
                ])
            )
        )

        self.assertEqual(bytes(e)[:2], bytes(ExtensionType.supported_groups))
        self.assertEqual(Extension.from_bytes(bytes(e)), e)

    def test_encrypted_extensions(self):

        ee = EncryptedExtensions(
            extensions=Extensions([
                Extension(
                    extension_type=ExtensionType.supported_groups,
                    extension_data=NamedGroupList(
                        named_group_list=NamedGroups([
                            NamedGroup.x25519, NamedGroup.secp256r1,
                        ])
                    )
                )
            ])
        )

        self.assertEqual(EncryptedExtensions.from_bytes(bytes(ee)), ee)


if __name__ == '__main__':
    unittest.main()
