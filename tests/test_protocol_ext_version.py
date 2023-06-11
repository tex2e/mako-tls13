# protocol_ext_version.pyの単体テスト
# python -m unittest -v tests.test_protocol_ext_version

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from protocol_ext_version import *

class TestUint(unittest.TestCase):

    def test_ext_supported_versions_client_hello(self):

        @meta.struct
        class Handshake(meta.MetaStruct):
            msg_type: HandshakeType
            msg: SupportedVersions

        h = Handshake(
            msg_type=HandshakeType.client_hello,
            msg=SupportedVersions(versions=ProtocolVersions([
                ProtocolVersion.TLS13, ProtocolVersion.TLS12,
                ProtocolVersion.TLS11,
            ])),)

        self.assertEqual(bytes(h), bytes.fromhex('01 06 0304 0303 0302'))
        self.assertEqual(Handshake.from_bytes(bytes(h)), h)

    def test_ext_supported_versions_server_hello(self):

        @meta.struct
        class Handshake(meta.MetaStruct):
            msg_type: HandshakeType
            msg: SupportedVersions

        h = Handshake(
            msg_type=HandshakeType.server_hello,
            msg=SupportedVersions(versions=ProtocolVersion.TLS13),)

        self.assertEqual(bytes(h), bytes.fromhex('02 0304'))
        self.assertEqual(Handshake.from_bytes(bytes(h)), h)


if __name__ == '__main__':
    unittest.main()
