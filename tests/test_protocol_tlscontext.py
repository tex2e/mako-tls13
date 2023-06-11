# protocol_tlscontext.pyの単体テスト
# python -m unittest -v tests.test_protocol_tlscontext

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
import io
from protocol_tlscontext import *
from protocol_handshake import Handshake
from protocol_recordlayer import TLSPlaintext
from protocol_types import ContentType
from protocol_ext_version import ProtocolVersion
from protocol_authentication import Hash
from crypto_ecdhe import x25519

class TestUint(unittest.TestCase):

    def test_simple_1rtt_handshake(self):
        # RFC 8448 #section-2

        # {client}  create an ephemeral x25519 key pair:

        client_private_key = bytes.fromhex('''
            49 af 42 ba 7f 79 94 85  2d 71 3e f2 78 4b cb ca
            a7 91 1d e2 6a dc 56 42  cb 63 45 40 e7 ea 50 05
        ''')
        client_public_key = bytes.fromhex('''
            99 38 1d e5 60 e4 bd 43  d2 3d 8e 43 5a 7d ba fe
            b3 c0 6e 51 c1 3c ae 4d  54 13 69 1e 52 9a af 2c
        ''')

        # {client}  construct a ClientHello handshake message:

        client_hello_bytes = bytes.fromhex('''
            01 00 00 c0 03 03 cb 34  ec b1 e7 81 63 ba 1c 38
            c6 da cb 19 6a 6d ff a2  1a 8d 99 12 ec 18 a2 ef
            62 83 02 4d ec e7 00 00  06 13 01 13 03 13 02 01
            00 00 91 00 00 00 0b 00  09 00 00 06 73 65 72 76
            65 72 ff 01 00 01 00 00  0a 00 14 00 12 00 1d 00
            17 00 18 00 19 01 00 01  01 01 02 01 03 01 04 00
            23 00 00 00 33 00 26 00  24 00 1d 00 20 99 38 1d
            e5 60 e4 bd 43 d2 3d 8e  43 5a 7d ba fe b3 c0 6e
            51 c1 3c ae 4d 54 13 69  1e 52 9a af 2c 00 2b 00
            03 02 03 04 00 0d 00 20  00 1e 04 03 05 03 06 03
            02 03 08 04 08 05 08 06  04 01 05 01 06 01 02 01
            04 02 05 02 06 02 02 02  00 2d 00 02 01 01 00 1c
            00 02 40 01
        ''')
        client_hello = Handshake.from_bytes(client_hello_bytes)
        # print(client_hello)
        ctx_client = TLSContext('client')
        ctx_client.append_msg(client_hello)

        tlsplaintext = TLSPlaintext.create(ContentType.handshake, client_hello)
        tlsplaintext.legacy_record_version = ProtocolVersion.TLS10  # 互換性ありの場合

        # {client}  send handshake record:

        client_hello_complete_record = bytes.fromhex('''
            16 03 01 00 c4 01 00 00  c0 03 03 cb 34 ec b1 e7
            81 63 ba 1c 38 c6 da cb  19 6a 6d ff a2 1a 8d 99
            12 ec 18 a2 ef 62 83 02  4d ec e7 00 00 06 13 01
            13 03 13 02 01 00 00 91  00 00 00 0b 00 09 00 00
            06 73 65 72 76 65 72 ff  01 00 01 00 00 0a 00 14
            00 12 00 1d 00 17 00 18  00 19 01 00 01 01 01 02
            01 03 01 04 00 23 00 00  00 33 00 26 00 24 00 1d
            00 20 99 38 1d e5 60 e4  bd 43 d2 3d 8e 43 5a 7d
            ba fe b3 c0 6e 51 c1 3c  ae 4d 54 13 69 1e 52 9a
            af 2c 00 2b 00 03 02 03  04 00 0d 00 20 00 1e 04
            03 05 03 06 03 02 03 08  04 08 05 08 06 04 01 05
            01 06 01 02 01 04 02 05  02 06 02 02 02 00 2d 00
            02 01 01 00 1c 00 02 40  01
        ''')
        self.assertEqual(bytes(tlsplaintext), client_hello_complete_record)

        # {server}  create an ephemeral x25519 key pair:

        server_private_key = bytes.fromhex('''
            b1 58 0e ea df 6d d5 89  b8 ef 4f 2d 56 52 57 8c
            c8 10 e9 98 01 91 ec 8d  05 83 08 ce a2 16 a2 1e
        ''')

        server_public_key = bytes.fromhex('''
            c9 82 88 76 11 20 95 fe  66 76 2b db f7 c6 72 e1
            56 d6 cc 25 3b 83 3d f1  dd 69 b1 b0 4e 75 1f 0f
        ''')

        # {server}  construct a ServerHello handshake message:

        server_hello_bytes = bytes.fromhex('''
            02 00 00 56 03 03 a6 af  06 a4 12 18 60 dc 5e 6e
            60 24 9c d3 4c 95 93 0c  8a c5 cb 14 34 da c1 55
            77 2e d3 e2 69 28 00 13  01 00 00 2e 00 33 00 24
            00 1d 00 20 c9 82 88 76  11 20 95 fe 66 76 2b db
            f7 c6 72 e1 56 d6 cc 25  3b 83 3d f1 dd 69 b1 b0
            4e 75 1f 0f 00 2b 00 02  03 04
        ''')
        server_hello = Handshake.from_bytes(server_hello_bytes)
        # print(server_hello)
        ctx_client.append_msg(server_hello)

        tlsplaintext = TLSPlaintext.create(ContentType.handshake, server_hello)

        server_hello_complete_record = bytes.fromhex('''
            16 03 03 00 5a 02 00 00  56 03 03 a6 af 06 a4 12
            18 60 dc 5e 6e 60 24 9c  d3 4c 95 93 0c 8a c5 cb
            14 34 da c1 55 77 2e d3  e2 69 28 00 13 01 00 00
            2e 00 33 00 24 00 1d 00  20 c9 82 88 76 11 20 95
            fe 66 76 2b db f7 c6 72  e1 56 d6 cc 25 3b 83 3d
            f1 dd 69 b1 b0 4e 75 1f  0f 00 2b 00 02 03 04
        ''')
        self.assertEqual(bytes(tlsplaintext), server_hello_complete_record)


        dhkex_classes = {
            NamedGroup.x25519: x25519
        }
        secret_keys = {
            NamedGroup.x25519: client_private_key
        }
        ctx_client.set_key_exchange(dhkex_classes, secret_keys)
        Hash.length = ctx_client.hash_size
        # print('[+] shared key:', ctx_client.shared_key.hex())

        # Suppress output
        sys.stdout = io.StringIO()
        ctx_client.key_schedule_in_handshake()
        sys.stdout = sys.__stdout__

        # {server}  derive write traffic keys for handshake data:

        # expected_client_handshake_traffic_secret = bytes.fromhex('''
        #     b6 7b 7d 69 0c c1 6c 4e  75 e5 42 13 cb 2d 37 b4
        #     e9 c9 12 bc de d9 10 5d  42 be fd 59 d3 91 ad 38
        # ''')
        # self.assertEqual(ctx_client.client_hs_traffic_secret,
        #                  expected_client_handshake_traffic_secret)

        # {server}  construct an EncryptedExtensions handshake message:

        encrypted_extensions_bytes = bytes.fromhex('''
            08 00 00 24 00 22 00 0a  00 14 00 12 00 1d 00 17
            00 18 00 19 01 00 01 01  01 02 01 03 01 04 00 1c
            00 02 40 01 00 00 00 00
        ''')
        encrypted_extensions = Handshake.from_bytes(encrypted_extensions_bytes)
        # print(encrypted_extensions)
        ctx_client.append_msg(encrypted_extensions)

        # {server}  construct a Certificate handshake message:

        certificate_bytes = bytes.fromhex('''
            0b 00 01 b9 00 00 01 b5  00 01 b0 30 82 01 ac 30
            82 01 15 a0 03 02 01 02  02 01 02 30 0d 06 09 2a
            86 48 86 f7 0d 01 01 0b  05 00 30 0e 31 0c 30 0a
            06 03 55 04 03 13 03 72  73 61 30 1e 17 0d 31 36
            30 37 33 30 30 31 32 33  35 39 5a 17 0d 32 36 30
            37 33 30 30 31 32 33 35  39 5a 30 0e 31 0c 30 0a
            06 03 55 04 03 13 03 72  73 61 30 81 9f 30 0d 06
            09 2a 86 48 86 f7 0d 01  01 01 05 00 03 81 8d 00
            30 81 89 02 81 81 00 b4  bb 49 8f 82 79 30 3d 98
            08 36 39 9b 36 c6 98 8c  0c 68 de 55 e1 bd b8 26
            d3 90 1a 24 61 ea fd 2d  e4 9a 91 d0 15 ab bc 9a
            95 13 7a ce 6c 1a f1 9e  aa 6a f9 8c 7c ed 43 12
            09 98 e1 87 a8 0e e0 cc  b0 52 4b 1b 01 8c 3e 0b
            63 26 4d 44 9a 6d 38 e2  2a 5f da 43 08 46 74 80
            30 53 0e f0 46 1c 8c a9  d9 ef bf ae 8e a6 d1 d0
            3e 2b d1 93 ef f0 ab 9a  80 02 c4 74 28 a6 d3 5a
            8d 88 d7 9f 7f 1e 3f 02  03 01 00 01 a3 1a 30 18
            30 09 06 03 55 1d 13 04  02 30 00 30 0b 06 03 55
            1d 0f 04 04 03 02 05 a0  30 0d 06 09 2a 86 48 86
            f7 0d 01 01 0b 05 00 03  81 81 00 85 aa d2 a0 e5
            b9 27 6b 90 8c 65 f7 3a  72 67 17 06 18 a5 4c 5f
            8a 7b 33 7d 2d f7 a5 94  36 54 17 f2 ea e8 f8 a5
            8c 8f 81 72 f9 31 9c f3  6b 7f d6 c5 5b 80 f2 1a
            03 01 51 56 72 60 96 fd  33 5e 5e 67 f2 db f1 02
            70 2e 60 8c ca e6 be c1  fc 63 a4 2a 99 be 5c 3e
            b7 10 7c 3c 54 e9 b9 eb  2b d5 20 3b 1c 3b 84 e0
            a8 b2 f7 59 40 9b a3 ea  c9 d9 1d 40 2d cc 0c c8
            f8 96 12 29 ac 91 87 b4  2b 4d e1 00 00
        ''')
        certificate = Handshake.from_bytes(certificate_bytes)
        # print(certificate)
        ctx_client.append_msg(certificate)

        # {server}  construct a CertificateVerify handshake message:

        certificate_verify_bytes = bytes.fromhex('''
            0f 00 00 84 08 04 00 80  5a 74 7c 5d 88 fa 9b d2
            e5 5a b0 85 a6 10 15 b7  21 1f 82 4c d4 84 14 5a
            b3 ff 52 f1 fd a8 47 7b  0b 7a bc 90 db 78 e2 d3
            3a 5c 14 1a 07 86 53 fa  6b ef 78 0c 5e a2 48 ee
            aa a7 85 c4 f3 94 ca b6  d3 0b be 8d 48 59 ee 51
            1f 60 29 57 b1 54 11 ac  02 76 71 45 9e 46 44 5c
            9e a5 8c 18 1e 81 8e 95  b8 c3 fb 0b f3 27 84 09
            d3 be 15 2a 3d a5 04 3e  06 3d da 65 cd f5 ae a2
            0d 53 df ac d4 2f 74 f3
        ''')
        certificate_verify = Handshake.from_bytes(certificate_verify_bytes)
        # print(certificate_verify)
        ctx_client.append_msg(certificate_verify)

        # {server}  construct a Finished handshake message:

        server_finished_bytes = bytes.fromhex('''
            14 00 00 20 9b 9b 14 1d  90 63 37 fb d2 cb dc e7
            1d f4 de da 4a b4 2c 30  95 72 cb 7f ff ee 54 54
            b7 8f 07 18
        ''')

        server_finished = Handshake.from_bytes(server_finished_bytes)
        # print(server_finished)
        ctx_client.append_msg(server_finished)

        # TODO: 鍵導出のテスト
