# ------------------------------------------------------------------------------
# TLSの接続状態を管理して、鍵導出を支援するためのクラス
# ------------------------------------------------------------------------------

from protocol_types import HandshakeType
from protocol_extensions import ExtensionType
from protocol_ciphersuite import CipherSuite
from protocol_ext_supportedgroups import NamedGroup
import crypto_hkdf as hkdf

class TLSContext:
    def __init__(self, peer_name: str):
        # TLSのどちら側の通信者か
        assert peer_name in ('client', 'server')
        self.peer_name = peer_name
        # TLSのやりとりで送信されてきたメッセージを格納する。
        # 辞書のkeyはクラス名 (ClientHelloなど) 、valueはTLSPlaintextクラスのインスタンス
        self.tls_messages: dict[str, bytes] = {}
        # Handshakeレコードのrecord.fragment部分のバイト列を結合したもの
        self.tls_messages_bytes: list[bytes] = []

    def append_msg(self, handshake: bytes):
        self.tls_messages[handshake.msg_type] = handshake
        self.tls_messages_bytes.append(bytes(handshake))

    def get_messages_byte(self) -> bytes:
        return b''.join(self.tls_messages_bytes)

    def set_key_exchange(self, dhkex_classes: dict, secret_keys: dict):
        self.client_hello = self.tls_messages.get(HandshakeType.client_hello)
        self.server_hello = self.tls_messages.get(HandshakeType.server_hello)
        self.dhkex_classes = dhkex_classes # TODO: something like list or ...
        self.secret_keys = secret_keys   # TODO:

        self._derive_negotiated_params()

    def _derive_negotiated_params(self):
        self.cipher_suite = self.server_hello.msg.cipher_suite

        # 共通鍵の導出
        peer_share = None
        if self.peer_name == 'client':
            for ext in self.server_hello.msg.extensions:
                if ext.extension_type == ExtensionType.key_share:
                    if ext.extension_data.shares.group == NamedGroup.x25519:
                        peer_share = ext.extension_data.shares
                        dhkex_class = self.dhkex_classes[NamedGroup.x25519]
                        secret_key = self.secret_keys[NamedGroup.x25519]
                    if ext.extension_data.shares.group == NamedGroup.ffdhe4096:
                        peer_share = ext.extension_data.shares
                        dhkex_class = self.dhkex_classes[NamedGroup.ffdhe4096]
                        secret_key = self.secret_keys[NamedGroup.ffdhe4096]
                    break
        elif self.peer_name == 'server':
            ext = self.client_hello.msg.extensions \
                .find(lambda ext: ext.extension_type == ExtensionType.key_share)
            for client_share in ext.extension_data.shares:
                if client_share.group == NamedGroup.x25519:
                    peer_share = client_share
                    dhkex_class = self.dhkex_classes[NamedGroup.x25519]
                    secret_key = self.secret_keys[NamedGroup.x25519]
                    break
                if client_share.group == NamedGroup.ffdhe4096:
                    peer_share = client_share
                    dhkex_class = self.dhkex_classes[NamedGroup.ffdhe4096]
                    secret_key = self.secret_keys[NamedGroup.ffdhe4096]
                    break

        self.shared_key = dhkex_class(
            secret_key, peer_share.key_exchange.get_raw_bytes())
        # print('[+] shared key:', self.shared_key.hex())

        self.hash_name   = CipherSuite.get_hash_name(self.cipher_suite)
        self.secret_size = CipherSuite.get_hash_size(self.cipher_suite)
        self.hash_size = hkdf.hash_size(self.hash_name)

    def key_schedule_in_handshake(self):
        messages = self.get_messages_byte()
        secret = bytearray(self.secret_size)
        psk    = bytearray(self.secret_size)

        # early secret
        secret = hkdf.HKDF_extract(secret, psk, self.hash_name)
        self.early_secret = secret
        print('[+] early secret:', secret.hex())

        # handshake secret
        secret = hkdf.derive_secret(secret, b'derived', b'', self.hash_name)
        secret = hkdf.HKDF_extract(secret, self.shared_key, self.hash_name)
        self.handshake_secret = secret
        print('[+] handshake secret:', secret.hex())

        self.client_hs_traffic_secret = \
            hkdf.derive_secret(secret, b'c hs traffic', messages, self.hash_name)
        self.server_hs_traffic_secret = \
            hkdf.derive_secret(secret, b's hs traffic', messages, self.hash_name)

        # print('[+] c hs traffic:', client_hs_traffic_secret.hex())
        # print('[+] s hs traffic:', server_hs_traffic_secret.hex())

        self.cipher_class = CipherSuite.get_cipher_class(self.cipher_suite)
        key_size   = self.cipher_class.key_size
        nonce_size = self.cipher_class.nonce_size

        client_write_key, client_write_iv = \
            hkdf.gen_key_and_iv(self.client_hs_traffic_secret,
                                key_size, nonce_size, self.hash_name)
        server_write_key, server_write_iv = \
            hkdf.gen_key_and_iv(self.server_hs_traffic_secret,
                                key_size, nonce_size, self.hash_name)

        self.client_traffic_crypto = self.cipher_class(
            key=client_write_key, nonce=client_write_iv)
        self.server_traffic_crypto = self.cipher_class(
            key=server_write_key, nonce=server_write_iv)

    def key_schedule_in_app_data(self):
        messages = self.get_messages_byte()
        secret = self.handshake_secret
        label = bytearray(self.secret_size)

        # master secret
        secret = hkdf.derive_secret(secret, b'derived', b'')
        secret = hkdf.HKDF_extract(secret, label, self.hash_name)
        self.master_secret = secret
        print('[+] master secret:', secret.hex())

        self.client_app_traffic_secret = \
            hkdf.derive_secret(secret, b'c ap traffic', messages, self.hash_name)
        self.server_app_traffic_secret = \
            hkdf.derive_secret(secret, b's ap traffic', messages, self.hash_name)

        # print('[+] c ap traffic:', client_app_traffic_secret.hex())
        # print('[+] s ap traffic:', server_app_traffic_secret.hex())

        key_size   = self.cipher_class.key_size
        nonce_size = self.cipher_class.nonce_size

        client_app_write_key, client_app_write_iv = \
            hkdf.gen_key_and_iv(self.client_app_traffic_secret, key_size,
                                nonce_size, self.hash_name)
        server_app_write_key, server_app_write_iv = \
            hkdf.gen_key_and_iv(self.server_app_traffic_secret, key_size,
                                nonce_size, self.hash_name)

        # print('[+] client_app_write_key:', client_app_write_key.hex())
        # print('[+] client_app_write_iv:', client_app_write_iv.hex())
        # print('[+] server_app_write_key:', server_app_write_key.hex())
        # print('[+] server_app_write_iv:', server_app_write_iv.hex())

        self.client_app_data_crypto = self.cipher_class(
                key=client_app_write_key, nonce=client_app_write_iv)
        self.server_app_data_crypto = self.cipher_class(
                key=server_app_write_key, nonce=server_app_write_iv)
