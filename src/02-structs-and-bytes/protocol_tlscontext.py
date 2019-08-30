
from protocol_extensions import ExtensionType
from protocol_ciphersuite import CipherSuite
import crypto_hkdf as hkdf

class TLSContext:
    def __init__(self):
        # TLSのやりとりで送信されてきたメッセージを格納する。
        # 辞書のkeyはクラス名 (ClientHelloなど) 、valueはTLSPlaintextクラスのインスタンス
        self.tls_records = {}
        # Handshakeレコードのrecord.fragment部分のバイト列を結合したもの
        self.tls_messages = b''

    def append_handshake_record(self, handshake):
        name = handshake.msg.__class__.__name__
        self.tls_records[name] = handshake
        self.tls_messages += bytes(handshake)

    def append_appdata_record(self, handshake):
        name = handshake.msg.__class__.__name__
        self.tls_records[name] = handshake

    def get_messages(self):
        return self.tls_messages

    def set_key_exchange(self, dhkex_class, secret_key):
        self.client_hello = self.tls_records.get('ClientHello')
        self.server_hello = self.tls_records.get('ServerHello')
        self.dhkex_class = dhkex_class # TODO: something like list or ...
        self.secret_key = secret_key   # TODO:

        self.derive_negotiated_params()

    def derive_negotiated_params(self):
        self.cipher_suite = self.server_hello.msg.cipher_suite

        for ext in self.server_hello.msg.extensions:
            if ext.extension_type == ExtensionType.key_share:
                server_share = ext.extension_data.shares

        # self.client_share = self.client_hello.fragment.msg.extensions \
        #     .find(lambda ext: ext.extension_type == ExtensionType.key_share) \
        #     .extension_data.shares \
        #     .find(lambda keyshare: keyshare.group == server_share.group)

        self.shared_key = self.dhkex_class(
            self.secret_key, server_share.key_exchange.get_raw_bytes())

        self.hash_name   = CipherSuite.get_hash_name(self.cipher_suite)
        self.secret_size = CipherSuite.get_hash_size(self.cipher_suite)
        self.hash_size = hkdf.hash_size(self.hash_name)

    def key_schedule_in_handshake(self):
        messages = self.get_messages()
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
        messages = self.get_messages()
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
