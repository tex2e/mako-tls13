
# TLS 1.3 + Quic 通信プログラム

[![Unittest](https://github.com/tex2e/mako-tls13/actions/workflows/unittest.yml/badge.svg)](https://github.com/tex2e/mako-tls13/actions/workflows/unittest.yml)

- `crypto_*.py` ... DH鍵共有やChaCha20-Poly1305暗号化など
- `main_*.py` ... ClientやServer側の処理
- `protocol_*.py` ... パケットフォーマットなど
- `type.py` ... RFCで登場する型の定義
- `meta*.py` ... RFCで登場する構造体の定義

## Prerequisites

```bash
pip install -r requirements.txt
```

## Execution

サーバ側
```bash
python main_server.py
```

クライアント側
```bash
python main_client.py
```

単体テスト
```bash
python -m unittest discover tests "test_*.py"
```


## OpenSSLを使ったデバッグ方法

OpenSSLローカルビルド

```bash
cd ~
mkdir -p local/download
cd local/download
curl -L https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.9.zip -O
file openssl-3.0.9.zip
unzip openssl-3.0.9.zip
cd openssl-openssl-3.0.9
./Configure --prefix=~/local/openssl --openssldir=~/local/ssl
make -j4
make install_sw install_ssldirs
```

サーバとして実行

```bash
~/local/openssl/bin/openssl s_server -accept 50007 \
  -cert ./cert/server.crt -key ./cert/server.key -tls1_3 -state -debug
```

クライアントとして実行

```bash
~/local/openssl/bin/openssl s_client -connect 127.0.0.1:50007 -state -debug -tls1_3
```
