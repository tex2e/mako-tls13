---
title: 鍵交換の構造体
tags: [protocol]
sidebar: doc_sidebar
permalink: handshake_key_exch.html
---

## Client Hello

TLSで最初にクライアント側から送るメッセージです。

```
uint16 ProtocolVersion;
opaque Random[32];

uint8 CipherSuite[2];    /* Cryptographic suite selector */

struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;
```

- legacy_version : TLSのバージョン (2byte)。TLS1.2以前の互換性のために必ず 0x0303 にします。
- random : 安全な乱数生成器によって生成された32bytesの乱数
- legacy_session_id : TLS 1.2でのクライアントが既存のセッションの再開をするときに使うフィールドですが、TLS 1.3ではセッションの再開が禁止されているので、ランダムな32byteの値を入れます。
- cipher_suite : クライアントが対応可能な暗号スイートの一覧
- legacy_compression_methods : 圧縮方法。必ず0にすること (c.f. CRIME攻撃)。
- extensions : TLS拡張のリスト。TLS1.3では必ず supported_versions 拡張が含まれるので、その拡張がなければTLS 1.2などで ClientHello してきていることがわかります。


## Server Hello

Client Helloの応答としてサーバ側が送るメッセージです。

```
struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id_echo<0..32>;
    CipherSuite cipher_suite;
    uint8 legacy_compression_method = 0;
    Extension extensions<6..2^16-1>;
} ServerHello;
```

- legacy_version : TLSのバージョン (2byte)。TLS 1.2以前の互換性のために必ず 0x0303 にします。
- random : 安全な乱数生成器によって生成された32byteの乱数
- legacy_session_id_echo : クライアントの ClientHello.legacy_session_id と同じ値が入ります。TLS1.2以前の互換性のためのものです。
- cipher_suite : サーバが ClientHello.cipher_suites から選んだ暗号スイートが入ります。
- legacy_compression_method : 圧縮方法。必ず 0 にすること (c.f. CRIME攻撃)。
- extensions : TLS拡張のリスト。TLS1.3では必ず supported_versions 拡張が含まれます。残りの鍵共有に関係ない拡張は EncryptedExtensions メッセージで送られます。
