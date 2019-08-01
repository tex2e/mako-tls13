---
title: ハンドシェイクプロトコルの構造体
tags: [protocol]
sidebar: doc_sidebar
permalink: handshake_protocol.html
---

TLSプロトコルのパケットの構造について大まかに説明します。
まず、全てのメッセージは TLSPlaintext または TLSCiphertext 構造体の中に格納され、パケットとして送信されます。
また、ハンドシェイクプロトコルの間は TLSPlaintext/TLSCiphertext 構造体の中には Handshake 構造体が格納されます。
この Handshake 構造体の中に ClientHello メッセージなどが格納されます。

例えば、ハンドシェイクにおいてクライアントは始めに ClientHello メッセージを送信しますが、その階層は次のようになります (構造的には TLSPlaintext の中の Handshake の中に ClientHello がある状態です)。

```
TLSPlaintext
└── Handshake
    └── ClientHello
```

以下では、TLSPlaintext と Handshake の構造体について詳しく見ていきます。

## レコード層 (Record Layer)

レコード層はTLSパケットの一番下の層のことです。
TLSの全てのメッセージは、ここで説明する TLSPlaintext または TLSCiphertext のどちらかに格納されて送信されます。

### TLSPlaintext

TLSPlaintext 構造体は平文メッセージを送信するための構造体です。

```
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion legacy_record_version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
```

TLSPlaintextについて：

- type : 格納する構造体の種類 (2byte)
- legacy_record_version : TLSのバージョン (2byte)。必ず 0x0303 にします。
- length : 上のレイヤの構造体のバイト長 (2byte)
- fragment : 上のレイヤの構造体のデータ。ここのHandshake構造体のデータなどが格納されます。

ProtocolVersion はそれぞれ、0x0300 は SSL 3.0、0x0301 は TLS 1.0、0x0302 は TLS 1.1、0x0303 は TLS 1.2、0x0304 は TLS 1.3 です。
TLS 1.3 では TLSPlaintext.legacy_record_version フィールドは非推奨で、もはや使われません。
しかし互換性のために、このフィールドは残されています。

### TLSCiphertext

TLSCiphertext 構造体は暗号化したメッセージを送信するための構造体です。
実際には、送信したいメッセージの構造体を TLSInnerPlaintext 構造体に格納してバイト長が 64 の倍数などとなるようにゼロパディングを加えた上で、暗号化した構造体データを TLSCiphertext.encrypted_record に格納します。

```
struct {
    opaque content[TLSPlaintext.length];
    ContentType type;
    uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct {
    ContentType opaque_type = application_data; /* 23 */
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    uint16 length;
    opaque encrypted_record[TLSCiphertext.length];
} TLSCiphertext;
```

TLSInnerPlaintextについて：

- content : 暗号化したい構造体のデータ
- type : 暗号化したい構造体の種類 (2byte)
- zeros : ゼロパディング (任意長)

TLSCiphertextについて：

- opaque_type : 上のレイヤの構造体の種類 (2byte)。必ず application_data の値 (0x17) にします。
- legacy_record_version : TLSのバージョン (2byte)。必ず 0x0303 にします。
- length : 上のレイヤの構造体のバイト長 (2byte)
- encrypted_record : 上のレイヤの構造体のデータ。TLSInnerPlaintext が格納されます。

TLSInnerPlaintext を TLSCiphertext に暗号化するときは認証付き暗号(AEAD)を使います。


## ハンドシェイクプロトコル

ハンドシェイクに関連するメッセージは Handshake 構造体を使います。

### Handshake

Handshake 構造体は、ハンドシェイクプロトコルで鍵共有や証明書の送信をするための構造体です。

```
enum {
    client_hello(1),
    server_hello(2),
    new_session_ticket(4),
    end_of_early_data(5),
    encrypted_extensions(8),
    certificate(11),
    certificate_request(13),
    certificate_verify(15),
    finished(20),
    key_update(24),
    message_hash(254),
    (255)
} HandshakeType;

struct {
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* remaining bytes in message */
    select (Handshake.msg_type) {
        case client_hello:          ClientHello;
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
    };
} Handshake;
```

Handshakeについて：

- msg_type : メッセージ構造体の種類 (2byte)
- length : メッセージ構造体のバイト長 (3byte)
- メッセージデータ : メッセージ構造体のデータ
