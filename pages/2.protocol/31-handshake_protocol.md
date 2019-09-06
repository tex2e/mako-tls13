---
title: プロトコルの構造体
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

以下では、それぞれの構造体について詳しく見ていきます。

# レコード層 (Record Layer)

レコード層はTLSパケットの一番下の層のことです。
TLSの全てのメッセージは、ここで説明する TLSPlaintext または TLSCiphertext のどちらかに格納されて送信されます。

## TLSPlaintext

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
    ProtocolVersion legacy_record_version = 0x0303;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
```

TLSPlaintextについて：

- type : 格納する構造体の種類 (2byte)
- legacy_record_version : TLSのバージョン (2byte)。TLS 1.2以前の互換性のために必ず 0x0303 にします。
- length : 上のレイヤの構造体のバイト長 (2byte)
- fragment : 上のレイヤの構造体のデータ。ここのHandshake構造体のデータなどが格納されます。

ProtocolVersion はそれぞれ、0x0300 は SSL 3.0、0x0301 は TLS 1.0、0x0302 は TLS 1.1、0x0303 は TLS 1.2、0x0304 は TLS 1.3 です。
TLS 1.3 では TLSPlaintext.legacy_record_version フィールドは非推奨で、もはや使われません。
しかし互換性のために、このフィールドは残されています。

TLSPlaintextのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
class ContentType(Enum):
    elem_t = Uint8

    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)

ProtocolVersion = Uint16

@meta.struct
class TLSPlaintext(meta.StructMeta):
    type: ContentType
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.fragment)))
    fragment: OpaqueLength
```

## TLSCiphertext

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
- legacy_record_version : TLSのバージョン (2byte)。TLS 1.2以前の互換性のために必ず 0x0303 にします。
- length : 上のレイヤの構造体のバイト長 (2byte)
- encrypted_record : 上のレイヤの構造体のデータ。TLSInnerPlaintext が格納されます。

TLSInnerPlaintext を TLSCiphertext に暗号化するときは認証付き暗号(AEAD)を使います。

TLSCiphertextのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。
TLSInnerPlaintext構造体は暗号化をする前に16byteの倍数になるようにパディングを加えているだけなので、構造体をプログラムで表現しない方向で実装して行きます。

```python
@meta.struct
class TLSCiphertext(meta.StructMeta):
    opaque_type: ContentType = ContentType.application_data
    legacy_record_version: ProtocolVersion = ProtocolVersion(0x0303)
    length: Uint16 = lambda self: Uint16(len(bytes(self.encrypted_record)))
    encrypted_record: OpaqueLength
```


# ハンドシェイクプロトコル

ハンドシェイクに関連するメッセージは Handshake 構造体を使います。

## Handshake

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

メッセージデータは .msg_type の値によって型が変わります。
例えば、.msg_type が HandshakeType.client_hello のときは ClientHello 型になります。

HandshakeのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
@meta.struct
class Handshake(meta.StructMeta):
    msg_type: HandshakeType
    length: Uint24 = lambda self: Uint24(len(bytes(self.msg)))
    msg: meta.Select('msg_type', cases={
        HandshakeType.client_hello:         ClientHello,
        HandshakeType.server_hello:         ServerHello,
        HandshakeType.encrypted_extensions: EncryptedExtensions,
        HandshakeType.certificate:          Certificate,
        HandshakeType.certificate_verify:   CertificateVerify,
        HandshakeType.finished:             Finished,
        HandshakeType.new_session_ticket:   NewSessionTicket,
    })
```

## Client Hello

TLSで最初にクライアント側から送るメッセージは ClientHello です。

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

ClientHelloのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
@meta.struct
class ClientHello(meta.StructMeta):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suites: CipherSuites
    legacy_compression_methods: OpaqueUint8 = OpaqueUint8(b'\x00')
    extensions: Extensions
```

## Server Hello

ClientHelloの応答としてサーバ側が送るメッセージは ServerHello です。

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

ServerHelloのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
@meta.struct
class ServerHello(meta.StructMeta):
    legacy_version: ProtocolVersion = ProtocolVersion(0x0303)
    random: Random = lambda self: Random(os.urandom(32))
    legacy_session_id_echo: OpaqueUint8 = lambda self: OpaqueUint8(os.urandom(32))
    cipher_suite: CipherSuite
    legacy_compression_method: Opaque1 = Opaque1(b'\x00')
    extensions: Extensions
```

## Hello Retry Request

ClientHello で送られてきた情報がハンドシェイクを進めるのに不十分なときには、サーバは HelloRetryRequest を返します。
ただし、HelloRetryRequest の構造は ServerHello の構造と同じです。

## Encrypted Extensions

サーバ側がServerHelloを送信した後に、必ず送信するメッセージです。

```
enum {
    server_name(0),                             /* RFC 6066 */
    max_fragment_length(1),                     /* RFC 6066 */
    status_request(5),                          /* RFC 6066 */
    supported_groups(10),                       /* RFC 8422, 7919 */
    signature_algorithms(13),                   /* RFC 8446 */
    use_srtp(14),                               /* RFC 5764 */
    heartbeat(15),                              /* RFC 6520 */
    application_layer_protocol_negotiation(16), /* RFC 7301 */
    signed_certificate_timestamp(18),           /* RFC 6962 */
    client_certificate_type(19),                /* RFC 7250 */
    server_certificate_type(20),                /* RFC 7250 */
    padding(21),                                /* RFC 7685 */
    pre_shared_key(41),                         /* RFC 8446 */
    early_data(42),                             /* RFC 8446 */
    supported_versions(43),                     /* RFC 8446 */
    cookie(44),                                 /* RFC 8446 */
    psk_key_exchange_modes(45),                 /* RFC 8446 */
    certificate_authorities(47),                /* RFC 8446 */
    oid_filters(48),                            /* RFC 8446 */
    post_handshake_auth(49),                    /* RFC 8446 */
    signature_algorithms_cert(50),              /* RFC 8446 */
    key_share(51),                              /* RFC 8446 */
    (65535)
} ExtensionType;

struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

struct {
    Extension extensions<0..2^16-1>;
} EncryptedExtensions;
```

サーバが特別なことをしない場合は、TLS拡張が0個のEncryptedExtensionsをクライアントに送信します。
EncryptedExtensionsで送信できるTLS拡張の一覧は以下の通りです。

- server_name ([RFC 6066](https://tools.ietf.org/html/rfc6066))
- max_fragment_length ([RFC 6066](https://tools.ietf.org/html/rfc6066))
- supported_groups ([RFC 7919](https://tools.ietf.org/html/rfc7919))
- use_srtp ([RFC 5764](https://tools.ietf.org/html/rfc5764))
- heartbeat ([RFC 6520](https://tools.ietf.org/html/rfc6520))
- application_layer_protocol_negotiation ([RFC 7301](https://tools.ietf.org/html/rfc7301))
- client_certificate_type ([RFC 7250](https://tools.ietf.org/html/rfc7250))
- server_certificate_type ([RFC 7250](https://tools.ietf.org/html/rfc7250))
- early_data ([RFC 8446](https://tools.ietf.org/html/rfc8446))


## Certificate Request

CertificateRequest はクライアント認証を必要とする場合に、サーバがクライアントに送信するメッセージです。

```
struct {
    opaque certificate_request_context<0..2^8-1>;
    Extension extensions<2..2^16-1>;
} CertificateRequest;
```

## Certificate

Certificate はサーバ証明書を送信するためのメッセージです。
事前共有鍵(PSK)を使う場合は省略することができます。

```
enum {
    X509(0),
    RawPublicKey(2),
    (255)
} CertificateType;

struct {
    select (certificate_type) {
        case RawPublicKey:
          /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
          opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

        case X509:
          opaque cert_data<1..2^24-1>;
    };
    Extension extensions<0..2^16-1>;
} CertificateEntry;

struct {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
```

CertificateのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
class CertificateType(Enum):
    elem_t = Uint8

    X509 = Uint8(0)
    RawPublicKey = Uint8(2)

@meta.struct
class CertificateEntry(meta.StructMeta):
    cert_data: OpaqueUint24
    extensions: Extensions

CertificateEntrys = List(size_t=Uint24, elem_t=CertificateEntry)

@meta.struct
class Certificate(meta.StructMeta):
    certificate_request_context: OpaqueUint8
    certificate_list: CertificateEntrys
```

## CertificateVerify

CertificateVerify は証明書に署名をしたデータを送信します。

```
struct {
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} CertificateVerify;
```

CertificateVerifyのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
@meta.struct
class CertificateVerify(meta.StructMeta):
    algorithm: SignatureScheme
    signature: OpaqueUint16
```

## Finished

Finished では同じ鍵を共有できたかを確認するためのメッセージです。

```
struct {
    opaque verify_data[Hash.length];
} Finished;
```

FinishedのRFC記法をPythonで表現するときは以下のようなプログラムにしたいと思います。

```python
class Hash:
    length = None

OpaqueHash = Opaque(lambda self: Hash.length)

@meta.struct
class Finished(meta.StructMeta):
    verify_data: OpaqueHash
```
