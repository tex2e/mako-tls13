---
title: TLS拡張
tags:
sidebar: doc_sidebar
permalink: extensions.html
---


プロトコル自体を修正することなくTLSに機能を追加する仕組みがTLS拡張です。
TLS拡張は、先頭2byteで拡張の種類 (ExtensionType) を表し、その後に拡張の内容が続きます。

```
struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

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
```

## ALPN (Application-layer Protocol Negotiation)

TLS拡張名は application_layer_protocol_negotiation で、拡張タイプの値は 16 です。

TLS接続上でアプリケーション層に異なるプロトコルを使うことをネゴシエーションするためのTLS拡張がALPN (Application-Layer Protocol Negotiation) です。
具体的には複数のアプリケーションプロトコル、例えば HTTP/1.1 と HTTP/2 を同じ 443 番ポートで動かしたいときに使います。
どのアプリケーションプロトコルを使うかを、TLSの通信路を確立した後に選択するのではなく、TLSのハンドシェイクと同時に選択することで、クライアントサーバ間の通信回数を増やすことなくアプリケーションプロトコルを選択することができます。

クライアントとサーバの両方がこの拡張で相手に対応しているアプリケーションプロトコルを伝えます。
拡張の extension_data フィールドには ProtocolNameList というプロトコルの一覧が格納されます。

```
opaque ProtocolName<1..2^8-1>;

struct {
    ProtocolName protocol_name_list<2..2^16-1>
} ProtocolNameList;
```

- [RFC 7301 -- Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension](https://tools.ietf.org/html/rfc7301)

## CT (Certificate Transparency)

TLS拡張名は signed_certificate_timestamp で、拡張タイプの値は 18 です。

2011年にオランダの認証局 DigiNotar が不正アクセスを受け、不正なサーバ証明書が大量に発行された事件がありました。
不正なサーバ証明書は偽装Webサイトで使用され、フィッシングの危険性が高まります。
パブリック認証局によるサーバ証明書を全て記録することでインターネットPKIを改善しようというものが CT (Certificate Transparency : 証明書の透明性) で、Google社により2013年に提案されました。
CTの目的は3つあります。

1. ドメインの所有者ではない人が、そのドメインの証明書を発行することを不可能(もしくは非常に困難)にします。
2. 証明書が誤って発行されたのか悪意を持って発行されたのかを、ドメインの所有者やCAが判断できる監視・監査システムを提供します。
3. ユーザが悪意を持って発行された証明書に騙されないようにします。

流れとしては、まずサーバは、認証局から発行された証明書を公開のログサーバに登録します。
各ログサーバは SCT (Signed Certificate Timestamp : 認証済み証明書のタイムスタンプ) というタイムスタンプを各証明書に紐付けます。
サーバはサーバ証明書を送信するときに、このSCTも一緒にクライアントに送信します。
そして、クライアントは証明書とSCTを使ってログサーバの中にその証明書が登録されているかどうかを確認します。
ここで検証に失敗した場合は、同一のホスト名を持つ偽の証明書である可能性があると判断できます。

- [RFC 6962 -- Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [What is Certificate Transparency? - Certificate Transparency](https://www.certificate-transparency.org/)

## Heartbeat

TLS拡張名は heartbeat で、拡張タイプの値は 15 です。

Heartbeat とは keep-alive (通信相手の死活を確認する) および PMTU (Path MTU) 探索の機能を TLS と DTLS で提供するためのプロトコル拡張です。
TLSは通常はTCP上で使い、TCPには keep-alive 機能がありますが、Heartbeat が対象にしているのは DTLS というUDP上で動くTLSです。

しかし、2014年4月にOpenSSLのHeartbeatの実装には脆弱性 **Heartbleed** という、サーバのメモリ上にあるデータを取得することが可能になる深刻な問題が発見されました。
この影響で、Hearbeatはほとんどのサーバで無効にされています。
補足ですが、2019年6月現在に SSL Pulse で確認したところ、15万件以上のWebサイトの内、Heartbleed攻撃が可能なサイトは49件でした。

- [RFC 6520 -- Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension](https://tools.ietf.org/html/rfc6520)
- [Qualys SSL Labs - SSL Pulse](https://www.ssllabs.com/ssl-pulse/)

## SNI (Server Name Indication)

TLS拡張名は server_name で、拡張タイプの値は 0 です。

名前ベースバーチャルホストは、利用する全てのドメイン名に同じIPアドレスを使用することで、IPアドレスを節約するものです。しかし、TLSで通信を確立するためのハンドシェイク時にはホスト名がわからないと、サーバ証明書を使い分けることができません。
そこで、SSLハンドシェイク時にクライアントがアクセスしたいホスト名を伝えることで、サーバ側がグローバルIPごとではなくホスト名によって異なる証明書を使い分けることを可能にするためのTLS拡張が SNI (Server Name Indication) です。

- [RFC 6066 -- Transport Layer Security (TLS) Extensions: Extension Definitions, 3. Server Name Indication](https://tools.ietf.org/html/rfc6066#section-3)
- [Server Name Indication -- Wikipedia](https://ja.wikipedia.org/wiki/Server_Name_Indication)

## OCSP Stapling

TLS拡張名は status_request で、拡張タイプの値は 5 です。

OCSPはX.509証明書の失効情報を確認するためのプロトコルです。
しかし、OCSPレスポンダは認証局の負担を増やす問題と、どのサイトにアクセスしたのかをOCSPレスポンダも知り得てしまう問題があります。
これらの問題は、OCSP Stapling (OCSPステープリング) を使うことで解決できます。
具体的には、認証局がOCSPのレスポンスを返すのではなく、認証局がタイムスタンプを付与して(staplingして)署名したOCSPのレスポンスをコンテンツを配信するサーバに渡すことで、サーバがOCSPレスポンダを兼ねることができる方法です。

クライアント側は status_request 拡張を送信することで、OCSP Stapling に対応していることをサーバに伝えます。
クライアント側では拡張の extension_data フィールドに CertificateStatusRequest の内容を格納します。

```
struct {
    CertificateStatusType status_type;
    select (status_type) {
        case ocsp: OCSPStatusRequest;
    } request;
} CertificateStatusRequest;

enum { ocsp(1), (255) } CertificateStatusType;

struct {
    ResponderID responder_id_list<0..2^16-1>;
    Extensions  request_extensions;
} OCSPStatusRequest;

opaque ResponderID<1..2^16-1>;
opaque Extensions<0..2^16-1>;
```

サーバ側では status_request を受信したら Certificate メッセージの直後に CertificateStatus メッセージを送信します。CertificateStatus の OCSPResponse には DER でエンコードした OCSP レスポンスを格納します。

```
struct {
    CertificateStatusType status_type;
    select (status_type) {
        case ocsp: OCSPResponse;
    } response;
} CertificateStatus;

opaque OCSPResponse<1..2^24-1>;
```

これにより、各サーバはTLSハンドシェイクの中にOCSPレスポンスを埋め込むことができます。

- [RFC 6066 -- Transport Layer Security (TLS) Extensions: Extension Definitions, 8. Certificate Status Request](https://tools.ietf.org/html/rfc6066#section-8)

## 鍵共有アルゴリズム

TLS拡張名は supported_groups で、拡張タイプの値は 10 です。

この拡張は TLS 1.2 までは elliptic_curves という名前でしたが、TLS 1.3 では supported_groups になりました。
クライアント側が対応している鍵共有アルゴリズムをサーバ側に伝えるためのTLS拡張です。
拡張の extension_data フィールドには NamedGroupList が入り、対応しているアルゴリズムの一覧が格納されます。

```
enum {
    /* Elliptic Curve Groups (ECDHE) */
    secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
    x25519(0x001D), x448(0x001E),

    /* Finite Field Groups (DHE) */
    ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
    ffdhe6144(0x0103), ffdhe8192(0x0104),

    ...
} NamedGroup;

struct {
    NamedGroup named_group_list<2..2^16-1>;
} NamedGroupList;
```

TLS 1.3で必ずサポートとしないといけないアルゴリズムは secp256r1 です。

- [RFC 8446 -- The Transport Layer Security (TLS) Protocol Version 1.3, 4.2.7. Supported Groups](https://tools.ietf.org/html/rfc8446#section-4.2.7)


## 署名アルゴリズム

- TLS拡張名は signature_algorithms で、拡張タイプの値は 13 です。
- TLS拡張名は signature_algorithms_cert で、拡張タイプの値は 50 です。

クライアント側が対応している署名アルゴリズムとハッシュ関数をサーバ側に伝えるためのTLS拡張が signature_algorithms 拡張です。
クライアント側が、証明書の検証では違った署名アルゴリズムを使いたい場合は、signature_algorithms_cert 拡張でアルゴリズムを伝えることもできますが、通常これは省略されます。
TLS 1.3で使用できる署名アルゴリズムの一覧は次の通りです。

```
enum {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256(0x0401),
    rsa_pkcs1_sha384(0x0501),
    rsa_pkcs1_sha512(0x0601),

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256(0x0403),
    ecdsa_secp384r1_sha384(0x0503),
    ecdsa_secp521r1_sha512(0x0603),

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256(0x0804),
    rsa_pss_rsae_sha384(0x0805),
    rsa_pss_rsae_sha512(0x0806),

    /* EdDSA algorithms */
    ed25519(0x0807),
    ed448(0x0808),

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256(0x0809),
    rsa_pss_pss_sha384(0x080a),
    rsa_pss_pss_sha512(0x080b),

    ...
} SignatureScheme;
```

TLS 1.3で必ずサポートしないといけない署名アルゴリズムは rsa_pkcs1_sha256, rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256 の3つです。

- [RFC 8446 -- The Transport Layer Security (TLS) Protocol Version 1.3, 4.2.3. Signature Algorithms](https://tools.ietf.org/html/rfc8446#section-4.2.3)
