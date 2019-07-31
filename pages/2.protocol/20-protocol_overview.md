---
title: プロトコルの概要
tags: [protocol]
sidebar: doc_sidebar
permalink: protocol_overview.html
---


この章では [RFC 8446](https://tools.ietf.org/html/rfc8446) を読みながらTLS 1.3プロトコルの概要について理解していきます[^rfc8446] [^IPAPKI]。

TLSのプロトコルは主に2つの部分から構成されます。

- ハンドシェイクプロトコル : 使用するTLSのバージョンや暗号の種類などを決め、鍵共有を行います。
- レコードプロトコル : ハンドシェイクプロトコルで得られた共有鍵を用いて通信を暗号化します。

ハンドシェイクプロトコルはClientHelloからFinishedまでです。
それ以降はレコードプロトコルで、暗号化したメッセージ ApplicationData を送受信します。

TLS 1.3 のハンドシェイクは次の通りです。
これはフルハンドシェイクとも呼ばれます。

```
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]
```

- `+` は拡張を表します。例えば ClientHello メッセージは key_share 拡張を持ちます。
- `*` は必要に応じて送信されるメッセージや拡張を表します。
- `{}` は handshake_traffic_secret で暗号化されることを表します。
- `[]` は application_traffic_secret_N で暗号化されることを表します。Nは Application Data の送信毎に増えていく値です。

上の図に示したように、ハンドシェイクには「鍵交換」「サーバパラメータ」「認証」の3つの段階があります。

### 1. 鍵交換 (Key Exch)

Diffie-Hellman鍵交換で共有鍵を作るためのパラメータを送信します。

まず、クライアントは ClientHello メッセージを送り、サーバは ServerHello メッセージを返します。
ClientHello メッセージの中には、ランダムなノンス (ClientHello.random)、プロトコルのバージョンの一覧、共通鍵暗号とハッシュベースの鍵導出関数HKDFの組み合わせの一覧、などがあります。
一方で ServerHello メッセージでは、クライアント側が対応しているプロトコルやアルゴリズムの一覧から、選択した結果を返します。

### 2. サーバパラメータ (Server Params)

鍵交換以外のその他のパラメータを送信します。
メッセージとしては EncryptedExtensions と CertificateRequest の2つです。

- EncryptedExtensions : ClientHelloのTLS拡張に対するメッセージを返します。
- CertificateRequest : クライアント証明書で認証されたユーザとだけ通信する場合は、このメッセージを送信します。一般的なWebサーバなどのクライアント認証が不要なサーバでは、省略されます。

### 3. 認証 (Auth)

最後に、サーバ証明書 (とクライアント証明書) を通信相手に送信します。
メッセージとしては Certificate, CertificateVerify, Finished の3つです。

- Certificate : サーバはサーバ証明書を送信します。クライアントは CertificateRequest メッセージを受け取ったときだけ、クライアント証明書を送信します。
- CertificateVerify : 今までに受信したメッセージから署名を生成して送信します。このメッセージの中身は、受け取った証明書を使って署名の検証をします。検証が成功すれば、その証明書が間違いなく相手のものであることが確認できます。
- Finished : 鍵交換と認証処理が成功したことを通知します。

Finished を送信した時点で、ハンドシェイクプロトコルは完了します。
ハンドシェイクプロトコルが終わるとレコードプロトコルが始まります。
レコードプロトコルでは、鍵交換で得た共有鍵を使ってデータを暗号化し、ApplicationDataメッセージとして送受信します。

-----

[^rfc8446]: [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
[^IPAPKI]: [PKI 関連技術情報 -- IPA](https://www.ipa.go.jp/security/pki/index.html)
