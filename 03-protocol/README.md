
## プロトコル概要

この章では [RFC 8446](https://tools.ietf.org/html/rfc8446) を読みながら TLS 1.3 について理解し、Pythonを使って実装していきます。

TLSのプロトコルは主に2つの部分から構成されます。また、ハンドシェイクプロトコルには3つの段階があります。

- ハンドシェイクプロトコル : 使用するTLSのバージョンや暗号の種類などを決め、鍵共有を行います。
- レコードプロトコル : ハンドシェイクプロトコルで得られた共有鍵を用いて通信を暗号化します。

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

ハンドシェイクプロトコルはClientHelloからFinishedまでです。
それ以降はレコードプロトコルで、暗号化したメッセージを送受信します。
