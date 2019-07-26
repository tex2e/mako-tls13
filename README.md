
TLS 1.3 をフルスクラッチするために役立つことを書きたい。
最終的には「n日でできる! TLS1.3自作入門」みたいな形にしたい。

モチベーション：

- TLS 1.3 を Python で実装できる
  - 鍵共有の仕組みや安全性が理解できる
  - 認証付き暗号が理解できる
  - 公開鍵基盤の仕組みが理解できる
- 以下はおまけ的な要素
  - RFCの読み方
  - SSL/TLS の歴史や攻撃手法

目次：

- Pythonでソケット通信
- プロトコルのデータ構造をオブジェクト化する (ClientHello, ServerHello など)
- データ構造とバイト列の相互変換
- DH鍵共有
- 暗号化
  - AES_128_GCM
  - AES_256_GCM
  - CHACHA20_POLY1305
- curlによる TLS 1.3 のテスト

参考文献：

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Qualys SSL Labs - SSL Pulse](https://www.ssllabs.com/ssl-pulse/)
- [Using TLS1.3 With OpenSSL](https://www.openssl.org/blog/blog/2017/05/04/tlsv1.3/)
- [PLAY TLS 1.3 WITH CURL](https://daniel.haxx.se/blog/2018/03/27/play-tls-1-3-with-curl/)

--------------------

## はじめに

インターネットの前身であるARPANETが設計された当時はネットに接続する参加者は大学関係者と限られていたので、性善説に基づいて通信路を暗号化する必要はありませんでした。しかし、誰もがインターネットに参加する現代では、悪意のある人やプロバイダが飛び交うパケットを捕らえて通信内容を調べるかもしれません (郵便はがきと同じです)。実際にNSAはPRISMによる広域盗聴をし、XKeyscoreで解析をすることで個人情報の収集をしていました。通信内容から個人情報やパスワード、クレジットカード番号などを収集されては、安心してインターネットを利用することはできません。
この問題をトランスポート層で解決するのがTLS (Transport Layer Security) です。

### TLS

TLS は2者間の通信を安全にするためのものです。
ここでいう安全というのは、次の特性を持ちます。

- 認証 : 通信者は認証される特性 (サーバ証明書などによる証明)
- 機密性 : 権限を持つ人だけが通信内容にアクセスできる特性 (通信内容の暗号化)
- 完全性 : 改竄されることなく正確な状態を保つ特性 (ハッシュによる改ざん検知)

### TLS 1.2との違い

TLS 1.3はTLS 1.2と比較したときの主な変更点には、次のようなものがあります。

- 暗号アルゴリズムの選別 : **認証付き暗号(AEAD)**だけが使えるようになりました。これにより、互換性用の安全でないアルゴリズムが削除され、暗号文の改ざんが検知可能となりました。
- **前方秘匿性**の徹底 : セッション鍵を通信毎に破棄します。セッション鍵を使い回すことは、秘密鍵が漏れたときに過去の全ての通信が復号できることになりかねません。
- プロトコルの改良 :

- ハンドシェイクの通信回数が減少 (2-RTT ⇒ 1-RTT)
- ClientHelloとServerHelloで鍵共有した後のハンドシェイクは全て暗号化
- 鍵導出関数の変更 (PRF ⇒ HKDF)


## プロトコル

この章では TLS 1.3 について説明し、Pythonを使って実装していきます。

TLSのプロトコルは主に2つの部分から構成されます。

- ハンドシェイクプロトコル : 使用するTLSのバージョンや暗号の種類などを決め、鍵共有を行います。
- レコードプロトコル : ハンドシェイクプロトコルで得られた共有鍵を用いて通信を暗号化します。

### OpenSSL v1.1.1

OpenSSL は TLS クライアントとしても使うことができます。
まずは OpenSSL のバージョンを確認しましょう。
コマンドで `openssl version` と入力して「OpenSSL 1.1.1」と表示されれば TLS 1.3 が使えます。
それ以下のバージョンだと TLS 1.2 までしか使えません。GitHubの[openssl](https://github.com/openssl/openssl)のページにアクセスしてダウンロードすることもできますが、最新のレポジトリは必ず動くという保証はないので、opensslの[releases](https://github.com/openssl/openssl/releases)から1.1.1以上の最新のバージョンをダウンロードします。
ここでは OpenSSL_1_1_1c をインストールする例をやりますが、必要に応じてバージョンを置き換えながら読んでください。

ソースのダウンロードと展開：

```
wget https://github.com/openssl/openssl/archive/OpenSSL_1_1_1c.zip
unzip OpenSSL_1_1_1c.zip
cd openssl-OpenSSL_1_1_1c
```

ビルドディレクトリの作成と ./config による Makefile の作成：

```
mkdir build && cd build
../config --prefix=$HOME/local -DSSL_DEBUG
make -j4
make install_runtime install_dev
```

./config のオプションについて

1. --prefix : インストール先を指定します。`--prefix=$HOME/local` と指定すればコマンドは $HOME/local/bin/openssl に置かれます。
2. -D : `-DSSL_DEBUG` で SSL_DEBUG というマクロを定義します。これを有効にするとデバッグモードで openssl が実行されます。openssl の動作を調査するときに役に立つので有効にしておきましょう。

make でオプション -j4 を付けると4並列でコンパイルするようになるので、高速化することができます。
make install ではなく make install_runtime install_dev をしているのはドキュメントはインストールしないようにして早く終わらせるためです。
インストールが終わったら、さっそく実行してみましょう。
https://tls13.pinterjann.is/ は TLS 1.3 に対応しているサイトなので、ここにアクセスしてみます。

```
~/local/bin/openssl s_client -connect tls13.pinterjann.is:443 -tls1_3
```

オプションについて

1. s_client : SSL/TLSのクライアントとして動作します。
2. -connect : 接続先のホストとポートを指定します。
3. -tls1_3 : TLS 1.3 で接続します。

実行すると、送受信したバイト列が16進で流れてきます。
TLS 1.3の通信が確立すると流れが止まって、入力待ちになるので、HTTPプロトコルで挨拶しましょう。
試しに `GET / HTTP/1.0` と入力して2回Enterを押すと、サーバから応答がHTMLで返ってきます。

```
GET / HTTP/1.0

HTTP/1.1 200 OK
Server: nginx/1.16.0
Content-Type: text/html; charset=utf-8
Content-Length: 1585
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'
Strict-Transport-Security: max-age=31536000

<!DOCTYPE html><head><title>TLS 1.3 (RFC8446) Test Server</title><meta name="description" content="This is a TLS 1.3 (RFC8446) test website that runs on OpenSSL and NGINX">
...省略...
<p class="title">Congratulations! You're connected using <span class="green">TLSv1.3</span>!</p><p class="message">Cipher: TLS_AES_256_GCM_SHA384</p>
...
```

Congratulations! You're connected using TLSv1.3! という文字列がHTMLの中にあれば成功です！

### curl 7.52.0

次に TLS 1.3で通信ができる curl も用意します。
curl は 7.52.0 以上であることに加えて、コンパイル時に TLS 1.3 対応の SSL を指定しないと TLS 1.3 で通信できません。
curl の最新バージョンは [curl/Download](https://curl.haxx.se/download.html) で確認できるので必要に応じて最新バージョンに置き換えてください。

```
wget https://curl.haxx.se/download/curl-7.65.3.zip
unzip curl-7.65.3.zip
cd curl-7.65.3
./configure --prefix=$HOME/local --with-ssl=$HOME/local
make -j4
make install-exec
```

./config のオプションについて

1. --prefix : インストール先を指定します。`--prefix=$HOME/local` と指定すればコマンドは $HOME/local/bin/curl に置かれます。
2. --with-ssl : 使用する SSL がある場所を指定します。ここで TLS 1.3 対応の SSL を使います。

インストールできたら実行してみます。-v を付けると詳細が表示されるので TLS 1.3 で通信しているか確認できます。

```
~/local/bin/curl -v --tlsv1.3 https://tls13.pinterjann.is
```

出力の中に「SSL connection using TLSv1.3」という文字列があれば、TLS 1.3で接続されていることが確認できます。


### WiresharkでTLS 1.3を観察する

openssl や curl が TLS 1.3 で通信できるようになったので、Wireshark でパケットを見てみます。

```
~/local/bin/curl -v --tlsv1.3 https://tls13.pinterjann.is
```

```
~/local/bin/curl -v --tls-max 1.2 https://tls13.pinterjann.is
```
