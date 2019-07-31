---
title: TLS 1.3対応のOpenSSLとcURLのインストール
tags:
sidebar: doc_sidebar
permalink: install_openssl_and_curl.html
---


## OpenSSL v1.1.1

OpenSSL は TLS クライアントとしても使うことができます。
まずは OpenSSL のバージョンを確認しましょう。
コマンドで `openssl version` と入力して「OpenSSL 1.1.1」と表示されれば TLS 1.3 が使えます。
それ以下のバージョンだと TLS 1.2 までしか使えません。GitHubの[openssl](https://github.com/openssl/openssl)のページにアクセスしてダウンロードすることもできますが、最新のレポジトリは必ず動くという保証はないので、opensslの[releases](https://github.com/openssl/openssl/releases)から1.1.1以上の最新のバージョンをダウンロードします[^openssl]。
ここでは OpenSSL_1_1_1c をインストールする例をやりますが、必要に応じてバージョンを置き換えながら読んでください。

ソースのダウンロードと展開：

```bash
wget https://github.com/openssl/openssl/archive/OpenSSL_1_1_1c.zip
unzip OpenSSL_1_1_1c.zip
cd openssl-OpenSSL_1_1_1c
```

ビルドディレクトリの作成と ./config による Makefile の作成：

```bash
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

<!DOCTYPE html>...
<p class="title">Congratulations! You're connected using <span class="green">TLSv1.3</span>!</p>...
```

Congratulations! You're connected using TLSv1.3! という文字列がHTMLの中にあれば成功です！


## curl 7.52.0

次に TLS 1.3で通信ができる curl も用意します。
curl は 7.52.0 以上であることに加えて、コンパイル時に TLS 1.3 対応の SSL を指定しないと TLS 1.3 で通信できません[^curl]。
curl の最新バージョンは [curl/Download](https://curl.haxx.se/download.html) で確認できるので必要に応じて最新バージョンに置き換えてください。

```bash
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

-----

[^curl]: [PLAY TLS 1.3 WITH CURL](https://daniel.haxx.se/blog/2018/03/27/play-tls-1-3-with-curl/)
[^openssl]: [Using TLS1.3 With OpenSSL](https://www.openssl.org/blog/blog/2017/05/04/tlsv1.3/)