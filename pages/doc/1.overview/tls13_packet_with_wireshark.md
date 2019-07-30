---
title: WiresharkでTLS 1.3を観察する
tags:
sidebar: doc_sidebar
permalink: tls13_packet_with_wireshark.html
---

openssl や curl が TLS 1.3 で通信できるようになったので、Wireshark でパケットを見てみます。
ここでは2種類のハンドシェイクが現れます。「TCPのハンドシェイク」と「TLSのハンドシェイク」です。
TCPのパケットは右側に `[SYN]`, `[SYN,ACK]`, `[ACK]`, `[FIN]`, `[FIN,ACK]` と書かれています。
TCPの3ウェイハンドシェイクとしてはコネクション開始時の SYN, SYN+ACK, ACK や終了時の FIN, FIN+ACK, ACK があります。
一方、TLSのパケットは `Client Hello`, `Server Hello`, `Application Data` などと書かれています。
TLSの手順は ClientHello と ServerHello で公開鍵暗号による鍵共有をして、ApplicationData でメッセージを暗号化するという流れです。
レイヤー的にはTCPの上の層にTLSがあるので、TLSのパケットを送ると、正しく受け取ったことをTCPのACKで返してくれます。
なので、TLSよりもTCPのパケットが一杯流れるということを知っておいてください。

では実際にTLSのパケットを捕まえてみます。
まずは Wireshark を起動して、Wi-Fi のインターフェイスを選択します。
様々なパケットが流れているので、設定(歯車のアイコン)のキャプチャフィルタで `tcp port https` とすれば、HTTPSの通信だけにすることができます。


## curl の TLS 1.3 で通信するとき

パケットキャプチャしている状態で以下の curl コマンドを入力します。

```
~/local/bin/curl -v --tlsv1.3 https://tls13.pinterjann.is
```

![TLS 1.3 で通信したときのパケットキャプチャ](assets/wireshark/img/tls13.png)


## curl の TLS 1.2 で通信するとき

パケットキャプチャしている状態で以下の curl コマンドを入力します。

```
~/local/bin/curl -v --tls-max 1.2 https://tls13.pinterjann.is
```

![TLS 1.2 で通信したときのパケットキャプチャ](assets/wireshark/img/tls12.png)

サーバがクライアントに送るパケットでHTMLを渡していると思われるパケットを青色にしました。
両者を比較すると TLS 1.3 の方が 0.2秒ほど早くレスポンスが返ってきています。
他にも TLS 1.2 では Certificate (証明書を送るパケット) が見えますが、TLS 1.3では暗号化されているので Application Data (暗号化データを送るパケット) しか見えません。
これらはTLS 1.3でのプロトコルの改善によるものです。
