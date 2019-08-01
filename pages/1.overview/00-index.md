---
title: "TLS 1.3自作入門"
keywords: homepage
tags:
sidebar: doc_sidebar
permalink: index.html
toc: false
redirect_from: /homepage.html
---

{{site.data.alerts.warning}}
...鋭意作成中です...
{{site.data.alerts.end}}

{{site.data.alerts.tip}}
TLS 1.3 をフルスクラッチするために役立つことを書きたい。
最終的には「CPUの創り方」や「30日でできる! TLS1.3自作入門」みたいな形にしたい。
{{site.data.alerts.end}}

### モチベーション

- TLS 1.3 を Python で実装できる
  - TLSのやりとりの流れが理解できる
  - 鍵共有の仕組みや安全性が理解できる
  - 認証付き暗号が理解できる
  - 公開鍵基盤の仕組みが理解できる
  - 実装・プロトコル・暗号技術に対する攻撃手法について理解できる

### 実装の流れ

- curlによる TLS 1.3 のテスト
- Pythonでソケット通信
- プロトコルのデータ構造をオブジェクト化する (ClientHello, ServerHello など)
- データ構造とバイト列の相互変換
- DH鍵共有
- 暗号化
  - AES_128_GCM
  - AES_256_GCM
  - CHACHA20_POLY1305


## 参考文献

- [RFC 8446 -- The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

{% include links.html %}
