
秘密鍵とオレオレ証明書の作成

```
openssl genrsa -out server.key
openssl req -new -key server.key -out server.csr \
  -config /usr/local/etc/openssl/openssl.cnf \
  -subj "/C=JP/ST=Tokyo/O=TeX2e/CN=tls13-test.co.jp"
openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
```

openssl で TLS 1.3 サーバ

```
~/local/bin/openssl s_server -accept 50007 \
  -cert ./cert/server.crt -key ./cert/server.key -tls1_3 -state -debug
```
