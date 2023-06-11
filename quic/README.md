
# mako-http3

* ClientHello & ServerHello まで実装完了
* クライアント側のみ

```
python quic/main_client.py
```


### Debug

Sample:
```
git clone https://github.com/cloudflare/quiche
```

サーバ側：
```
cargo run --manifest-path=apps/Cargo.toml --bin quiche-server -- --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --listen 127.0.0.1:4433
```

クライアント側：
```
cargo run --manifest-path=apps/Cargo.toml --bin quiche-client -- https://127.0.0.1:4433/ --no-verify
```

Wiresharkで復号する場合は、変数 `SSLKEYLOGFILE=./keylog.txt` をコマンド実行時に追加する。
