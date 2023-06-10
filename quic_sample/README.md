
# mako-http3

実装中

---

### Debug

Sample:
```
git clone https://github.com/cloudflare/quiche
cp quiche /opt/quiche
```

```
cd /opt/quiche
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
