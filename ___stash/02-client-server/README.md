
## ソケット通信

この章では2者間で平文通信をするための Python プログラムを作ります。

TCP/IPプロトコルの簡単な例として、受信したデータをクライアントのそのまま返すサーバを作ります[^pythonsocket]。
サーバでは socket(), bind(), listen(), accept() を実行し、クライアントでは socket() と connect() だけを呼び出します。

サーバ側：

```python
import socket

HOST = '127.0.0.1'
PORT = 1234
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024) # データの受信
            if not data: break
            conn.sendall(data)     # データの送信
```

クライアント側：

```python
import socket

HOST = '127.0.0.1'
PORT = 1234
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'Hello, world') # データの送信
    data = s.recv(1024)        # データの受信
print('Received', repr(data))
```

コンソールを2つ開いて、サーバ側、クライアント側の順に実行すると動きます。

これでも良いのですが、TLS 1.3 の実装を簡単にするために、サーバ側とクライアント側のやりとりは send_msg と recv_msg という共通のメソッドだけでできるようにします。
まず、Connection という抽象クラスを作り、初期化の処理を子クラスで定義するようにします。
デザインパターンでいうところの「Template Method」です。

connection.py :

```python
import socket

HOST = '127.0.0.1'
PORT = 1234

# 抽象クラス
class Connection:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.init_socket()

    def send_msg(self, byte_str):
        return self.socket.sendall(byte_str)

    def recv_msg(self):
        return self.socket.recv(2**14)

    def close(slef):
        return self.socket.close()

# クライアント側
class ClientConnection(Connection):
    def init_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.socket = self.sock

# サーバ側
class ServerConnection(Connection):
    def init_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        conn, addr = self.sock.accept()
        self.socket = conn
        self.addr = addr
        print('Connected by', self.addr)
```

サーバ側とクライアント側の両方で connection.py をインポートします。

server.py :

```python
import connection

server_conn = connection.ServerConnection() # サーバ側
data = server_conn.recv_msg() # データの受信
server_conn.send_msg(data)    # データの送信
```

client.py :

```python
import connection

client_conn = connection.ClientConnection() # クライアント側
client_conn.send_msg(b'Hello, world') # データの送信
data = client_conn.recv_msg()         # データの受信
print('Received', data)
```

データの送信と受信をいい感じに抽象化できて、最初の例よりも読みやすくなりました。
TLS 1.3 の実装では、この抽象化したコードを使っていきます。


### 参考文献

[^pythonsocket]: [socket --- 低水準ネットワークインターフェイス &#8212; Python 3.7.4 ドキュメント](https://docs.python.org/ja/3/library/socket.html#socket.socket.recv)
