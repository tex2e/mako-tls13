import socket

HOST = '127.0.0.1'
PORT = 1234

class Connection:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.init_socket()
        self.socket.setblocking(False)
        self.fs = self.socket.makefile('rwb', buffering=0)

    def send_msg(self, b):
        return self.fs.write(b)

    def recv_msg(self, setblocking=False):
        if setblocking:
            self.socket.setblocking(True)
            record_header = self.fs.read(5)
            record_length = int.from_bytes(record_header[3:5], byteorder='big')
            record_content = self.fs.read(record_length)
            self.socket.setblocking(False)
            return record_header + record_content

        else:
            return self.fs.readall()

    def close(self):
        return self.fs.close()

class ClientConnection(Connection):
    def init_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.socket = self.sock

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
