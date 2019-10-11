import connection

client_conn = connection.ClientConnection()
client_conn.send_msg(b'Hello, world')
data = client_conn.recv_msg()
print('Received', data)
