import connection

server_conn = connection.ServerConnection()
data = server_conn.recv_msg()
server_conn.send_msg(data)
