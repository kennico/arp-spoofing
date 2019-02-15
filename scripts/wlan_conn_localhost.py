import socket

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

conn.bind(('127.0.0.1', 44444))
print("Local:", conn.getsockname())

conn.connect(('192.168.43.24', 8080))

print("Remote", conn.getpeername())

conn.close()
