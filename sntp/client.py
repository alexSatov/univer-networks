import socket
import select

HOST = 'localhost'
PORT = 4444
addr = (HOST, PORT)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data = b'Hi'
udp_socket.sendto(data, addr)

try:
    if select.select([udp_socket], [], [], 1)[0]:
        data, _ = udp_socket.recvfrom(2048)
        if len(data) != 0:
            print(data.decode())
finally:
    udp_socket.close()
