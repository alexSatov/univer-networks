import socket
import select

sock = socket.create_connection(('time.nist.gov', 13))

while True:
    r, _, _ = select.select([sock], [], [], 5)
    if not r:
        print('empty')
        break
    response_string = sock.recv(1024).decode()
    print(response_string)
    break

sock.shutdown(socket.SHUT_RDWR)
sock.close()
