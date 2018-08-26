import socket

HOST = 'whois.ripe.net'
PORT = 43


def as_socket(s):
    s.sendall(b'194.226.235.185\r\n')
    response = ''
    while True:
        buf = s.recv(1024).decode("utf-8")
        if len(buf) == 0:
            break
        response += buf
    print(response)


def as_fn(s):
    fn = s.makefile()

    for line in fn:
        line = line.strip()
        print(line)
        if not line:
            break

    s.sendall(b'194.226.235.185\n')

    for line in fn:
        line = line.strip()
        print(line)


if __name__ == "__main__":
    sock = socket.create_connection((HOST, PORT))
    as_fn(sock)
