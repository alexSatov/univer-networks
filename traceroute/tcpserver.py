import socket
from time import sleep
from threading import Thread


class TcpServer:
    IP = 'localhost'
    PORT = 4343
    CLIENTS_COUNT = 100

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.IP, self.PORT))
        self.sock.listen(self.CLIENTS_COUNT)

        try:
            self.launch()
        finally:
            self.sock.close()

    def launch(self):
        while True:
            conn, addr = self.sock.accept()
            thread = Thread(target=self.handle_client,
                            args=(conn, addr))
            thread.start()

    @staticmethod
    def handle_client(conn, addr):
        try:
            print("Connection from {0}".format(addr))
            conn.sendall(b"Hello!")
            sleep(5)
            conn.sendall(b"Bye!")
        finally:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

if __name__ == '__main__':
    tcp_server = TcpServer()
