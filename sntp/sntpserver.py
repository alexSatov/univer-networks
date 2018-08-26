import sys
import struct
import socket as sc
from time import time
from select import select
from argparse import ArgumentParser
from multiprocessing.dummy import Pool
from ntime import Packet, utc_to_ntp_bytes


class SntpServer:
    TIMEOUT = 1
    BUF_SIZE = 4 * 1024

    def __init__(self, delay, ip='localhost', port=123):
        self.ip = ip
        self.port = port
        self.pool = Pool()
        self.delay = delay

        self.sock = sc.socket(sc.AF_INET, sc.SOCK_DGRAM)
        self.sock.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))

        try:
            sys.stdout.write('Server is running [delay = %i]\r\n' % self.delay)
            self.launch()
        finally:
            self.sock.close()

    @property
    def current_time_binary(self):
        return utc_to_ntp_bytes(time() + self.delay)

    def launch(self):
        while True:
            read, _, _ = select([self.sock], [], [], self.TIMEOUT)
            if len(read) != 0:
                data, addr = self.sock.recvfrom(self.BUF_SIZE)
                receive = self.current_time_binary
                sys.stdout.write('%s\r\n' % addr[0])
                self.pool.apply_async(self.handle_client,
                                      (addr, data, receive))

    def handle_client(self, addr, data, receive):
        try:
            request = Packet.from_binary(data)
        except struct.error:
            sys.stdout.write('Incorrect package\r\n')
            pass

        originate = request.transmit_binary if request.transmit_binary != 0 \
            else self.current_time_binary
        transmit = self.current_time_binary

        packet = Packet(mode=4,
                        receive=receive,
                        origin=originate,
                        transmit=transmit,
                        version=request.version)

        self.sock.sendto(packet.to_binary(), addr)


def parse_args():
    arg_parser = ArgumentParser(description='Обманывающий sntp-сервер времени')

    arg_parser.add_argument('-d', '--delay',
                            type=int,
                            default=0,
                            help='Смещение времени (+/-) в секундах')

    arg_parser.add_argument('-p', '--port',
                            type=int,
                            default=123,
                            help='Порт, который слушаем')

    return arg_parser.parse_args()

if __name__ == '__main__':
    try:
        args = parse_args()
        server = SntpServer(args.delay, port=args.port)
    except KeyboardInterrupt:
        sys.stdout.write('^C')
        exit(0)
    except Exception as e:
        print(e)
