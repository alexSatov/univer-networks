import socket as sock
from sys import stdout
from select import select
from threading import Lock
from dnscache import DnsCache
from ipaddress import IPv4Address
from argparse import ArgumentParser
from multiprocessing.dummy import Pool
from dns import Packet, MessageType, RCode


class DnsServer:
    PORT = 53
    TIMEOUT = 0.5
    BUF_SIZE = 512

    def __init__(self, address, forwarder):
        self.port = port
        self.address = address
        self.forwarder = forwarder
        self.cache = DnsCache()
        self.pool = Pool()
        self.lock = Lock()
        self.server = None
        self.processed_requests = set()

    def launch(self):
        stdout.write('Server is running\r\n')
        with sock.socket(sock.AF_INET, sock.SOCK_DGRAM) as conn:
            conn.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
            conn.bind(self.address)
            self.server = conn
            while True:
                read, _, _ = select([self.server], [], [], self.TIMEOUT)
                if read:
                    data, addr = self.server.recvfrom(self.BUF_SIZE)
                    self.pool.apply_async(self.handle_client,
                                          args=[data, addr])

    def handle_client(self, b_request, client_addr):
        try:
            answers = []
            failed_responses = []
            client_ip, _ = client_addr
            request = Packet.from_bytes(b_request)

            with self.lock:
                if b_request in self.processed_requests:
                    response = get_empty_response(request.id)
                    self._send_response(response, client_addr, b_request)
                    return
                self.processed_requests.add(b_request)

            for question in request.questions:
                with self.lock:
                    c_answers = self.cache.get_record(question)
                if c_answers:
                    self._add_answers(answers, c_answers, client_ip,
                                      question, 'cache')
                else:
                    f_response = self.ask_forwarder(question, request.id)
                    if f_response:
                        if f_response.rcode == RCode.NO_ERROR:
                            f_answers = f_response.answers
                            self._add_answers(answers, f_answers, client_ip,
                                              question, 'forwarder')
                            with self.lock:
                                self.cache.insert_records(question, f_answers)
                        else:
                            failed_responses.append(f_response)

            response = get_empty_response(request.id)
            response.answers = answers

            if len(answers) == 0 and len(failed_responses) > 0:
                response = failed_responses[0]

            with self.lock:
                self._send_response(response, client_addr, b_request)
        except Exception as e:
            stdout.write(str(e) + '\r\n')

    def ask_forwarder(self, question, request_id):
        response = None
        request = Packet.form_request(question.domain, id=request_id,
                                      dns_type=question.dns_type)

        with sock.socket(sock.AF_INET, sock.SOCK_DGRAM) as asker:
            asker.sendto(request.to_bytes(), self.forwarder)
            read, _, _ = select([asker], [], [], self.TIMEOUT)
            if read:
                binary_response, _ = asker.recvfrom(self.BUF_SIZE)
                response = Packet.from_bytes(binary_response)

        return response

    @staticmethod
    def request_info(ip, dns_type, domain, source):
        return '%s, %s, %s, %s\r\n' % (ip, dns_type, domain, source)

    def _send_response(self, response, addr, b_request):
        if b_request in self.processed_requests:
            self.processed_requests.remove(b_request)
        self.server.sendto(response.to_bytes(), addr)

    def _add_answers(self, all_answers, answers, client_ip, question, source):
        all_answers.extend(answers)
        stdout.write(
            self.request_info(
                client_ip, question.dns_type.name, question.domain, source))


def get_empty_response(id):
    return Packet(id, MessageType.RESPONSE, 0, 0, 0, 0, 0,
                  RCode.NO_ERROR, [], [], [], [])


def parse_args():
    parser = ArgumentParser(description='Dns server with cache')

    parser.add_argument('-p', '--port',
                        type=int, default=53,
                        help='Dns server udp port')

    parser.add_argument('-f', '--forwarder',
                        type=str, required=True,
                        help='Dns forwarder address (ip[:port])')

    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_args()
        port = args.port
        forwarder = None
        server_address = '0.0.0.0', port

        if args.forwarder:
            if ':' in args.forwarder:
                f_ip, f_port = args.forwarder.split(':')
            else:
                f_ip, f_port = args.forwarder, DnsServer.PORT
            IPv4Address(f_ip)
            forwarder = f_ip, f_port

        server = DnsServer(server_address, forwarder)
        server.launch()
    except KeyboardInterrupt:
        exit(1)
    except Exception as e:
        stdout.write(str(e) + '\r\n')
