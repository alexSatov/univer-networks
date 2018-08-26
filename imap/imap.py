import re
import socket as sock
from select import select
from getpass import getpass
from ssl import wrap_socket
from letterinfo import LetterInfo
from argparse import ArgumentParser, ArgumentTypeError


class ImapClient:
    PORT = 143
    TIMEOUT = 0.6
    BUF_SIZE = 1024
    SSL_PORT = 993

    def __init__(self, address, user, ssl):
        self.address = address
        self.user = user
        self.ssl = ssl
        self.tag = 'A100'
        self.client = None
        self.separator = ''
        self.extensions = {}

    def get_inbox_mail_info(self, n1, n2):
        self.client = sock.create_connection(self.address, self.TIMEOUT*3)
        with self.client:
            self.start_session()

            self.send_message('SELECT inbox\r\n')
            response = self.recv_response()
            self._check_for_correctness(response, 'SELECT error')
            l_count = int(re.search(r'\* (\d+) EXISTS', response).group(1))

            if n1 > l_count or n1 < 0:
                msg = 'Incorrect letters start index: %i (max %i)' % \
                      (n1, l_count)
                raise AttributeError(msg)
            if n2 > l_count or n2 < n1:
                n2 = l_count

            for i in range(n1, n2+1):
                try:
                    letter_info = self.get_letter_info(i)
                    if letter_info:
                        yield letter_info
                except sock.error as sock_err:
                    print(sock_err)

    def start_session(self):
        if self.ssl:
            if self.address[1] != self.SSL_PORT:
                self.send_message('STARTTLS\r\n')
                self._check_for_correctness(self.recv_response(),
                                            'STARTTLS error')
            self.client = wrap_socket(self.client)
        self._authenticate()

    def get_letter_info(self, index):
        msg = 'FETCH %i (RFC822.SIZE BODY[HEADER.FIELDS ' \
              '(from to subject date)])\r\n' % index

        self.send_message(msg)
        fetch = self.recv_response()

        try:
            self._check_for_correctness(fetch, 'FETCH error')
        except ValueError:
            print('Bad fetch №%i: %s\r\n' % (index, fetch))
            return

        self.send_message('FETCH %i BODYSTRUCTURE\r\n' % index)
        bodystructure = self.recv_response()
        letter_info = LetterInfo.letter_info_from_fetch(fetch, index)
        letter_info.update_with_bodystructure(bodystructure)
        return letter_info

    def send_message(self, message):
        if self.ready_to_write():
            self.tag = 'A%i' % (int(self.tag[1:])+1)
            self.client.sendall(('%s %s' % (self.tag, message)).encode())
        else:
            raise TimeoutError("Client can't send message")

    def recv_response(self):
        response = ''

        while self.ready_to_read():
            b_resp = self.client.recv(self.BUF_SIZE)
            if not b_resp:
                break
            response += b_resp.decode()

        return response

    def ready_to_read(self):
        return len(select([self.client], [], [], self.TIMEOUT)[0]) != 0

    def ready_to_write(self):
        return len(select([], [self.client], [], self.TIMEOUT)[1]) != 0

    def _authenticate(self):
        password = getpass()
        self.send_message('LOGIN %s %s\r\n' % (self.user, password))
        self._check_for_correctness(self.recv_response(),
                                    'Authentication error')

    def _check_for_correctness(self, response, error=''):
        scs_code = '%s OK' % self.tag
        if re.search(scs_code, response):
            return
        raise ValueError('Bad response: %s\r\n%s' % (''.join(response), error))


def get_ip():
    return sock.gethostbyname(sock.gethostname())


def check_range(range):
    if len(range) == 2:
        n1, n2 = range
        if n1 >= n2 or n1 < 1:
            raise ArgumentTypeError('Incorrect range: %i, %i' % (n1, n2))
        return [n1, n2]
    return range[0]


def print_inbox_mail_info(letters_info):

    for l_info in letters_info:
        str_info = '№{number}.\r\n' \
                   'To: {to}\r\n' \
                   'From: {from_}\r\n' \
                   'Subject: {subject}\r\n' \
                   'Date: {date}\r\n' \
                   'Size: {size}\r\n'.format(**l_info.__dict__)

        if l_info.attachments_count != 0:
            str_info += 'Attachments count: {attachments_count}\r\n' \
                        'Files: {files}\r\n'.format(**l_info.__dict__)
        print(str_info)


def parse_args():
    parser = ArgumentParser('IMAP-client')

    parser.add_argument('--ssl', action='store_true',
                        help='Use ssl if server supports')

    parser.add_argument('-s', '--server', type=str, required=True,
                        help='IMAP-server address (domain|ip[:port])')

    parser.add_argument('-n', nargs=2, dest='l_range', type=int,
                        help='Letters range')

    parser.add_argument('-u', '--user', type=str, required=True,
                        help='User name')

    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_args()

        if args.l_range:
            check_range(args.l_range)
            l_range = args.l_range
        else:
            l_range = [1, -1]

        if ':' in args.server:
            host, port = args.server.split(':')
        else:
            host, port = args.server, ImapClient.PORT
        addr = sock.gethostbyaddr(host)[0], int(port)

        client = ImapClient(addr, args.user, args.ssl)
        print_inbox_mail_info(client.get_inbox_mail_info(*l_range))
    except Exception as e:
        print(e)
    except KeyboardInterrupt:
        exit(1)
