import ssl
import b64
import socket as sock
from select import select
from random import randint
from getpass import getpass
from argparse import ArgumentParser
from string import ascii_letters, digits
from image import get_images_list, get_binary_image


def get_ip():
    return sock.gethostbyname(sock.gethostname())


class SmtpClient:
    PORT = 25
    TIMEOUT = 0.5
    BUF_SIZE = 512
    SSL_PORT = 465

    def __init__(self, address, sender, subject, auth, verbose, ssl):
        self.sender = sender
        self.address = address
        self.subject = subject
        self.verbose = verbose
        self.auth = auth
        self.ssl = ssl
        self.client = None
        self.extensions = {}
        self.boundary = ''

    def send_images(self, images, recipient):
        letter = self.form_letter(recipient, images)
        self.client = sock.create_connection(self.address, self.TIMEOUT*3)
        with self.client:
            self.start_session()
            self.send_from_to_commands(recipient)
            self.send_command(b'DATA\r\n', 'DATA error', '354')
            self.send_data(letter, False)
            self.send_command(b'.\r\n', 'Error while letter sending')
            self.send_command(b'QUIT\r\n', 'Error while quiting', '221')

    def start_session(self):
        if self.ssl and self.address[1] == self.SSL_PORT:
            self.client = ssl.wrap_socket(self.client)
            self.ssl = False
        server_greeting = self.recv_response()
        self._send_greeting_command()
        response = self.recv_response()
        if self.is_successful(response, '250'):
            self._save_extensions(response)
            if self.ssl:
                self.send_command(b'STARTTLS\r\n', 'STARTTLS error', '220')
                self.client = ssl.wrap_socket(self.client)
                self._send_greeting_command()
        else:
            command = b'HELO ' + get_ip().encode() + b'\r\n'
            error = 'Error while client greeting'
            self.send_command(command, error)

    def send_from_to_commands(self, recipient):
        if self.auth:
            self._authenticate()

        _from = b'MAIL FROM: <' + self.sender.encode() + b'>\r\n'
        to = b'RCPT TO: <' + recipient.encode() + b'>\r\n'
        error = 'Error while sending sender and recipient addresses'

        if 'PIPELINING' in self.extensions:
            self.send_command(_from + to, error)
        else:
            self.send_command(_from, error)
            self.send_command(to, error)

    def form_letter(self, recipient, images):
        letter = self.form_letter_header(recipient)
        for image in images:
            letter += self.format_image(image)
        letter += b'--' + self.boundary.encode() + b'\r\n'

        if 'SIZE' in self.extensions:
            max_size = int(self.extensions['SIZE'])
            letter_size = len(letter)
            if letter_size > max_size:
                raise AttributeError('Letter size (%s) exceeds max size (%s)'
                                     % (letter_size, max_size))

        return letter

    def send_command(self, command, err_msg, scs_code='250', dec_resp=False):
        self.send_data(command)
        resp = self.recv_response(dec_resp)
        if not self.is_successful(resp, scs_code):
            raise ValueError('%s: "%s"' % (err_msg, resp.strip()))

    def send_data(self, data, to_print=True):
        if self.ready_to_write():
            if self.verbose and to_print:
                print('C: ' + data.decode())
            self.client.sendall(data)
        else:
            raise TimeoutError("Client can't send message")

    def recv_response(self, dec_resp=False):
        response = ''
        while self.ready_to_read():
            b_response = self.client.recv(self.BUF_SIZE)

            if not b_response:
                break

            if dec_resp and b_response[:3] == b'334':
                response += b_response[:4].decode() + \
                           b64.decode(b_response[4:-2]).decode()
            else:
                response += b_response.decode()

            if self.verbose:
                print('S: ' + response)
        return response

    def ready_to_read(self):
        return len(select([self.client], [], [], self.TIMEOUT)[0]) != 0

    def ready_to_write(self):
        return len(select([], [self.client], [], self.TIMEOUT)[1]) != 0

    def form_letter_header(self, recipient):
        symbols = ascii_letters + digits
        self.boundary = ''
        for i in range(30):
            self.boundary += symbols[randint(0, len(symbols)-1)]
        self.boundary += '.alexsatov'

        return b'From: <' + self.sender.encode() + b'>\r\n' + \
               b'To: <' + recipient.encode() + b'>\r\n' + \
               b'Subject: ' + self.subject.encode() + b'\r\n' + \
               b'MIME-Version: 1.0\r\n' + \
               b'Content-Type: multipart/mixed;\r\n' + \
               b'\tboundary="' + self.boundary.encode() + b'"\r\n\r\n'

    def format_image(self, image):
        b_boundary = b'--' + self.boundary.encode() + b'\r\n'
        b_img_ext = image[-3:].encode()
        image_name = image[image.rfind('\\')+1:].encode()

        f_image = b_boundary + \
            b'Content-Disposition: attachment;\r\n' + \
            b'\tfilename="' + image_name + b'"\r\n' + \
            b'Content-Transfer-Encoding: base64\r\n' + \
            b'Content-Type: image/' + b_img_ext + b';\r\n' + \
            b'\tname="' + image_name + b'"\r\n\r\n'

        img_data = get_binary_image(image)
        img_base64_data = b64.encode(img_data)

        n = len(img_base64_data) // 76
        for i in range(n+1):
            f_image += img_base64_data[i*76:(i+1)*76] + b'\r\n'

        return f_image

    @staticmethod
    def is_successful(response, success_code):
        return success_code in response

    def _send_greeting_command(self):
        self.send_data(b'EHLO ' + get_ip().encode() + b'\r\n')

    def _save_extensions(self, response):
        lines = list(filter(lambda l: l != '', response.split('\r\n')))
        for ext_line in lines[1:]:
            ext = ext_line[4:]
            sep_pos = ext.find(' ')

            if sep_pos != -1:
                command, params = ext[:sep_pos], ext[sep_pos + 1:]
            else:
                command, params = ext, ''

            self.extensions[command] = params

    def _authenticate(self):
        error = 'Authentication error'
        login = b64.encode(self.sender.encode()) + b'\r\n'

        self.send_command(b'AUTH LOGIN\r\n', error, '334', True)
        self.send_command(login, error, '334', True)
        password = b64.encode(getpass().encode()) + b'\r\n'
        self.send_command(password, error, '235')


def parse_args():
    parser = ArgumentParser('smtp-mime')

    parser.add_argument('--ssl', action='store_true',
                        help='Use ssl if server supports')

    parser.add_argument('-s', '--server', type=str, required=True,
                        help='SMTP-Server address (domain|ip[:port])')

    parser.add_argument('-t', '--to', type=str, dest='recipient',
                        help='Postal address of the recipient', required=True)

    parser.add_argument('-f', '--from', type=str, default='', dest='sender',
                        help='Postal address of the sender')

    parser.add_argument('--subject', type=str, default='Happy Pictures',
                        help='Letter subject')

    parser.add_argument('--auth', action='store_true',
                        help='Authorization request')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display protocol job except letter text')

    parser.add_argument('-d', '--directory', type=str, default='$pwd',
                        help='Directory with images')

    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_args()

        if ':' in args.server:
            host, port = args.server.split(':')
        else:
            host, port = args.server, SmtpClient.PORT
        addr = sock.gethostbyaddr(host)[0], int(port)

        client = SmtpClient(addr, args.sender, args.subject,
                            args.auth, args.verbose, args.ssl)

        images = get_images_list(args.directory)
        client.send_images(images, args.recipient)
    except Exception as e:
        print(e)
    except KeyboardInterrupt:
        exit(1)
