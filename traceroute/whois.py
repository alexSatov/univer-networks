import re
import socket
from select import select
from functools import lru_cache

WHOIS_PORT = 43
BUFFER_SIZE = 4 * 1024
IANA = "whois.iana.org"
SOCKET_CONNECT_TIMEOUT = 2
SOCKET_POLLING_PERIOD = 0.5

# STATUS_EXPR = re.compile(r'status:\s*(\w+)\n?')
COUNTRY_EXPR = re.compile(r'[cC]ountry:\s*(\w+)\n')
REFER_EXPR = re.compile(r'refer:\s*(\w+\.\w+\.\w+)\n')
NETNAME_EXPR = re.compile(r'[nN]et[nN]ame:\s*([\w-]+)\n')
AS_EXPR = re.compile(r'([oO]riginA?S?|aut-num):\s*.*?(\d[\d-]*).*\n')


def get_whois_address(ip):
    iana_response = receive_information(IANA, ip)
    match = re.search(REFER_EXPR, iana_response)
    if match:
        return match.group(1)


def recv_all(sock):
    result = b''
    while select([sock], [], [], SOCKET_POLLING_PERIOD)[0]:
        data = sock.recv(BUFFER_SIZE)
        if len(data) == 0:
            break
        result += data
    return result


def get_local_machine_ip():
    return socket.gethostbyname(socket.gethostname())


def receive_information(address, ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(SOCKET_CONNECT_TIMEOUT)
        sock.connect((address, WHOIS_PORT))
        sock.setblocking(0)
        result = recv_all(sock).decode('utf-8')
        sock.sendall((ip + "\r\n").encode('utf-8'))
        result += recv_all(sock).decode('utf-8')
    return result


@lru_cache()
def get_ip_info(ip):
    try:
        whois_address = get_whois_address(ip)

        if not whois_address:
            return "local"

        response = receive_information(whois_address, ip)

        match_netname = re.search(NETNAME_EXPR, response)
        match_as = re.search(AS_EXPR, response)
        match_country = re.search(COUNTRY_EXPR, response)

        info = ''
        info += '%s, ' % match_netname.group(1) if match_netname else ''
        info += '%s, ' % match_as.group(2) if match_as else ''
        info += match_country.group(1) if match_country else ''
        return info
    except Exception as e:
        print(e)
        return ''

# if __name__ == '__main__':
#     print(get_ip_info(''))
