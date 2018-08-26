import re
import icmp
import select
import argparse
import socket as sc
from whois import get_ip_info
from ipaddress import IPv4Address

TIMEOUT = 3
MAX_HOPS = 30
IP_EXPR = re.compile('(\d+\.\d+\.\d+\.\d+)')
PROTOCOL = sc.getprotobyname(icmp.PROTOCOL_NAME)


def trace_ip(dest_ip):
    for ttl in range(1, MAX_HOPS + 1):
        icmp_sock = form_icmp_socket(ttl)
        icmp_packet = icmp.get_icmp_request_packet().to_binary()

        icmp_sock.sendto(icmp_packet, (dest_ip, 1))
        ip = try_get_reply(icmp_sock)
        icmp_sock.close()

        yield ip or '*'

        if ip == dest_ip:
            break


def try_get_reply(sock):
    reading_sock, _, _ = select.select([sock], [], [], TIMEOUT)

    if len(reading_sock) == 0:
        return None

    icmp_message, addr = sock.recvfrom(1024)
    icmp_header = icmp_message[20:28]
    packet = icmp.Packet.from_binary(icmp_header)
    ip, _ = addr

    if packet.is_ttl_exceeded or packet.is_reply:
        return ip


def form_icmp_socket(ttl):
    sock = sc.socket(sc.AF_INET, sc.SOCK_RAW, PROTOCOL)
    sock.setsockopt(sc.SOL_IP, sc.IP_TTL, ttl)
    return sock


def parse_args():
    parser = argparse.ArgumentParser(description='Traceroute')

    parser.add_argument('address',
                        type=str,
                        help='IP-address or DNS-name')

    parser.add_argument('--hops',
                        type=int,
                        default=30,
                        help='Max count of hops')

    return parser.parse_args()

if __name__ == '__main__':
    addr = ''
    try:
        args = parse_args()
        addr, MAX_HOPS = args.address, args.hops
        dest_ip = str(IPv4Address(addr)) if re.search(IP_EXPR, addr) else \
            sc.gethostbyname(addr)

        n = 1
        for ip in trace_ip(dest_ip):
            if ip != '*':
                report = '%i. %s\r\n' \
                         '%s\r\n' % (n, ip, get_ip_info(ip))
            else:
                report = '%i. *\r\n' % n
                if n == MAX_HOPS + 1:
                    raise Exception('Unreachable address %s' % dest_ip)
            print(report)
            n += 1
    except Exception as e:
        if e.args[0] == 11001:
            print('%s is invalid' % addr)
        else:
            print(e)
