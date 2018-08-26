import argparse
import socket as sc
from select import select
from multiprocessing.dummy import Pool
from proto import tcp_queries, udp_queries, is_valid_reply

TIMEOUT = 0.2
HOST = 'localhost'


def scan_ports(first, last, scans):
    pool = Pool()
    for scan in scans:
        pool.map(scan, range(first, last + 1))
    pool.close()
    pool.join()


def tcp_scan(port):
    try:
        with sc.create_connection((HOST, port), TIMEOUT) as sock:
            port_info = 'TCP %i' % port
            sock.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR, 1)
            for proto, query in tcp_queries.items():
                try:
                    sock.send(query)
                    read, _, _ = select([sock], [], [], TIMEOUT)
                    if len(read) == 0:
                        continue
                    reply = sock.recv(1024)
                    if is_valid_reply(reply, proto):
                        port_info += ' %s' % proto
                        break
                except sc.error:
                    continue
            print(port_info)
    except sc.error:
        pass


def udp_scan(port, tries=3):
    try:
        with sc.socket(sc.AF_INET, sc.SOCK_DGRAM) as sock:
            reply = None
            port_info = None
            for proto, query in udp_queries.items():
                for i in range(tries):
                    sock.sendto(query, (HOST, port))
                    read, _, _ = select([sock], [], [], TIMEOUT)
                    if len(read) != 0:
                        reply = sock.recv(1024)
                        break
                if reply:
                    port_info = 'UDP %i' % port
                    if is_valid_reply(reply, proto):
                        port_info += ' %s' % proto
                        break
                    reply = None
            if port_info:
                print(port_info)
    except sc.error:
        pass


def parse_args():
    argparser = argparse.ArgumentParser(description='TCP/UDP port scanner')

    argparser.add_argument('host',
                           type=str,
                           help='Host address')
    argparser.add_argument('-t', '--tcp',
                           action='store_true',
                           help='Scan tcp')
    argparser.add_argument('-u', '--udp',
                           action='store_true',
                           help='Scan udp')
    argparser.add_argument('-p', '--ports',
                           type=int,
                           nargs='+',
                           help='Ports range (N1 N2) [0..65535]')
    return argparser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_args()

        if len(args.ports) != 2:
            print('2 values were expected, but (%i)' % len(args.ports))
            exit(1)
        for p in args.ports:
            if p < 0 or p > 65535:
                print('Port value was excepted, but (%i)' % p)
                exit(1)

        first_port = min(args.ports)
        last_port = max(args.ports)
        HOST = args.host

        available_scans = []
        if args.udp:
            available_scans.append(udp_scan)
        if args.tcp:
            available_scans.append(tcp_scan)

        scan_ports(first_port, last_port, available_scans)
    except Exception as e:
        print(e)
    except KeyboardInterrupt:
        exit(1)
