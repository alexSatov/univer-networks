# coding=utf-8
import sys
from collections import namedtuple
from ipaddress import IPv4Address, AddressValueError

__REQ_PYTHON = 3, 6, 0
if sys.version_info < __REQ_PYTHON:
    print(f'Use python >= {__REQ_PYTHON}', file=sys.stderr)
    sys.exit(1)

import argparse
import logging
import asyncio as aio
from typing import Tuple, Type, Iterable, AsyncIterable
from modules.servers import Server, Responder, ZoneTransfer
from modules.db import DnsDb
from modules.parser import DnsParseError, parse_file
from modules.packet import ResourceRecord

_SELF_PORT = 53


def _get_udp_server(loop: aio.AbstractEventLoop, protocol_factory: Type[aio.Protocol], **params) -> \
        Tuple[aio.DatagramTransport, Server]:
    listener = loop.create_datagram_endpoint(protocol_factory, **params)
    return loop.run_until_complete(listener)


def _get_tcp_server(loop: aio.AbstractEventLoop, responder: Responder, local_addr: str, port: int) -> aio.AbstractServer:
    task = aio.start_server(responder.tcp_received, host=local_addr, port=port)
    return loop.run_until_complete(task)


def run_server(args, local_addr: str, self_port: int = _SELF_PORT,
               async_loop: aio.AbstractEventLoop = aio.get_event_loop()) -> None:
    protocol_factory = Server
    try:
        db = DnsDb()
        transport, udp_server = _get_udp_server(async_loop, protocol_factory, local_addr=(local_addr, self_port))
        async_loop.run_until_complete(_server_init(db, args))
        responder = Responder(udp_server, db)
        tcp_server: aio.AbstractServer = _get_tcp_server(async_loop, responder, local_addr, self_port)
        async_loop.run_forever()
    except KeyboardInterrupt:
        raise
    finally:
        async_loop.close()


async def _server_init(db: DnsDb, args):
    if args.axfr:
        try:
            zone, address, port, serial = args.axfr
            address = IPv4Address(address)
            port = int(port)
            serial = int(serial)
        except AddressValueError as e:
            raise ValueError('Incorrect IP in AXFR parameters') from e
        except ValueError as e:
            raise ValueError('Incorrect port or serial value in AXFR parameters, must be int')
        records = [record async for record in _transfer_zone(zone, address, port, serial)]
    else:
        records = _read_from_file(args.file, args.fqdn)
    num_read = _fill_db(db, records)
    print(f'Filled database with {num_read} entries')
    print('Server started')


def _read_from_file(path: str, fqdn: str) -> Iterable[ResourceRecord]:
    try:
        yield from parse_file(path, fqdn)
    except DnsParseError as e:
        print(f'Error when parsing file.\n{e}')
        raise
    except Exception as e:
        print(f'Unknown error when parsing file\n{e}')
        raise


async def _transfer_zone(zone: str, address: IPv4Address, port: int, serial: int) -> AsyncIterable[ResourceRecord]:
    try:
        async for record in ZoneTransfer.make_request(zone, address, port, serial):
            yield record
    except Exception as e:
        print(f'Zone transfer was interrupted with error:\n{e}')
        raise


def _fill_db(db: DnsDb, records: Iterable[ResourceRecord]) -> int:
    count = 0
    for record in records:
        db.insert(record, commit=False)
        count += 1
    db.connection.commit()
    return count


def _get_args():
    argparser = argparse.ArgumentParser(
        description='DNS server')
    argparser.add_argument('fqdn', type=str, help='Zone name')
    argparser.add_argument('-p', '--port', default=_SELF_PORT, type=int,
                           help='Port that server is listening to')
    argparser.add_argument('-f', '--file', type=str,
                           help='Path to zone file')
    argparser.add_argument('-a', '--address', type=int, help='Last octet in local IP', default=1)
    argparser.add_argument('--axfr', nargs=4, help='Make AXFR request to another server.\n'
                                                   'Format: {zone} {source ip} {source port} {serial}')
    values = argparser.parse_args()
    args = namedtuple('args', ('fqdn', 'port', 'file', 'axfr', 'address'))
    args.port, args.fqdn, args.axfr, args.address = values.port, values.fqdn, values.axfr, values.address
    if not 1 <= args.address < 255:
        print(f'Address must be within 1 and 254, not {args.address}')
        sys.exit(1)
    args.address = f'127.0.0.{args.address}'
    if not args.fqdn.endswith('.'):
        args.fqdn += '.'
    args.file = values.file if values.file else args.fqdn + 'dns'
    return args


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG)
    args = _get_args()
    try:
        run_server(args, args.address, args.port)
    except (OSError, PermissionError):
        print(f'Not enough rights or port {_SELF_PORT} is already occupied')
    except Exception:
        print('Server was shut down with error')
