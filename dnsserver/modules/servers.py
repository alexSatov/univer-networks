# coding=utf-8
import logging
import struct
from ipaddress import IPv4Address
from typing import Tuple, Callable, Set, List, Iterable, Optional, AsyncIterable
import asyncio as aio

from modules.db import DnsDb
from modules.packet import Packet, Question, ResourceRecord, Opcode, Errcode, Type


class Server(aio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self._received_callbacks: Set[Callable] = set()

    def connection_made(self, transport: aio.DatagramTransport) -> None:
        logging.debug('Connection made')
        self.transport = transport

    def datagram_received(self, data: bytes, address: Tuple[str, int]) -> None:
        logging.debug(f'Received message from {address}')
        for callback in self._received_callbacks:
            callback(data, *address)

    def register_callback(self, received_callback: Callable):
        self._received_callbacks.add(received_callback)


async def _read_tcp_packet(reader: aio.StreamReader) -> bytes:
    length = await reader.readexactly(2)
    length = struct.unpack('>H', length)[0]
    return await reader.readexactly(length)


def _write_tcp_packet(packet: Packet, writer: aio.StreamWriter) -> None:
    packet = packet.to_bytes()
    writer.write(struct.pack('>H', len(packet)) + packet)
    writer.drain()


class Responder:
    _TCP_TIME_LIMIT = 60 * 5  # 5 mins
    _UDP_SIZE_LIMIT = 512

    def __init__(self, udp_server: Server, db: DnsDb):
        self._udp_server = udp_server
        self._db = db
        self._futures: Set[aio.Future] = set()
        self._server_requests = aio.Queue()
        udp_server.register_callback(self._udp_received)

    def _get_reply(self, data: bytes) -> Packet:
        try:
            packet = Packet.from_bytes(data)
            if not len(packet.questions) or packet.opcode != Opcode.QUERY \
                    or not packet.is_ok or not packet.is_query:
                raise Exception()
        except Exception:
            reply = Packet(errcode=Errcode.FORMAT)
        else:
            transfer = ZoneTransfer.get_response(packet, self._db)
            if transfer:
                return transfer
            answers = self._ask_db(packet.questions)
            additional = self._get_additional(answers)
            reply = Packet(packet.id, questions=packet.questions, answers=answers,
                           additional=additional, is_authoritative=True, recursion_avail=False)
            if not len(answers):
                reply.error_code = Errcode.NAME
        return reply

    def _get_additional(self, answers: Iterable[ResourceRecord]) -> List[ResourceRecord]:
        answers = set(answers)
        names = list(filter(lambda a: a.type in (Type.PTR, Type.NS, Type.CNAME), answers))
        additional = []
        for type in (Type.A, Type.AAAA):
            for name in names:
                additional.extend(filter(lambda x: x not in answers, self._db.select(name.rdata.name, type)))
        return additional

    def _udp_received(self, data: bytes, address: str, port: int) -> None:
        reply = self._get_reply(data)
        self._udp_server.transport.sendto(reply.to_bytes(limit=self._UDP_SIZE_LIMIT), (address, port))

    async def tcp_received(self, reader: aio.StreamReader, writer: aio.StreamWriter) -> None:
        logging.debug(f'Tcp connected {writer.get_extra_info("peername")}')
        try:
            await aio.wait_for(self._tcp_received(reader, writer), timeout=self._TCP_TIME_LIMIT)
        except Exception:
            pass
        finally:
            writer.write_eof()
            writer.close()
            logging.debug('Done TCP')

    async def _tcp_received(self, reader: aio.StreamReader, writer: aio.StreamWriter) -> None:
        while True:
            data = await _read_tcp_packet(reader)
            reply = self._get_reply(data)
            logging.debug('Writing on TCP')
            _write_tcp_packet(reply, writer)

    def _ask_db(self, questions: Iterable[Question]) -> List[ResourceRecord]:
        answers = []
        for question in questions:
            if question.type == Type.ANY:
                for type in Type:
                    answers.extend(self._db.select(question.name, type))
            else:
                answers.extend(self._db.select_question(question))
        return answers


class ZoneTransfer:
    @staticmethod
    def get_response(query: Packet, db: DnsDb) -> Optional[Packet]:
        if query.questions_count != 1:
            return None
        question = query.questions[0]
        if question.type != Type.AXFR:
            return None
        logging.debug('Preparing AXFR answer')
        zone = question.name
        soa = list(db.select(zone, Type.SOA))
        records = filter(lambda r: r.type != Type.SOA, db.select_all())
        answers = soa + list(records) + soa
        logging.debug(f'Found {len(answers)} records for AXFR transfer')
        response = Packet(id=query.id, questions=[question],
                          is_authoritative=True, answers=answers)
        return response

    @classmethod
    async def make_request(cls, zone: str, server_address: IPv4Address,
                           port: int, serial: int = None) -> AsyncIterable[ResourceRecord]:
        try:
            reader: aio.StreamReader = None
            writer: aio.StreamWriter = None
            reader, writer = await aio.open_connection(host=str(server_address), port=port)

            if serial:
                if not await cls._check_serial(zone, serial, reader, writer):
                    raise ValueError('Serial numbers are same, no need to transfer zone')
                logging.debug('AXFR checked serial')

            question = Question(zone, Type.AXFR)
            request = Packet(is_response=False, questions=[question])
            _write_tcp_packet(request, writer)
            async for record in cls._stream_answers(zone, reader):
                yield record
        finally:
            if writer:
                writer.close()

    @staticmethod
    async def _stream_answers(zone: str, reader: aio.StreamReader) -> AsyncIterable[ResourceRecord]:
        soa = None
        while True:
            packet = Packet.from_bytes(await _read_tcp_packet(reader))
            if not packet.is_ok:
                raise ValueError(f'Server indicates that there is an error: {packet.error_code}')
            if not soa:
                if packet.questions_count != 1 or packet.questions[0].type != Type.AXFR \
                        or packet.answers_count < 1 or packet.answers[0].type != Type.SOA:
                    raise ValueError('AXFR process was interrupted due to wrong response')
                soa = packet.answers.pop(0)
                if soa.name != zone:
                    raise ValueError(f'Server returned SOA record for wrong zone {soa.rdata.mname}')
                logging.debug('Received SOA during AXFR')
                yield soa
            for record in packet.answers:
                if record.type == Type.SOA:
                    if record.name != zone:
                        raise ValueError('Received another SOA record during transfer with wrong mname: '
                                         f'{record.name} and terminated process')
                    return
                yield record

    @staticmethod
    async def _check_serial(zone: str, serial: int, reader: aio.StreamReader, writer: aio.StreamWriter) -> bool:
        question = Question(zone, Type.SOA)
        request = Packet(is_response=False, questions=[question])
        _write_tcp_packet(request, writer)
        response = Packet.from_bytes(await _read_tcp_packet(reader))
        answer = response.answers[0]
        if answer.type != Type.SOA:
            raise ValueError('Wrong response type')
        return answer.name == zone and answer.rdata.serial != serial
