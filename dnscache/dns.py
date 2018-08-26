import re
import random
from enum import IntEnum
from itertools import chain
from struct import pack, unpack


class Class(IntEnum):
    IN = 1
    ANY = 255


class Opcode(IntEnum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class MessageType(IntEnum):
    REQUEST = 0
    RESPONSE = 1


class Type(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    AAAA = 28
    ANY = 255


class RCode(IntEnum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NON_IMPLEMENTED = 4
    REFUSED = 5


class QEntry:
    FORMAT = '>HH'

    def __init__(self, domain, dns_type, dns_class):
        self.domain = domain
        self.dns_type = Type(dns_type)
        self.dns_class = Class(dns_class)

    @classmethod
    def from_bytes(cls, data, offset):
        domain, offset = domain_from_bytes(data, offset)
        dns_type, dns_class = unpack(QEntry.FORMAT, data[offset:offset + 4])
        return QEntry(domain, dns_type, dns_class), offset + 4

    def to_bytes(self):
        domain = domain_to_bytes(self.domain)
        header = pack(QEntry.FORMAT, self.dns_type, self.dns_class)
        return domain + header

    def __hash__(self):
        return hash((self.domain, self.dns_type, self.dns_class))

    def __eq__(self, other):
        return isinstance(other, QEntry) and \
               (self.domain, self.dns_type, self.dns_class) == \
               (other.domain, other.dns_type, other.dns_class)


class RRecord:
    FORMAT = '>HHIH'

    def __init__(self, domain, dns_type, dns_class, ttl, rdata):
        self.domain = domain
        self.dns_type = Type(dns_type)
        self.dns_class = Class(dns_class)
        self.ttl = ttl
        self.rdata = rdata

    @classmethod
    def from_bytes(cls, data, offset):
        domain, offset = domain_from_bytes(data, offset)
        dns_type, dns_class, ttl, rdlen = unpack(RRecord.FORMAT,
                                                 data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        return RRecord(domain, dns_type, dns_class, ttl, rdata), offset + rdlen

    def to_bytes(self):
        domain = domain_to_bytes(self.domain)
        header = pack(RRecord.FORMAT, self.dns_type, self.dns_class,
                      self.ttl, len(self.rdata))
        return domain + header + self.rdata


class Packet:
    FORMAT = '>HHHHHH'

    def __init__(self, id, qr, opcode, aa, tc, rd, ra,
                 rcode, questions, answers, authority, additional):
        self.id = id
        self.qr = MessageType(qr)
        self.opcode = Opcode(opcode)
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = RCode(rcode)
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional

    @classmethod
    def form_request(cls, target, id=None, recursion=True,
                     dns_type=None, cl=Class.IN):
        id = random.randint(0, 1 << 16) if id is None else id
        default_type, domain = get_domain_name(target)
        question = QEntry(domain, dns_type if dns_type else default_type, cl)
        return Packet(id, MessageType.REQUEST, Opcode.QUERY, 0, 0,
                      1 if recursion else 0,
                      1 if recursion else 0,
                      RCode.NO_ERROR,
                      [question], [], [], [])

    @classmethod
    def from_bytes(cls, data):
        id, options, q_count, answers_count, \
            auth_count, add_count = unpack(Packet.FORMAT, data[:12])

        qr = options >> 15
        opcode = (options >> 11) & 0xF
        aa = options >> 10 & 0x1
        tc = options >> 9 & 0x1
        rd = options >> 8 & 0x1
        ra = options >> 7 & 0x1
        rcode = options & 0xF

        questions = []
        answers = []
        authority = []
        additional = []
        if rcode == RCode.NO_ERROR:
            offset = 12
            questions, offset = list_from_bytes(QEntry, data, offset, q_count)
            answers, offset = r_records_from_bytes(data, offset, answers_count)

        return Packet(id, qr, opcode, aa, tc, rd, ra, rcode,
                      questions, answers, authority, additional)

    def to_bytes(self):
        options = self.qr << 15 | self.opcode << 11 | self.aa << 10 \
                  | self.tc << 9 | self.rd << 8 | self.ra << 7 | self.rcode

        header = pack(Packet.FORMAT, self.id, options, len(self.questions),
                      len(self.answers), len(self.authority),
                      len(self.additional))
        content = chain(self.questions, self.answers,
                        self.authority, self.additional)

        return header + b''.join(map(lambda x: x.to_bytes(), content))


def list_from_bytes(cls, data, offset, count):
    result = []
    for i in range(count):
        rr, offset = cls.from_bytes(data, offset)
        result.append(rr)
    return result, offset


def r_records_from_bytes(data, offset, count):
    return list_from_bytes(RRecord, data, offset, count)


def domain_from_bytes(data, offset):
    domain = ''
    offset_to_return = offset
    shortened = False
    while True:
        length = data[offset]
        offset += 1

        if length & 0xC0 == 0xC0:
            if not shortened:
                offset_to_return = offset + 1
            offset = ((length & (~0xC0)) << 8) + data[offset]
            shortened = True
        elif length & 0xC0 == 0 and length > 0:
            domain += data[offset: offset + length].decode('utf-8') + '.'
            offset += length
        else:
            return domain, offset_to_return if shortened else offset


def domain_to_bytes(domain):
    return b''.join(
        map(lambda label: pack(">B", len(label)) + label.encode('utf-8'),
            domain.split('.')))


def get_domain_name(target):
    if re.match(r'\d+\.\d+\.\d+\.\d+', target):
        return Type.PTR, '.'.join(reversed(target.split('.'))) + \
               ".IN-ADDR.ARPA."
    return Type.A, target if target[-1] == '.' else target + '.'
