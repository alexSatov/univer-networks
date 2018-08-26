# coding=utf-8
import random
import struct
from math import inf
from enum import Enum
from itertools import chain
from ipaddress import IPv4Address, IPv6Address
from typing import List, Tuple, Union, Optional


class Opcode(Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2
    # not described in RFC 1035
    __RESERVED = 3
    NOTIFY = 4
    UPDATE = 5


class Errcode(Enum):
    NO_ERROR = 0
    FORMAT = 1
    SERVER = 2
    NAME = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5
    # not described in RFC 1035
    YX_DOMAIN = 6
    YX_RR_SET = 7
    NX_RR_SET = 7
    NOT_AUTH = 9
    NOT_ZONE = 10


class Class(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    ANY = 255


class Type(Enum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AAAA = 28
    AXFR = 252
    ANY = 255


def _extract_domain(data: bytes, offset: int) -> Tuple[str, int]:
    """
    :return: domain, length of read data
    """
    init_offset = offset
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
            domain += data[offset: offset + length].decode() + '.'
            offset += length
        else:
            return domain, offset_to_return - init_offset if shortened else offset - init_offset


def _pack_domain(domain: str) -> bytes:
    return b''.join(map(lambda label: struct.pack('>B', len(label)) + label.encode('utf-8'), domain.split('.')))


class RData:
    _DATA_CLASSES = {}

    @classmethod
    def register_class(cls, *keys):
        return lambda value: (
            cls._DATA_CLASSES.update({key: value for key in keys})
        )

    @classmethod
    def get_data_class(cls, type: Type):
        return cls._DATA_CLASSES.get(type)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int, length: int, type: Type) -> Optional['RData']:
        data_class = cls.get_data_class(type)
        if not data_class:
            return None
        return data_class._from_bytes(data, offset, length)

    @classmethod
    def _from_bytes(cls, data: bytes, offset: int, length: int) -> 'RData':
        pass

    def to_bytes(self) -> bytes:
        pass


class _Ip(RData):
    _TYPE = None

    def __init__(self, ip: Union[IPv4Address, IPv6Address]):
        self.ip = ip

    @classmethod
    def _from_bytes(cls, data: bytes, offset: int, length: int) -> '_Ip':
        ip = cls._TYPE(data[offset:offset + length])
        return cls(ip)

    def to_bytes(self) -> bytes:
        return self.ip.packed


@RData.register_class(Type.A)
class A(_Ip):
    _TYPE = IPv4Address


@RData.register_class(Type.AAAA)
class AAAA(_Ip):
    _TYPE = IPv6Address


@RData.register_class(Type.MX)
class MX(RData):
    _FORMAT = '>H'

    def __init__(self, preference: int, name: str):
        self.preference = preference
        self.name = name

    @classmethod
    def _from_bytes(cls, data: bytes, offset: int, length: int) -> 'MX':
        preference, *_ = struct.unpack(cls._FORMAT, data[offset:offset + 2])
        name, _ = _extract_domain(data, offset + 2)
        return cls(preference, name)

    def to_bytes(self) -> bytes:
        return b''.join((
            struct.pack(self._FORMAT, self.preference),
            _pack_domain(self.name)
        ))


@RData.register_class(Type.SOA)
class Soa(RData):
    _FORMAT = '>5I'

    def __init__(self, mname: str, rname: str, serial: int, refresh: int, retry: int, expire: int, minimum: int):
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    @classmethod
    def _from_bytes(cls, data: bytes, offset: int, length: int) -> 'Soa':
        mname, mname_length = _extract_domain(data, offset)
        offset += mname_length
        rname, rname_length = _extract_domain(data, offset)
        offset += rname_length
        serial, refresh, retry, expire, minimum = struct.unpack(cls._FORMAT, data[offset:offset + 20])
        return cls(mname, rname, serial, refresh, retry, expire, minimum)

    def to_bytes(self) -> bytes:
        return b''.join((
            _pack_domain(self.mname),
            _pack_domain(self.rname),
            struct.pack(self._FORMAT, self.serial, self.refresh,
                        self.retry, self.expire, self.minimum)
        ))


@RData.register_class(Type.NS, Type.PTR, Type.CNAME)
class Name(RData):
    def __init__(self, name: str):
        self.name = name

    @classmethod
    def _from_bytes(cls, data: bytes, offset: int, length: int) -> 'Name':
        name, _ = _extract_domain(data, offset)
        return cls(name)

    def to_bytes(self) -> bytes:
        return _pack_domain(self.name)


class Question:
    _HEADER_LENGTH = 4
    _FORMAT = '>HH'

    def __init__(self, name: str, type: Type, _class: Class = Class.IN, total_length: int = 16):
        self.name = name
        self.type = type
        self._class = _class
        self.total_length = total_length

    @classmethod
    def from_bytes(cls, data: bytes, *, offset: int = 0) -> Tuple['Question', int]:
        name, name_length = _extract_domain(data, offset)
        offset += name_length
        type, _class = struct.unpack(cls._FORMAT, data[offset:offset + 4])
        return cls(name, Type(type), Class(_class)), cls._HEADER_LENGTH + name_length

    def to_bytes(self) -> bytes:
        return b''.join((
            _pack_domain(self.name),
            struct.pack(self._FORMAT, self.type.value, self._class.value)
        ))


class ResourceRecord:
    _HEADER_LENGTH = 10
    _FORMAT = '>HHIH'

    def __init__(self, name: str, type: Type, _class: Class, ttl: int, rdata: RData):
        self.name = name
        self.type = type
        self._class = _class
        self.ttl = ttl
        self.rdata = rdata

    @classmethod
    def from_bytes(cls, data: bytes, *, offset: int = 0) -> Tuple[Optional['ResourceRecord'], int]:
        name, name_length = _extract_domain(data, offset)
        offset += name_length
        type, _class, ttl, rlength = struct.unpack(cls._FORMAT, data[offset:offset + cls._HEADER_LENGTH])
        total_length = cls._HEADER_LENGTH + rlength + name_length
        try:
            type = Type(type)
        except ValueError:
            return None, total_length
        _class = Class(_class)
        rdata = RData.from_bytes(data, offset + cls._HEADER_LENGTH, rlength, type)
        if not rdata:
            return None, total_length
        return cls(name, type, _class, ttl, rdata), total_length

    def to_bytes(self) -> bytes:
        rdata = self.rdata.to_bytes()
        return b''.join((
            _pack_domain(self.name),
            struct.pack(self._FORMAT, self.type.value, self._class.value, self.ttl, len(rdata)),
            rdata
        ))

    def __hash__(self) -> int:
        return hash(self.name) ^ hash(self.type)

    def __eq__(self, other: 'ResourceRecord') -> bool:
        if not isinstance(other, ResourceRecord):
            return False
        return (self.name == other.name and self.type == other.type and self._class == other._class
                and self.rdata.__dict__ == other.rdata.__dict__)


class Packet:
    _HEADER_FORMAT = '>HHHHHH'
    _HEADER_LENGTH = 12

    def __init__(self, id: int = 0, is_response: bool = True, opcode: Opcode = Opcode.QUERY,
                 is_authoritative: bool = False, is_truncated: bool = False, recursion_desired: bool = True,
                 recursion_avail: bool = False, errcode: Errcode = Errcode.NO_ERROR,
                 questions_count=0, answers_count=0, authority_count=0, additional_count=0,
                 questions: List[Question] = None, answers: List[ResourceRecord] = None,
                 authority: List[Question] = None, additional: List[ResourceRecord] = None):
        if not id:
            id = self.generate_id()
        self.id = id
        self.is_response = is_response
        self.opcode = opcode
        self.is_authoritative = is_authoritative
        self.is_truncated = is_truncated
        self.recursion_desired = recursion_desired
        self.recursion_avail = recursion_avail
        self.error_code = errcode
        self.questions_count = questions_count or len(questions) if questions else 0
        self.answers_count = answers_count or len(answers) if answers else 0
        self.authority_count = authority_count or len(authority) if authority else 0
        self.additional_count = additional_count or len(additional) if additional else 0

        self.questions: List[Question] = questions or []
        self.answers: List[ResourceRecord] = answers or []
        self.authority: List[ResourceRecord] = authority or []
        self.additional: List[ResourceRecord] = additional or []

    @property
    def is_query(self) -> bool:
        return not self.is_response

    @property
    def is_ok(self):
        return self.error_code == Errcode.NO_ERROR

    @staticmethod
    def generate_id() -> int:
        return random.randint(0, 1 << 16)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Packet':
        id, flags, q_count, a_count, auth_count, add_count = struct.unpack(cls._HEADER_FORMAT,
                                                                           data[:cls._HEADER_LENGTH])
        is_response = flags >> 15
        opcode = (flags >> 11) & 0xF
        is_authoritative = flags >> 10 & 0x1
        is_truncated = flags >> 9 & 0x1
        recursion_desired = flags >> 8 & 0x1
        recursion_avail = flags >> 7 & 0x1
        errcode = flags & 0xF

        questions, offset = cls._get_entry(Question, q_count, data, cls._HEADER_LENGTH)
        answers, offset = cls._get_entry(ResourceRecord, a_count, data, offset)

        return cls(id, bool(is_response), Opcode(opcode), bool(is_authoritative), bool(is_truncated),
                   bool(recursion_desired), bool(recursion_avail), Errcode(errcode),
                   questions=questions, answers=answers)

    @staticmethod
    def _get_entry(entry_type: Type, count: int, data: bytes, offset: int) -> Tuple[List, int]:
        result = []
        for _ in range(count):
            entry, length = entry_type.from_bytes(data, offset=offset)
            if entry:
                result.append(entry)
            offset += length
        return result, offset

    def __to_bytes(self) -> bytes:
        flags = int(self.is_response) << 15 | self.opcode.value << 11 | int(self.is_authoritative) << 10 | \
                int(self.is_truncated) << 9 | int(self.recursion_desired) << 8 | \
                int(self.recursion_avail) << 7 | self.error_code.value
        header = struct.pack(self._HEADER_FORMAT, self.id, flags, len(self.questions), len(self.answers),
                             len(self.authority), len(self.additional))
        questions = b''.join(map(lambda q: q.to_bytes(), self.questions))
        answers = b''.join(map(lambda rr: rr.to_bytes(), self.answers))
        authority = b''.join(map(lambda rr: rr.to_bytes(), self.authority))
        additional = b''.join(map(lambda rr: rr.to_bytes(), self.additional))
        return header + questions + answers + authority + additional

    def to_bytes(self, *, limit: int = inf) -> bytes:
        truncated = True
        limit -= self._HEADER_LENGTH
        entries: List[bytes] = []
        sequence = [self.questions, self.answers, self.authority, self.additional]
        for entry in chain(*sequence):
            entry = entry.to_bytes()
            limit -= len(entry)
            if limit < 0:
                break
            entries.append(entry)
        else:
            truncated = False

        count = len(entries)
        nominal_lengths = [len(e) for e in sequence]
        actual_lengths = [0] * len(sequence)
        for i, ln in enumerate(nominal_lengths):
            count -= ln
            if count >= 0:
                actual_lengths[i] = ln
            else:
                actual_lengths[i] = abs(count)
                break

        flags = int(self.is_response) << 15 | self.opcode.value << 11 | int(self.is_authoritative) << 10 | \
                int(truncated) << 9 | int(self.recursion_desired) << 8 | \
                int(self.recursion_avail) << 7 | self.error_code.value
        header = struct.pack(self._HEADER_FORMAT, self.id, flags, *actual_lengths)
        return header + b''.join(entries)
