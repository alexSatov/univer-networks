# coding=utf-8
from collections import namedtuple
from ipaddress import IPv6Address, IPv4Address, AddressValueError
from typing import Iterable, Generator, Optional

from modules.packet import ResourceRecord, Type, Class, RData

_TYPES = [t.name for t in Type]
_CLASSES = [c.name for c in Class]


class DnsParseError(ValueError):
    pass


class _Tokens:
    COMMENT = ';'
    ESCAPE = '\\'
    LEFT_PAR = '('
    RIGHT_PAR = ')'


def _flatten(lines: Iterable[str]) -> Iterable[str]:
    opened_par = 0

    def open(x):
        nonlocal opened_par
        opened_par += 1

    def close(x):
        nonlocal opened_par
        opened_par -= 1

    neutral = lambda x: x
    empty = lambda x: None

    any = lambda x: True
    alnum = lambda x: x.isalnum() or x in '+-=/!@#$%^&<>,.[]{}":`~_'
    space = lambda x: x.isspace()
    left = lambda x: x == _Tokens.LEFT_PAR
    right = lambda x: x == _Tokens.RIGHT_PAR
    escape = lambda x: x == _Tokens.ESCAPE
    comment = lambda x: x == _Tokens.COMMENT

    normal_transition = ((alnum, neutral, 0),
                         (space, neutral, 1),
                         (left, open, 2),
                         (right, close, 3),
                         (escape, empty, 4),
                         (comment, empty, 5))

    transitions = (
        # 0 entry
        (
            normal_transition
        ),
        # 1 space
        (
            (alnum, neutral, 0),
            (space, empty, 1),
            (left, open, 2),
            (right, close, 3),
            (escape, empty, 4),
            (comment, empty, 5)
        ),
        # 2 left parenthesis
        (
            normal_transition
        ),
        # 3 right parenthesis
        (
            normal_transition
        ),
        # 4 escape
        (
            (any, neutral, 0),
        ),
        # 5 commentary
        (
            (any, empty, 5),
        )
    )

    exit_states = {0, 1, 2, 3, 5}

    buffer = []
    state = 0
    for line in lines:
        if not line:
            continue
        state = 0
        symbols = []
        for sym in line:
            any = False
            for test, val, trans in transitions[state]:
                if not test(sym):
                    continue
                any = True
                state = trans
                sym = val(sym)
                if sym:
                    symbols.append(sym)
                break
            if not any:
                raise DnsParseError('Unknown character sequence')

        read_line = ''.join(symbols)
        if opened_par == 0:
            if not len(buffer):
                yield read_line
            else:
                buffer.append(read_line)
                yield ' '.join(buffer)
                buffer = []
        elif opened_par < 0:
            raise DnsParseError(f'Parentheses mismatch near line "{line}"')
        else:
            buffer.append(read_line)
    if state not in exit_states:
        raise DnsParseError('Ended in wrong state, incorrect input')


def _tokenize_line(line: str):
    if not line:
        return None
    split = line.split()
    result = namedtuple('tokens', ('name', 'ttl', 'cclass', 'type', 'rdata'))
    result.cclass = None
    result.ttl = None
    if line[0].isspace():
        result.name = None
    else:
        result.name = split.pop(0)

    for i in range(2):
        if split[0].isdigit():
            result.ttl = int(split.pop(0))
        elif split[0] in _CLASSES:
            result.cclass = Class[split.pop(0)]
    if split[0] in _TYPES:
        result.type = Type[split.pop(0)]
    else:
        result.type = split.pop(0)
    result.rdata = split
    return result


class _Readers:
    @staticmethod
    def _get_ip(type, params):
        ip = params[0]
        try:
            ip = type(ip)
        except AddressValueError:
            raise DnsParseError(f'Wrong IP format for {type}, {ip}')
        return ip

    @classmethod
    def a(cls, params, *args) -> RData:
        return RData.get_data_class(Type.A)(cls._get_ip(IPv4Address, params))

    @classmethod
    def aaaa(cls, params, *args) -> RData:
        return RData.get_data_class(Type.AAAA)(cls._get_ip(IPv6Address, params))

    @staticmethod
    def name(params, origin: str) -> RData:
        name = _derive_name(params[0], None, origin)
        return RData.get_data_class(Type.NS)(name)

    @staticmethod
    def mx(params, origin: str) -> RData:
        name = _derive_name(params[1], None, origin)
        return RData.get_data_class(Type.MX)(int(params[0]), name)

    @staticmethod
    def soa(params, origin: str) -> RData:
        mname = _derive_name(params[0], None, origin)
        rname = _derive_name(params[1], None, origin)
        return RData.get_data_class(Type.SOA)(mname, rname, *map(int, params[2:]))


_TYPE_READERS = {
    Type.MX: _Readers.mx,
    Type.A: _Readers.a,
    Type.AAAA: _Readers.aaaa,
    Type.NS: _Readers.name,
    Type.PTR: _Readers.name,
    Type.CNAME: _Readers.name,
    Type.SOA: _Readers.soa
}


def _derive_name(name: str, prev_name: str, origin: str) -> Optional[str]:
    if not name:
        return prev_name
    if name == '@':
        return origin
    if name.endswith('.'):
        return name
    if not origin:
        return None
    return name + '.' + origin


def _derive_ttl(ttl: int, last_ttl: int, minimum: int) -> Optional[int]:
    if not ttl:
        return max(last_ttl, minimum)
    return max(ttl, minimum)


def _derive_class(_class: Class, default_class: Class) -> Class:
    if not _class:
        return default_class
    if _class == default_class:
        return _class


def _tokenize_special(line: str):
    result = namedtuple('tokens', ('name', 'value'))
    result.name, *result.value = line.split()
    return result


def parse_file(path: str, fqdn: str) -> Generator[None, ResourceRecord, None]:
    try:
        with open(path) as file:
            contents = file.readlines()
    except Exception as e:
        raise DnsParseError(str(e)) from e
    contents = filter(lambda x: x and not x.isspace(), _flatten(contents))


    origin = fqdn
    name = None
    ttl = 0
    soa = None
    _class = None
    for line in contents:
        var = _tokenize_special(line)
        if var.name == '$ORIGIN':
            origin = var.value[0]
            if not origin.endswith('.'):
                origin += '.'
            continue
        elif var.name == '$TTL':
            ttl = int(var.value[0])
            continue
        elif var.name == '$INCLUDE':
            raise DnsParseError('Includes are not supported')

        line = _tokenize_line(line)

        if line.type not in _TYPE_READERS:
            raise DnsParseError(f'Record of type {line.type} is not supported')

        name = _derive_name(line.name, name, origin)
        if not name:
            if not soa:
                raise DnsParseError('SOA record not found. Must be on top of file')
            raise DnsParseError('Record is corrupted: cannot derive domain name')

        rdata = _TYPE_READERS[line.type](line.rdata, origin)
        if line.type == Type.SOA:
            if not soa:
                soa = rdata
                _class = line.cclass
            else:
                raise DnsParseError('Must be exactly one SOA record in file')

        ttl = _derive_ttl(line.ttl, ttl, soa.minimum)
        if not ttl:
            raise DnsParseError('Record is corrupted: failed to derive TTL.')

        _class = _derive_class(line.cclass, _class)
        if not _class:
            raise DnsParseError('No class specified for SOA record or multiple classes in one file')

        record = ResourceRecord(name, line.type, _class, ttl, rdata)
        yield record
