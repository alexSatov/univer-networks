import os
import re
import locale
import random
import argparse
import ipaddress
import subprocess
from select import select
from struct import pack, unpack
from socket import socket, AF_INET, SOCK_DGRAM


def reverse_mapping(mapping):
    result = {}
    for key in mapping:
        result[mapping[key]] = key
    return result


DNS_DEFAULT_PORT = 53
DEFAULT_BUFFER_SIZE = 64 * 1024

CLASSES = {'IN': 1, 'ANY': 255, '*': 255}
OPCODES = {'QUERY': 0, 'IQUERY': 1, 'STATUS': 2}
MESSAGE_TYPE = {'QUERY': 0, 'RESPONSE': 1}
TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12,
         'MX': 15, 'AAAA': 28, 'ANY': 255, '*': 255}
RCODES = {'No error': 0, 'Format error': 1, 'Server failure': 2,
          'Name Error': 3, 'Not Implemented': 4, 'Refused': 5}


def deserialize_enum(mapping, value):
    for k, v in mapping.items():
        if v == value:
            return k
    return 'Unknown'


def deserialize_domain(data, offset):
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


def serialize_domain(domain):
    return b''.join(
        map(lambda label: pack(">B", len(label)) + label.encode('utf-8'),
            domain.split('.')))


def decode_rdata(data, offset, length, dns_type):
    if dns_type in ['A']:
        return str(ipaddress.IPv4Address(data[offset:offset + length]))
    if dns_type in ['AAAA']:
        return str(ipaddress.IPv6Address(data[offset:offset + length]))
    if dns_type in ['PTR', 'NS', 'CNAME']:
        return deserialize_domain(data, offset)[0]
    if dns_type in ['MX']:
        return [('Preference', unpack(">H", data[offset:offset + 2])[0]),
                ('Exchange', deserialize_domain(data, offset + 2)[0])]
    if dns_type == 'SOA':
        mname, offset = deserialize_domain(data, offset)
        rname, offset = deserialize_domain(data, offset)
        serial, refresh, retry, expire, minimum = unpack(
            ">5I", data[offset:offset + 20])
        return [('MNAME', mname), ('RNAME', rname), ('SERIAL', serial),
                ('REFRESH', refresh), ('RETRY', retry),
                ('EXPIRE', expire), ('MINIMUM', minimum)]
    return data[offset:offset + length]


def encode_rdata(rdata, dns_type):
    if dns_type == 'A':
        return b''.join(map(lambda x: int(x).to_bytes(1, 'big'),
                            rdata.split('.')))
    if dns_type == 'AAAA':
        return b''.join(map(bytes.fromhex, rdata.split(':')))
    if dns_type in ['PTR', 'NS', 'CNAME']:
        return serialize_domain(rdata)


def get_domain_name(target):
    if re.match(r'\d+\.\d+\.\d+\.\d+', target):
        return 'PTR', '.'.join(reversed(target.split('.'))) + ".IN-ADDR.ARPA."
    return 'A', target if target[-1] == '.' else target + '.'


class QuestionEntry:
    def __init__(self, domain, dns_type, dns_class):
        self.domain = domain
        self.dns_type = dns_type
        self.dns_class = dns_class

    @classmethod
    def deserialize(cls, data, offset):
        domain, offset = deserialize_domain(data, offset)
        dns_type, dns_class = unpack(">HH", data[offset:offset + 4])
        return QuestionEntry(domain, dns_type, dns_class), offset + 4

    def serialize(self):
        return serialize_domain(self.domain) + \
               pack(">HH", self.dns_type, self.dns_class)

    def to_plain_object(self):
        deser_type = deserialize_enum(TYPES, self.dns_type)
        deser_class = deserialize_enum(CLASSES, self.dns_class)
        return [("Domain", self.domain),
                ("TYPE", "%s (%d)" % (deser_type, self.dns_type)),
                ("CLASS", "%s (%d)" % (deser_class, self.dns_class))]


class ResourceRecord:
    def __init__(self, domain, dns_type, dns_class, ttl, rdlength, rdata):
        self.domain = domain
        self.dns_type = dns_type
        self.dns_class = dns_class
        self.ttl = ttl
        self.rdata = rdata
        self.rdlength = rdlength

    @classmethod
    def deserialize(cls, data, offset):
        domain, offset = deserialize_domain(data, offset)
        dns_type, dns_class, ttl, rdlen = unpack(">HHIH",
                                                 data[offset:offset + 10])
        rdata = decode_rdata(data, offset + 10, rdlen,
                             deserialize_enum(TYPES, dns_type))
        return ResourceRecord(domain, dns_type, dns_class, ttl, rdlen, rdata),\
            offset + 10 + rdlen

    def serialize(self):
        return serialize_domain(self.domain) \
               + pack(">HHIH", self.dns_type, self.dns_class,
                      self.ttl, self.rdlength) \
               + encode_rdata(self.rdata,
                              deserialize_enum(TYPES, self.dns_type))

    def to_plain_object(self):
        deser_type = deserialize_enum(TYPES, self.dns_type)
        deser_class = deserialize_enum(CLASSES, self.dns_class)
        return [("Domain", self.domain),
                ("TYPE", "%s (%d)" % (deser_type, self.dns_type)),
                ("CLASS", "%s (%d)" % (deser_class, self.dns_class)),
                ("TTL", self.ttl),
                ("RDLENGTH", self.rdlength),
                ("RDATA", self.rdata)]


def deserialize_list(cls, data, offset, count):
    result = []
    for i in range(count):
        rr, offset = cls.deserialize(data, offset)
        result.append(rr)
    return result, offset


def deserialize_resource_records(data, offset, count):
    return deserialize_list(ResourceRecord, data, offset, count)


def list_to_plain_object(prefix, list):
    return [("%s %d" % (prefix, i), list[i].to_plain_object())
            for i in range(len(list))]


def resource_records_to_plain_object(list):
    return list_to_plain_object("Resource record", list)


class Packet:
    def __init__(self, id, qr, opcode, aa, tc, rd, ra,
                 rcode, questions, answers, authority, additional):
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional

    @classmethod
    def form_request(cls, target, recursion=True, dns_type=None, dns_cls='IN'):
        default_type, domain = get_domain_name(target)
        question = QuestionEntry(
            domain,
            TYPES[default_type] if dns_type is None else TYPES[dns_type],
            CLASSES[dns_cls])
        return Packet(random.randint(0, 1 << 16), MESSAGE_TYPE['QUERY'],
                      OPCODES['QUERY'], 0, 0,
                      1 if recursion else 0,
                      1 if recursion else 0,
                      RCODES['No error'],
                      [question], [], [], [])

    @classmethod
    def deserialize(cls, data):
        id, options, questions_count, answers_count, \
            authority_count, additional_count = unpack(">HHHHHH", data[:12])
        qr = options >> 15
        opcode = (options >> 11) & 0xF
        aa = options >> 10 & 0x1
        tc = options >> 9 & 0x1
        rd = options >> 8 & 0x1
        ra = options >> 7 & 0x1
        rcode = options & 0xF
        offset = 12
        questions, offset = deserialize_list(
            QuestionEntry, data, offset, questions_count)
        answers, offset = deserialize_resource_records(
            data, offset, answers_count)
        authority, offset = deserialize_resource_records(
            data, offset, authority_count)
        additional, offset = deserialize_resource_records(
            data, offset, additional_count)
        return Packet(id, qr, opcode, aa, tc, rd, ra, rcode,
                      questions, answers, authority, additional)

    def serialize(self):
        options = self.qr << 15 | self.opcode << 11 | self.aa << 10 \
                  | self.tc << 9 | self.rd << 8 | self.ra << 7 | self.rcode
        header = pack('>HHHHHH', self.id, options, len(self.questions),
                      len(self.answers), len(self.authority),
                      len(self.additional))
        questions = b''.join(map(lambda qe: qe.serialize(), self.questions))
        answers = b''.join(map(lambda rr: rr.serialize(), self.answers))
        authority = b''.join(map(lambda rr: rr.serialize(), self.authority))
        additional = b''.join(map(lambda rr: rr.serialize(), self.additional))
        return header + questions + answers + authority + additional

    def to_plain_object(self):
        headers = [("ID", self.id),
                   ("QR", deserialize_enum(MESSAGE_TYPE, self.qr)),
                   ("OPCODE", deserialize_enum(OPCODES, self.opcode)),
                   ("AA", "YES" if self.aa == 1 else "NO"),
                   ("TC", "YES" if self.tc == 1 else "NO"),
                   ("RD", "YES" if self.rd == 1 else "NO"),
                   ("RA", "YES" if self.ra == 1 else "NO"),
                   ("Rcode", deserialize_enum(RCODES, self.rcode))]
        counts = [("Questions", len(self.questions)),
                  ("Answers", len(self.answers)),
                  ("Authority", len(self.authority)),
                  ("Additional", len(self.additional))]
        sections = [("HEADERS", headers), ("COUNTS", counts)]
        if len(self.questions) > 0:
            po = ("QUESTIONS",
                  list_to_plain_object("Question Entry", self.questions))
            sections.append(po)
        if len(self.answers) > 0:
            po = ("ANSWERS", resource_records_to_plain_object(self.answers))
            sections.append(po)
        if len(self.authority) > 0:
            po = ("AUTHORITY",
                  resource_records_to_plain_object(self.authority))
            sections.append(po)
        if len(self.additional) > 0:
            po = resource_records_to_plain_object(self.additional)
            sections.append(("ADDITIONAL", po))
        return sections


def get_default_dns_servers():
    if os.name == "nt":
        output = subprocess\
            .check_output('ipconfig /all')\
            .decode(locale.getpreferredencoding())
        raw_servers = re\
            .findall(r'(?:DNS Servers|DNS-серверы)\D+:([.\d\s]+)', output)
        not_none_lam = lambda x: x != ''
        split_lam = lambda s: re.split('\s+', s)
        servers = filter(not_none_lam, sum(map(split_lam, raw_servers), []))
        return list(servers)


def dns_type_handler(dns_type):
    if dns_type not in TYPES:
        raise argparse.ArgumentTypeError("Unknown DNS type '%s'" % dns_type)
    return dns_type


def dns_class_handler(dns_class):
    if dns_class not in CLASSES:
        raise argparse.ArgumentTypeError("Unknown DNS class '%s'" % dns_class)
    return dns_class


def get_args_parser():
    parser = argparse.ArgumentParser(description="DNS tool")
    parser.add_argument("target",
                        help="Domain name, IPv4 or IPv6 to be resolved")
    parser.add_argument("server",
                        nargs="*",
                        help="Domain servers to use",
                        default=get_default_dns_servers())
    parser.add_argument("-t", "--timeout",
                        help="Communication timeout in seconds (default 2)",
                        default=2, type=int)
    parser.add_argument("-v", "--verbose",
                        help="Show verbose packet structure",
                        action="store_true", default=False)
    parser.add_argument("--dns-type",
                        help="Query server with this DNS type",
                        type=dns_type_handler, default='A')
    parser.add_argument("--dns-class",
                        help="Query server with this DNS type",
                        type=dns_class_handler, default='IN')
    parser.add_argument("-r", "--no-recursion",
                        help="Disable recursion",
                        action="store_true", default=False)
    return parser


def get_address(source):
    chunks = source.split(':')
    return chunks[0], int(chunks[1]) if len(chunks) > 1 else DNS_DEFAULT_PORT


def get_raw_response(args, data):
    for server in args.server:
        try:
            address = get_address(server)
            with socket(AF_INET, SOCK_DGRAM) as sock:
                sock.sendto(data, address)
                if select([sock], [], [], args.timeout)[0]:
                    return sock.recvfrom(DEFAULT_BUFFER_SIZE)[0]
        except Exception:
            print('Failed to receive response from %s' % server)


def stringify_plain_object(obj, indent=0):
    result = ""
    for values in obj:
        if isinstance(values[1], list):
            t = (values[0], stringify_plain_object(values[1], indent + 1))
            result += "\t" * indent + "%s\n%s\n" % t
        else:
            result += "\t" * indent + "%-10s: %s\n" % (values[0], values[1])
    return result


def stringify_rr_short(rr):
    return "%s %s %s %s %s %s" % (rr.domain,
                                  deserialize_enum(TYPES, rr.dns_type),
                                  deserialize_enum(CLASSES, rr.dns_class),
                                  rr.ttl, rr.rdlength, rr.rdata)

if __name__ == "__main__":
    parser = get_args_parser()
    args = parser.parse_args()
    request = Packet.form_request(args.target,
                                  dns_type=args.dns_type,
                                  dns_cls=args.dns_class,
                                  recursion=not args.no_recursion)
    raw_packet = get_raw_response(args, request.serialize())
    if raw_packet:
        try:
            response = Packet.deserialize(raw_packet)
            if args.verbose:
                print(stringify_plain_object(response.to_plain_object()))
            for rr in response.answers:
                print(stringify_rr_short(rr))
            if len(response.answers) == 0 and len(response.authority) > 0:
                print("No answer. Set recursive or use authority:")
                for rr in response.authority:
                    print(stringify_rr_short(rr))
            if len(response.answers) == 0 and len(response.authority) == 0:
                s = "No answer not authority. Something wrong is going on here"
                print(s)
        except Exception:
            print('Failed to parse response')
    else:
        print('Failed to receive response')
