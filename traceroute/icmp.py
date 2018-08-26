import struct

ICMP_FORMAT = '>BBHHH'
PROTOCOL_NAME = 'icmp'
REQUEST_CHECKSUM = 63487


def get_icmp_request_packet():
    return Packet(8, checksum=REQUEST_CHECKSUM)


class Packet:
    def __init__(self, type=0, code=0, checksum=0, content=None):
        self.code = code
        self.type = type
        self.checksum = checksum

    def to_binary(self):
        return struct.pack(ICMP_FORMAT, self.type, self.code, self.checksum,
                           0, 0)

    def is_reply(self):
        return self.type == 0

    def is_ttl_exceeded(self):
        return self.type == 11

    @staticmethod
    def from_binary(bin_packet):
        type, code, checksum = struct.unpack(ICMP_FORMAT, bin_packet)[:-2]
        return Packet(type, code, checksum)
