tcp_queries = {
    'HTTP': b'GET /\r\nHost: localhost',
    'SMTP': b'NOOP\r\n',
    'IMAP': b'NOOP\r\n',
    'POP3': b'USER\r\n',
    'DNS': b'\xae\xd3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04'
           b'mail\x02ru\x00\x00\x01\x00\x01'  # mail.ru standard query
}

udp_queries = {
    'NTP': b'\x2b' + b'\x00'*47,
    'DNS': b'\xae\xd3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04'
           b'mail\x02ru\x00\x00\x01\x00\x01'  # mail.ru query
}

proto_val = {
    'HTTP': lambda reply: b'HTTP' in reply,
    'SMTP': lambda reply: reply[:4] in (b'220 ', b'250 '),
    'IMAP': lambda reply: b'OK' in reply,
    'POP3': lambda reply: reply[:3] in (b'+OK', b'-ER'),
    'DNS': lambda reply: reply[:2] == b'\xae\xd3',  # same id
    'NTP': lambda reply: len(reply) == 48  # ntp-packet length
}


def is_valid_reply(reply, proto):
    if reply:
        return proto_val[proto](reply)
    return False
