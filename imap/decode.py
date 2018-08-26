import re
import b64
from quopri import decodestring as qpdecode

_ENC_STR = re.compile(r'=\?.+?\?\w\?.+?\?=', re.DOTALL)
ENCODED_STRING = re.compile(r'=\?(.+?\?\w\?.+?)\?=', re.DOTALL)


def decode(string):
    ascii_parts = re.split(_ENC_STR, string)
    enc_parts = re.findall(ENCODED_STRING, string)
    dec_parts = map(decode_str, enc_parts)
    result = ''.join(
        map(lambda t: t[0] + t[1], zip(ascii_parts, dec_parts)))
    return result + ascii_parts[-1]


def decode_str(string):
    if not string:
        return ''

    str_enc, b_enc, enc_bytes = string.split('?')

    if b_enc in ('B', 'b'):
        dec_bytes = b_decode(enc_bytes)
    elif b_enc in ('Q', 'q'):
        dec_bytes = q_decode(enc_bytes)
    else:
        raise AttributeError('Unknown encoding attribute: %s' % b_enc)

    return dec_bytes.decode(str_enc)


def b_decode(string):  # base64
    return b64.decode(string.encode())


def q_decode(string):  # quoted-printable
    return qpdecode(string.encode())
