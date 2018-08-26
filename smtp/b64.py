import re

SYMBOLS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
           'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
           'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
           'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
           '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/']


def encode(bytes):
    bit_str = ''
    base64_str = ''
    padding = ''

    while (len(bytes) % 3) != 0:
        padding += '='
        bytes += b'\x00'

    for byte in bytes:
        bin_char = bin(byte).lstrip('0b')
        bin_char = (8 - len(bin_char)) * '0' + bin_char
        bit_str += bin_char

    bin_b64_symbols = re.findall('(\d{6})', bit_str)
    if padding != '':
        bin_b64_symbols = bin_b64_symbols[:-len(padding)]

    for bin_b64_symbol in bin_b64_symbols:
        base64_str += SYMBOLS[int(bin_b64_symbol, 2)]

    base64_str += padding
    return base64_str.encode()


def decode(bytes):
    source = bytes.decode()
    bin_str = b''
    bit_str = ''

    for char in source:
        if char != '=':
            bin_char = bin(SYMBOLS.index(char)).lstrip('0b')
            bin_char = (6 - len(bin_char)) * '0' + bin_char
            bit_str += bin_char

    bit_bytes = re.findall('(\d{8})', bit_str)

    for bit_byte in bit_bytes:
        bin_str += int(bit_byte, 2).to_bytes(length=1, byteorder="big")

    return bin_str

