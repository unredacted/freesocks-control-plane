"""Perform UDP DNS through the client's SOCKS5 UDP association (RFC 1928)."""
import socket
import struct
import secrets
import sys


def read_exact(sock, count):
    value = b''
    while len(value) < count:
        part = sock.recv(count - len(value))
        if not part:
            raise RuntimeError('SOCKS connection closed')
        value += part
    return value


with socket.create_connection(('127.0.0.1', 1080), timeout=5) as control:
    control.sendall(b'\x05\x01\x00')
    assert read_exact(control, 2) == b'\x05\x00', 'SOCKS authentication failed'
    control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
    header = read_exact(control, 4)
    assert header[:3] == b'\x05\x00\x00', 'UDP association failed'
    if header[3] == 1:
        host = socket.inet_ntop(socket.AF_INET, read_exact(control, 4))
    elif header[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(control, 16))
    else:
        host = read_exact(control, read_exact(control, 1)[0]).decode()
    port = struct.unpack('!H', read_exact(control, 2))[0]
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1'
    txid = secrets.token_bytes(2)
    label = secrets.token_hex(6).encode()
    query = txid + bytes.fromhex('01000001000000000000') + bytes([len(label)]) + label + b'\x04test\x00\x00\x01\x00\x01'
    target = socket.inet_aton(sys.argv[1])
    packet = b'\x00\x00\x00\x01' + target + struct.pack('!H', 5353) + query
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(8)
        udp.sendto(packet, (host, port))
        response, _ = udp.recvfrom(4096)
    atyp = response[3]
    offset = 10 if atyp == 1 else (22 if atyp == 4 else 7 + response[4])
    answer = response[offset:]
    assert answer[:2] == txid and answer[-4:] == bytes([192, 0, 2, 42]), 'Invalid DNS answer'
    assert label in answer, 'DNS response did not echo the fresh question'
print('UDP_DNS_OK')
