#!/usr/bin/env python3
"""A STUN server for the natwg network lab, standard library only.

RFC 5780 mode answers on two IPs and two ports and honours CHANGE-REQUEST:

    stun_server.py --rfc5780 45.78.0.1 45.78.0.2 --port 3478 --alt-port 3479

Each answer carries XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, RESPONSE-ORIGIN and,
in RFC 5780 mode, OTHER-ADDRESS. Plain mode answers on one or more addresses
without OTHER-ADDRESS and ignores CHANGE-REQUEST:

    stun_server.py --plain 45.78.0.3 --plain 45.78.0.4 --port 3478

Every request is logged to stderr as one line.
"""

import argparse
import select
import socket
import struct
import sys

COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
MAPPED_ADDRESS = 0x0001
CHANGE_REQUEST = 0x0003
XOR_MAPPED_ADDRESS = 0x0020
SOFTWARE = 0x8022
RESPONSE_ORIGIN = 0x802B
OTHER_ADDRESS = 0x802C
CHANGE_IP = 0x04
CHANGE_PORT = 0x02


def address(kind, ip, port, xor=False):
    raw_ip = struct.unpack(">I", socket.inet_aton(ip))[0]
    if xor:
        raw_ip ^= COOKIE
        port ^= COOKIE >> 16
    return struct.pack(">HHBBHI", kind, 8, 0, 1, port, raw_ip)


def attribute(kind, value):
    padded = value + b"\0" * (-len(value) % 4)
    return struct.pack(">HH", kind, len(value)) + padded


def change_flags(request):
    """The CHANGE-REQUEST flags of a Binding request, 0 without one."""
    length = struct.unpack(">H", request[2:4])[0]
    body = request[20 : 20 + length]
    while len(body) >= 4:
        kind, size = struct.unpack(">HH", body[:4])
        if kind == CHANGE_REQUEST and size == 4:
            return struct.unpack(">I", body[4:8])[0]
        body = body[4 + size + (-size % 4) :]
    return 0


def answer(request, client, origin, other):
    attributes = address(XOR_MAPPED_ADDRESS, client[0], client[1], xor=True)
    attributes += address(MAPPED_ADDRESS, client[0], client[1])
    attributes += address(RESPONSE_ORIGIN, origin[0], origin[1])
    if other is not None:
        attributes += address(OTHER_ADDRESS, other[0], other[1])
    attributes += attribute(SOFTWARE, b"natwg netlab")
    header = struct.pack(">HHI", BINDING_SUCCESS, len(attributes), COOKIE)
    return header + request[8:20] + attributes


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rfc5780", nargs=2, metavar=("IP", "OTHER_IP"))
    parser.add_argument("--plain", action="append", default=[], metavar="IP")
    parser.add_argument("--port", type=int, default=3478)
    parser.add_argument("--alt-port", type=int, default=3479)
    args = parser.parse_args()

    sockets = {}
    for ip in (args.rfc5780 or []):
        for port in (args.port, args.alt_port):
            sockets[(ip, port)] = None
    for ip in args.plain:
        sockets[(ip, args.port)] = None
    for bound in sockets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(bound)
        sockets[bound] = sock
    by_fd = {sock.fileno(): (bound, sock) for bound, sock in sockets.items()}
    print("listening on " + " ".join("%s:%d" % b for b in sockets), file=sys.stderr, flush=True)

    while True:
        ready, _, _ = select.select(list(by_fd), [], [])
        for fd in ready:
            here, sock = by_fd[fd]
            request, client = sock.recvfrom(2048)
            if len(request) < 20 or struct.unpack(">H", request[:2])[0] != BINDING_REQUEST:
                continue
            if args.rfc5780 and here[0] in args.rfc5780:
                primary, alternate = args.rfc5780
                flags = change_flags(request)
                ip = here[0]
                if flags & CHANGE_IP:
                    ip = alternate if ip == primary else primary
                port = here[1]
                if flags & CHANGE_PORT:
                    port = args.alt_port if port == args.port else args.port
                origin = (ip, port)
                other_ip = alternate if here[0] == primary else primary
                other_port = args.alt_port if here[1] == args.port else args.port
                other = (other_ip, other_port)
            else:
                flags, origin, other = 0, here, None
            print(
                "%s:%d -> %s:%d change=%d answer-from %s:%d"
                % (client[0], client[1], here[0], here[1], flags, origin[0], origin[1]),
                file=sys.stderr,
                flush=True,
            )
            sockets[origin].sendto(answer(request, client, origin, other), client)


if __name__ == "__main__":
    main()
