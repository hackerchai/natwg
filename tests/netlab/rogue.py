#!/usr/bin/env python3
"""A hostile SSDP responder for the natwg network lab, standard library only.

It answers every M-SEARCH for an InternetGatewayDevice with ANSWERS answers,
each with LOCATION, where "{n}" becomes the answer's number:

    rogue.py --lan-ip 192.168.77.1 --location http://45.78.0.3:5000/igd.xml
    rogue.py --lan-ip 192.168.77.1 --answers 10 \\
        --location 'http://192.168.77.1:5001/d{n}.xml' --stall 192.168.77.1:5001

--stall IP:PORT also accepts TCP connections there and never answers them,
a device description that never arrives.
"""

import argparse
import socket
import struct
import sys
import threading

DEVICE = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
SSDP = ("239.255.255.250", 1900)


def stall(address):
    ip, port = address.rsplit(":", 1)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((ip, int(port)))
    listener.listen(64)
    held = []
    while True:
        connection, _ = listener.accept()
        held.append(connection)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lan-ip", required=True)
    parser.add_argument("--location", required=True)
    parser.add_argument("--answers", type=int, default=1)
    parser.add_argument("--stall", metavar="IP:PORT")
    args = parser.parse_args()
    if args.stall:
        threading.Thread(target=stall, args=(args.stall,), daemon=True).start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", SSDP[1]))
    membership = struct.pack("4s4s", socket.inet_aton(SSDP[0]), socket.inet_aton(args.lan_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    print("rogue SSDP on %s" % args.lan_ip, file=sys.stderr, flush=True)
    while True:
        request, client = sock.recvfrom(2048)
        text = request.decode(errors="replace")
        if not text.startswith("M-SEARCH") or DEVICE not in text:
            continue
        for n in range(args.answers):
            answer = "HTTP/1.1 200 OK\r\nLOCATION: %s\r\nST: %s\r\n\r\n" % (
                args.location.replace("{n}", str(n)),
                DEVICE,
            )
            sock.sendto(answer.encode(), client)


if __name__ == "__main__":
    main()
