#!/usr/bin/env python3
"""A fake Cloudflare API and the authoritative DNS server of its zone, for the
natwg network lab, standard library only. It runs in the internet namespace:

    cloudflare.py --api 45.78.0.80:80 --dns 45.78.0.53:53 --zone example.net \\
        --token netlab-token --log /tmp/cloudflare.log \\
        [--record home.example.net=A:45.77.0.99]

- HTTP under /client/v4, the calls natwg makes: GET /zones?name=ZONE, GET
  /zones/ID/dns_records?type=T&name=N, POST /zones/ID/dns_records and PUT
  /zones/ID/dns_records/RECORD_ID. A call without "Authorization: Bearer
  TOKEN" gets HTTP 403 with error 9109, as from Cloudflare.
- DNS over UDP: answers A and TXT queries for the records the API holds,
  with the authoritative flag and each record's TTL. A name it holds no
  record of is NXDOMAIN.
- --record NAME=TYPE:CONTENT[,proxied] holds a record from the start, as
  one made before natwg ran: not proxied with a TTL of 60, or proxied with
  the automatic TTL (1), as the dashboard makes an A record.

The log gets one line per write, "POST TYPE NAME CONTENT", "PUT TYPE NAME
CONTENT" or "DELETE RECORD_ID", one per refused call, "DENIED METHOD
PATH", and one per DNS
answer, "DNS TYPE NAME CONTENT" or "DNS TYPE NAME NXDOMAIN". The API stores
a TXT content as Cloudflare does, quoted, and DNS answers it unquoted.
"""

import argparse
import http.server
import ipaddress
import json
import socket
import struct
import sys
import threading
import urllib.parse

ZONE_ID = "zone1"
PREFIX = "/client/v4"
TYPES = {"A": 1, "TXT": 16}


class Zone:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.records = {}
        self.next_id = 1
        for preset in args.record:
            name, kind_content = preset.split("=", 1)
            kind, content = kind_content.split(":", 1)
            proxied = content.endswith(",proxied")
            content = content.removesuffix(",proxied")
            ttl = 1 if proxied else 60
            self.add({"type": kind, "name": name, "content": content, "ttl": ttl, "proxied": proxied})

    def log(self, line):
        with open(self.args.log, "a") as log:
            log.write(line + "\n")

    def add(self, record):
        record = dict(record, id="rec%d" % self.next_id)
        self.next_id += 1
        self.records[record["id"]] = record
        return record

    def find(self, kind, name):
        return [
            record
            for record in self.records.values()
            if (not kind or record["type"] == kind) and record["name"].lower() == name.lower()
        ]


def valid(zone, record):
    """Why the record cannot be stored, or None."""
    kind, name, content = record.get("type"), record.get("name", ""), record.get("content", "")
    if kind not in TYPES:
        return "type %r is not supported" % kind
    if not (name == zone or name.endswith("." + zone)):
        return "%s is outside the zone %s" % (name, zone)
    if kind == "A":
        try:
            ipaddress.IPv4Address(content)
        except ValueError:
            return "content %r is not an IPv4 address" % content
    return None


def serve_api(zone, address):
    args = zone.args

    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, result=None, errors=None):
            body = json.dumps(
                {"success": errors is None, "errors": errors or [], "messages": [], "result": result}
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def fail(self, status, code, message):
            self.reply(status, errors=[{"code": code, "message": message}])

        def allowed(self):
            if self.headers.get("Authorization") == "Bearer " + args.token:
                return True
            zone.log("DENIED %s %s" % (self.command, self.path))
            self.fail(403, 9109, "Invalid access token")
            return False

        def route(self):
            url = urllib.parse.urlsplit(self.path)
            if not url.path.startswith(PREFIX):
                return None, None, {}
            parts = url.path[len(PREFIX):].strip("/").split("/")
            query = {key: values[0] for key, values in urllib.parse.parse_qs(url.query).items()}
            return parts, url, query

        def body(self):
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self):
            if not self.allowed():
                return
            parts, _, query = self.route()
            with zone.lock:
                if parts == ["zones"]:
                    found = [{"id": ZONE_ID, "name": args.zone}] if query.get("name") == args.zone else []
                    return self.reply(200, found)
                if parts == ["zones", ZONE_ID, "dns_records"]:
                    return self.reply(200, zone.find(query.get("type"), query.get("name", "")))
            self.fail(404, 7003, "No route for that URI")

        def do_POST(self):
            if not self.allowed():
                return
            parts, _, _ = self.route()
            if parts != ["zones", ZONE_ID, "dns_records"]:
                return self.fail(404, 7003, "No route for that URI")
            record = self.body()
            problem = valid(args.zone, record)
            if problem:
                return self.fail(400, 9005, problem)
            with zone.lock:
                stored = zone.add(record)
                zone.log("POST %s %s %s" % (stored["type"], stored["name"], stored["content"]))
            self.reply(200, stored)

        def do_PUT(self):
            if not self.allowed():
                return
            parts, _, _ = self.route()
            if len(parts or []) != 4 or parts[:3] != ["zones", ZONE_ID, "dns_records"]:
                return self.fail(404, 7003, "No route for that URI")
            record = self.body()
            problem = valid(args.zone, record)
            if problem:
                return self.fail(400, 9005, problem)
            with zone.lock:
                if parts[3] not in zone.records:
                    return self.fail(404, 81044, "Record does not exist")
                stored = dict(record, id=parts[3])
                zone.records[parts[3]] = stored
                zone.log("PUT %s %s %s" % (stored["type"], stored["name"], stored["content"]))
            self.reply(200, stored)

        def do_DELETE(self):
            if not self.allowed():
                return
            parts, _, _ = self.route()
            if len(parts or []) != 4 or parts[:3] != ["zones", ZONE_ID, "dns_records"]:
                return self.fail(404, 7003, "No route for that URI")
            with zone.lock:
                if zone.records.pop(parts[3], None) is None:
                    return self.fail(404, 81044, "Record does not exist")
                zone.log("DELETE %s" % parts[3])
            self.reply(200, {"id": parts[3]})

        def log_message(self, *_):
            pass

    host, port = address.rsplit(":", 1)
    server = http.server.ThreadingHTTPServer((host, int(port)), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def question(message):
    """The name, type and end of the one question of a query, or None."""
    at, labels = 12, []
    while at < len(message):
        length = message[at]
        at += 1
        if length == 0:
            break
        if length > 63:
            return None
        labels.append(message[at:at + length].decode("ascii", "replace"))
        at += length
    if at + 4 > len(message):
        return None
    kind = struct.unpack("!H", message[at:at + 2])[0]
    return ".".join(labels), kind, at + 4


def txt_data(content):
    text = content.strip('"').encode()
    return b"".join(bytes([len(text[i:i + 255])]) + text[i:i + 255] for i in range(0, max(len(text), 1), 255))


def answer(zone, message):
    if len(message) < 12:
        return None
    ident, flags, questions = struct.unpack("!HHH", message[:6])
    asked = question(message) if questions == 1 else None
    if asked is None:
        return struct.pack("!HHHHHH", ident, 0x8001 | (flags & 0x0100), 0, 0, 0, 0)
    name, kind, end = asked
    names = {code: label for label, code in TYPES.items()}
    with zone.lock:
        held = zone.find(None, name)
        records = [record for record in held if TYPES.get(record["type"]) == kind]
    rcode = 0 if held else 3
    head = struct.pack("!HHHHHH", ident, 0x8400 | (flags & 0x0100) | rcode, 1, len(records), 0, 0)
    body = message[12:end]
    for record in records:
        if record["type"] == "A":
            data = ipaddress.IPv4Address(record["content"]).packed
        else:
            data = txt_data(record["content"])
        ttl = int(record.get("ttl") or 60)
        body += struct.pack("!HHHIH", 0xC00C, kind, 1, ttl, len(data)) + data
    shown = " ".join(record["content"] for record in records) or ("NXDOMAIN" if rcode else "none")
    zone.log("DNS %s %s %s" % (names.get(kind, kind), name, shown))
    return head + body


def serve_dns(zone, address):
    host, port = address.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))

    def loop():
        while True:
            message, source = sock.recvfrom(4096)
            reply = answer(zone, message)
            if reply:
                sock.sendto(reply, source)

    threading.Thread(target=loop, daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", required=True, help="IP:PORT of the HTTP API")
    parser.add_argument("--dns", required=True, help="IP:PORT of the DNS server")
    parser.add_argument("--zone", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--record", action="append", default=[], help="NAME=TYPE:CONTENT")
    args = parser.parse_args()
    zone = Zone(args)
    serve_api(zone, args.api)
    serve_dns(zone, args.dns)
    print("Cloudflare API on http://%s%s, DNS on %s" % (args.api, PREFIX, args.dns), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    sys.exit(main())
