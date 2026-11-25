#!/usr/bin/env python3
"""A UPnP Internet Gateway Device for the natwg network lab, standard library
only. It runs in the router namespace and forwards leased UDP ports with
nftables, as a home router does:

    igd.py --lan-ip 192.168.77.1 --wan-ip 45.77.0.2 --wan-if nwl-r0 \\
        --table nwl --log /tmp/igd.log

- SSDP: answers M-SEARCH for an InternetGatewayDevice on 239.255.255.250:1900
  with LOCATION http://LAN_IP:5000/igd.xml. --no-ssdp leaves it out.
- HTTP on LAN_IP:5000: the device description, and SOAP on /ctl for
  GetExternalIPAddress, GetSpecificPortMappingEntry, AddPortMapping and
  DeletePortMapping of WANIPConnection:1.
- With --table, each mapping is a DNAT rule in chain `upnp_pre` and a
  port-keeping SNAT rule in chain `upnp_post` of `ip TABLE`; both chains are
  rebuilt on each change. Without it, nothing is forwarded.
- A lease with a duration ends after it, as the standard says.
- --permanent-only refuses a lease with a duration with error 725
  (OnlyPermanentLeasesSupported), as some routers do.
- --preset PORT:CLIENT holds a mapping from the start, made by someone else.

Every SOAP call is appended to the log as "ACTION port" (AddPortMapping adds
"lease=N" and, when refused, "refused=CODE"), each change as "MAPPINGS n",
and each lease that ends as "EXPIRED port".
"""

import argparse
import http.server
import re
import socket
import struct
import subprocess
import sys
import threading

SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"
DEVICE = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
SSDP = ("239.255.255.250", 1900)
HTTP_PORT = 5000

DESCRIPTION = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>natwg netlab gateway</friendlyName>
<deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<controlURL>/ctl</controlURL>
<eventSubURL>/evt</eventSubURL>
<SCPDURL>/scpd.xml</SCPDURL>
</service></serviceList>
</device></deviceList>
</device></deviceList>
</device>
</root>
"""


def envelope(body):
    return (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>%s</s:Body></s:Envelope>'
        % body
    )


def response(action, fields=""):
    return envelope('<u:%sResponse xmlns:u="%s">%s</u:%sResponse>' % (action, SERVICE, fields, action))


def fault(code, description):
    return envelope(
        "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"
        '<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode>'
        "<errorDescription>%s</errorDescription></UPnPError></detail></s:Fault>" % (code, description)
    )


def field(body, name):
    found = re.search(r"<%s>([^<]*)</%s>" % (name, name), body)
    return found.group(1) if found else ""


class Gateway:
    def __init__(self, args):
        self.args = args
        # external port -> (client, internal port, description, lease seconds, generation)
        self.mappings = {}
        self.generation = 0
        self.lock = threading.Lock()
        for preset in args.preset:
            port, client = preset.split(":")
            self.mappings[int(port)] = (client, int(port), "someone else", 0, 0)

    def log(self, line):
        with open(self.args.log, "a") as log:
            log.write(line + "\n")

    def apply(self):
        table = self.args.table
        if not table:
            return
        commands = ["flush chain ip %s upnp_pre" % table, "flush chain ip %s upnp_post" % table]
        for port, (client, internal, _, _, _) in sorted(self.mappings.items()):
            commands.append(
                "add rule ip %s upnp_pre ip daddr %s udp dport %d dnat to %s:%d"
                % (table, self.args.wan_ip, port, client, internal)
            )
            commands.append(
                'add rule ip %s upnp_post oifname "%s" ip saddr %s udp sport %d snat to %s:%d'
                % (table, self.args.wan_if, client, internal, self.args.wan_ip, port)
            )
        subprocess.run(["nft", "-f", "-"], input="\n".join(commands) + "\n", text=True, check=True)

    def changed(self):
        self.apply()
        self.log("MAPPINGS %d" % len(self.mappings))

    def expire(self, port, generation):
        with self.lock:
            if self.mappings.get(port, (None,) * 5)[4] == generation:
                del self.mappings[port]
                self.log("EXPIRED %d" % port)
                self.changed()

    def call(self, action, body):
        port = int(field(body, "NewExternalPort") or 0)
        with self.lock:
            if action == "GetExternalIPAddress":
                self.log(action)
                return response(action, "<NewExternalIPAddress>%s</NewExternalIPAddress>" % self.args.wan_ip)
            if action == "GetSpecificPortMappingEntry":
                self.log("%s %d" % (action, port))
                if port not in self.mappings:
                    return fault(714, "NoSuchEntryInArray")
                client, internal, description, lease, _ = self.mappings[port]
                return response(
                    action,
                    "<NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient>"
                    "<NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription>"
                    "<NewLeaseDuration>%d</NewLeaseDuration>" % (internal, client, description, lease),
                )
            if action == "AddPortMapping":
                lease = int(field(body, "NewLeaseDuration") or 0)
                line = "%s %d lease=%d" % (action, port, lease)
                if self.args.permanent_only and lease != 0:
                    self.log(line + " refused=725")
                    return fault(725, "OnlyPermanentLeasesSupported")
                client = field(body, "NewInternalClient")
                existing = self.mappings.get(port)
                if existing and existing[0] != client:
                    self.log(line + " refused=718")
                    return fault(718, "ConflictInMappingEntry")
                self.log(line)
                self.generation += 1
                internal = int(field(body, "NewInternalPort"))
                description = field(body, "NewPortMappingDescription")
                self.mappings[port] = (client, internal, description, lease, self.generation)
                if lease:
                    timer = threading.Timer(lease, self.expire, (port, self.generation))
                    timer.daemon = True
                    timer.start()
                self.changed()
                return response(action)
            if action == "DeletePortMapping":
                self.log("%s %d" % (action, port))
                if self.mappings.pop(port, None) is None:
                    return fault(714, "NoSuchEntryInArray")
                self.changed()
                return response(action)
            self.log(action)
            return fault(401, "Invalid Action")


def serve_http(gateway, ip):
    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, text):
            data = text.encode()
            self.send_response(status)
            self.send_header("Content-Type", 'text/xml; charset="utf-8"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            gateway.log("GET %s" % self.path)
            if self.path == "/igd.xml":
                self.reply(200, DESCRIPTION)
            else:
                self.reply(404, "")

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            action = self.headers.get("SOAPAction", "").strip('"').rsplit("#", 1)[-1]
            text = gateway.call(action, body)
            self.reply(500 if "<s:Fault>" in text else 200, text)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer((ip, HTTP_PORT), Handler)
    server.serve_forever()


def serve_ssdp(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", SSDP[1]))
    membership = struct.pack("4s4s", socket.inet_aton(SSDP[0]), socket.inet_aton(args.lan_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    location = "http://%s:%d/igd.xml" % (args.lan_ip, HTTP_PORT)
    while True:
        request, client = sock.recvfrom(2048)
        text = request.decode(errors="replace")
        if not text.startswith("M-SEARCH") or DEVICE not in text:
            continue
        answer = (
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nLOCATION: %s\r\n"
            "SERVER: natwg-netlab/1 UPnP/1.0\r\nST: %s\r\nUSN: uuid:natwg-netlab::%s\r\n\r\n"
            % (location, DEVICE, DEVICE)
        )
        sock.sendto(answer.encode(), client)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lan-ip", required=True, help="where HTTP listens and SSDP joins")
    parser.add_argument("--wan-ip", default="0.0.0.0")
    parser.add_argument("--wan-if", default="")
    parser.add_argument("--table", default="", help="the nft table to forward leases in")
    parser.add_argument("--log", required=True)
    parser.add_argument("--no-ssdp", action="store_true")
    parser.add_argument("--permanent-only", action="store_true")
    parser.add_argument("--preset", action="append", default=[], metavar="PORT:CLIENT")
    args = parser.parse_args()
    gateway = Gateway(args)
    gateway.apply()
    if gateway.mappings:
        gateway.log("MAPPINGS %d" % len(gateway.mappings))
    if args.no_ssdp:
        print("IGD on %s:%d" % (args.lan_ip, HTTP_PORT), file=sys.stderr, flush=True)
        serve_http(gateway, args.lan_ip)
        return
    threading.Thread(target=serve_http, args=(gateway, args.lan_ip), daemon=True).start()
    print("IGD on %s:%d" % (args.lan_ip, HTTP_PORT), file=sys.stderr, flush=True)
    serve_ssdp(args)


if __name__ == "__main__":
    main()
