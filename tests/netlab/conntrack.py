#!/usr/bin/env python3
"""Flush the IPv4 conntrack table of the network namespace it runs in, as
`conntrack -F` does, through ctnetlink, standard library only:

    ip netns exec nwl-rtr conntrack.py

The lab's routers need it after a WAN address change, since a NAT binding
made with the old address outlives the address.
"""

import os
import socket
import struct
import sys

NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_DELETE = 2
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLMSG_ERROR = 2


def main():
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    sock.bind((0, 0))
    # A delete with no tuple flushes every entry of the family.
    body = struct.pack("=BBH", socket.AF_INET, 0, 0)
    kind = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE
    header = struct.pack("=IHHII", 16 + len(body), kind, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
    sock.send(header + body)
    reply = sock.recv(4096)
    _, reply_kind = struct.unpack("=IH", reply[:6])
    if reply_kind == NLMSG_ERROR:
        error = struct.unpack("=i", reply[16:20])[0]
        if error:
            sys.exit("conntrack flush failed: %s" % os.strerror(-error))
    print("conntrack flushed")


if __name__ == "__main__":
    main()
