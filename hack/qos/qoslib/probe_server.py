#!/usr/bin/env python3
"""Echo server for the nylon QoS test kit.

  --udp PORT...   UDP echo sockets (echo every datagram back to its sender)
  --tcp PORT...   TCP 1:1 echo (accept, echo every received byte back)

Used by both hack/qos/tc-prio-demo.sh and demo/qos-test.sh:

  probe_server.py --udp 5405 7999 --tcp 22
"""
import argparse
import selectors
import socket


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--udp", type=int, nargs="*", default=[])
    ap.add_argument("--tcp", type=int, nargs="*", default=[])
    a = ap.parse_args()

    sel = selectors.DefaultSelector()

    def on_udp(s):
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)

    def on_conn(c):
        data = c.recv(65535)
        if not data:
            sel.unregister(c)
            c.close()
            return
        c.sendall(data)

    def on_accept(s):
        c, _ = s.accept()
        c.setblocking(True)
        sel.register(c, selectors.EVENT_READ, on_conn)

    for p in a.udp:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        sel.register(s, selectors.EVENT_READ, on_udp)
    for p in a.tcp:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.listen(16)
        sel.register(s, selectors.EVENT_READ, on_accept)

    while True:
        for key, _ in sel.select():
            key.data(key.fileobj)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
