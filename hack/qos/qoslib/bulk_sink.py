#!/usr/bin/env python3
"""TCP drain sink for the bulk flow. Prints one BULK line per connection:

  BULK bytes=<n> secs=<s> mbit=<goodput>

Usage: bulk_sink.py <port>
"""
import socket
import sys
import threading
import time


def drain(c):
    n = 0
    t0 = time.time()
    while True:
        d = c.recv(1 << 16)
        if not d:
            break
        n += len(d)
    dt = time.time() - t0
    mbit = n * 8 / dt / 1e6 if dt > 0 else 0.0
    print("BULK bytes=%d secs=%.1f mbit=%.1f" % (n, dt, mbit), flush=True)
    c.close()


def main():
    port = int(sys.argv[1])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=drain, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
