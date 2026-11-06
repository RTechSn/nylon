#!/usr/bin/env python3
"""TCP bulk sender. Pushes 1 MiB chunks at full speed for <duration> seconds,
letting the bottleneck qdisc do the pacing.

Usage: bulk_send.py <dst> <port> <duration-seconds>
"""
import socket
import sys
import time


def main():
    dst, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    s = socket.create_connection((dst, port), timeout=5.0)
    buf = b"x" * (1 << 20)
    t0 = time.time()
    while time.time() - t0 < dur:
        try:
            s.sendall(buf)
        except OSError:
            break
    s.close()


if __name__ == "__main__":
    main()
