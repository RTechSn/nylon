#!/usr/bin/env python3
"""Latency probe for the nylon QoS test kit.

Sends small datagrams (UDP) or 1-byte ping-pongs (TCP) at a fixed interval and
prints a single RESULT line when done:

  RESULT scen=<scen> flow=<flow> sent=<n> recv=<n> loss=<pct> p50=<ms> p95=<ms> p99=<ms> max=<ms>

The reply wait timeout is 1s by default, which matches the range where a
corosync totem token goes missing — replies slower than that count as loss.

Options:
  --dst IP --port N --proto udp|tcp --duration S --interval S
  --tos HEX       set IP_TOS on the probe socket, e.g. 0xb8 = DSCP EF.
                  This is how the "outer DSCP marking" half of the QoS plan
                  is simulated before nylon itself marks its outer packets.
  --size N        UDP payload size in bytes (default 64)
  --scen NAME     scenario label for the RESULT line (default "run")
  --flow NAME     flow label (default "<proto><port>")
"""
import argparse
import socket
import sys
import time


def pct(sorted_vals, p):
    if not sorted_vals:
        return float("nan")
    i = min(len(sorted_vals) - 1, int(len(sorted_vals) * p))
    return sorted_vals[i]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--proto", choices=["udp", "tcp"], default="udp")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--interval", type=float, default=0.05)
    ap.add_argument("--tos", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--size", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--scen", default="run")
    ap.add_argument("--flow", default="")
    a = ap.parse_args()
    if not a.flow:
        a.flow = "%s%d" % (a.proto, a.port)

    if a.proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.create_connection((a.dst, a.port), timeout=3.0)
    s.settimeout(a.timeout)
    if a.tos:
        try:
            s.setsockopt(socket.SOL_IP, socket.IP_TOS, a.tos)
        except OSError as e:
            print("cannot set tos: %s" % e, file=sys.stderr)

    rtts = []
    sent = 0
    t0 = time.time()
    seq = 0
    while time.time() - t0 < a.duration:
        seq += 1
        sent += 1
        st = time.time()
        try:
            if a.proto == "udp":
                payload = ("%d|%.6f" % (seq, st)).encode().ljust(a.size)
                s.sendto(payload, (a.dst, a.port))
                s.recvfrom(2048)
            else:
                s.sendall(b"P")
                s.recv(1)
            rtt = (time.time() - st) * 1000.0
            rtts.append(rtt)
        except (socket.timeout, ConnectionError, OSError):
            pass
        delay = a.interval - (time.time() - st)
        if delay > 0:
            time.sleep(delay)
    try:
        s.close()
    except OSError:
        pass

    rtts.sort()
    recv = len(rtts)
    loss = (sent - recv) * 100.0 / sent if sent else 0.0
    print(
        "RESULT scen=%s flow=%s sent=%d recv=%d loss=%.1f%% p50=%.1f p95=%.1f p99=%.1f max=%.1f"
        % (
            a.scen,
            a.flow,
            sent,
            recv,
            loss,
            pct(rtts, 0.50),
            pct(rtts, 0.95),
            pct(rtts, 0.99),
            rtts[-1] if rtts else float("nan"),
        )
    )


if __name__ == "__main__":
    main()
