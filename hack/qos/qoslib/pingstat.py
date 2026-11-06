#!/usr/bin/env python3
"""Turn an iputils ping log into a RESULT line (format: see probe_client.py).

Usage: pingstat.py <ping-log-file> <scenario-label>
"""
import re
import sys


def pct(v, p):
    if not v:
        return float("nan")
    return v[min(len(v) - 1, int(len(v) * p))]


def main():
    path, scen = sys.argv[1], sys.argv[2]
    with open(path, "r", errors="replace") as f:
        text = f.read()
    m = re.search(r"(\d+) packets transmitted, (\d+) received", text)
    if m:
        sent, recv = int(m.group(1)), int(m.group(2))
    else:
        seqs = [int(x) for x in re.findall(r"icmp_seq=(\d+)", text)]
        sent = max(seqs) if seqs else 0
        recv = len(re.findall(r" time=", text))
    rtts = sorted(float(x) for x in re.findall(r"time=([\d.]+)", text))
    loss = (sent - recv) * 100.0 / sent if sent else 0.0
    print(
        "RESULT scen=%s flow=icmp sent=%d recv=%d loss=%.1f%% p50=%.1f p95=%.1f p99=%.1f max=%.1f"
        % (
            scen,
            sent,
            recv,
            loss,
            pct(rtts, 0.5),
            pct(rtts, 0.95),
            pct(rtts, 0.99),
            rtts[-1] if rtts else float("nan"),
        )
    )


if __name__ == "__main__":
    main()
