#!/bin/bash
# tc-prio-demo.sh — standalone sanity check for the nylon in-tunnel QoS plan.
#
# It answers two questions WITHOUT any nylon involvement:
#
#   1. "bloat"  — how badly does a dumb deep FIFO at a bottleneck inflate
#                 small-flow RTT while bulk saturates it? (the "before")
#   2. "prio"   — does a small priority class, selected either by L4 port
#                 (like the future nylon priority_ports match) or by DSCP EF
#                 (like the outer marking nylon will apply), keep small-flow
#                 RTT at the base delay on the SAME saturated bottleneck?
#
# The eventual nylon feature classifies INNER packets by port and raises
# their in-device priority (polyamide already orders batches by
# TCElement.Priority); to survive the WAN bottleneck the plan is to mirror
# that classification onto the OUTER packets as DSCP. This demo validates
# the WAN half: both classification methods and the measurement method.
#
# Requirements: root + iproute2 (ip, tc) + python3 on the host.
# Kernel modules: sch_netem, sch_htb, sch_prio, cls_u32 (stock everywhere).
# Optional: ethtool — disables offloads for exact packet accounting.
#
# Usage:  sudo ./hack/qos/tc-prio-demo.sh
#
# Topology (throwaway network namespaces, cleaned on exit):
#     qosdemo-a 10.9.0.1  qa0 ==== qb0  qosdemo-b 10.9.0.2
#     egress of qa0 is the bottleneck: htb 10 Mbit + netem 15 ms
# Flows (a -> b):
#     bulk TCP to :5001      — saturates the bottleneck
#     UDP echo probe :5405  — "corosync" (candidate priority port)
#     UDP echo probe :7999  — control flow, never prioritized
#     TCP echo probe :22    — "ssh"
#     ICMP ping             — control flow, never prioritized
# Scenarios (in order):
#     base       no bulk, one class           -> reference RTT (~16 ms)
#     bloat      bulk, one deep-FIFO class    -> every flow shares the queue
#     prio-port  bulk, 2 classes; dport 5405/22 -> priority class
#     prio-dscp  bulk, 2 classes; DSCP EF 0xb8 -> priority class
#
# Output: ./tc-prio-demo-<timestamp>/ (per-flow logs, tc stats, results.tsv)
#         plus a summary table on stdout.

set -euo pipefail
export LC_ALL=C

[ "$(id -u)" -eq 0 ] || { echo "must be root (needs CAP_NET_ADMIN for netns + tc)" >&2; exit 1; }
command -v tc >/dev/null || { echo "tc not found (iproute2 required)" >&2; exit 1; }
command -v ip >/dev/null || { echo "ip not found (iproute2 required)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/qoslib" && pwd)"
[ -f "$LIB_DIR/probe_client.py" ] || { echo "missing $LIB_DIR/probe_client.py" >&2; exit 1; }

NS_A=qosdemo-a
NS_B=qosdemo-b
DEV_A=qosdemo-a0
DEV_B=qosdemo-b0
A_IP=10.9.0.1
B_IP=10.9.0.2

RATE=10mbit          # bottleneck capacity
DELAY=15ms           # one-way delay added at the bottleneck (RTT ~30 ms)
PRIO_RATE=256kbit    # guaranteed rate of the priority class (way more than
                     # corosync + ssh need; ceil lets it burst to full RATE)
BULK_LIMIT=1000      # bulk queue depth in packets (~1.5 MB -> seconds of bloat)
PRIO_LIMIT=100       # priority queue depth in packets (shallow on purpose)
BULK_T=28            # bulk duration, s
PROBE_T=20           # probe duration under load, s
BASE_T=8             # probe duration for the idle reference, s
PROBE_INT=0.05       # probe interval, s (20 pps)
WARMUP=3             # bulk pre-fill before probes start, s

OUT="$(pwd)/tc-prio-demo-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  sleep 0.3
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT

info() { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
tcA() { ip netns exec "$NS_A" tc "$@"; }
exeA() { ip netns exec "$NS_A" "$@"; }
exeB() { ip netns exec "$NS_B" "$@"; }

# ── topology ──────────────────────────────────────────────────────────
info "creating namespaces $NS_A / $NS_B with a veth pair"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$DEV_A" type veth peer name "$DEV_B"
ip link set "$DEV_A" netns "$NS_A"
ip link set "$DEV_B" netns "$NS_B"
ip -n "$NS_A" addr add "$A_IP/24" dev "$DEV_A"
ip -n "$NS_B" addr add "$B_IP/24" dev "$DEV_B"
ip -n "$NS_A" link set "$DEV_A" up
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set "$DEV_B" up
ip -n "$NS_B" link set lo up
if command -v ethtool >/dev/null; then
  exeA ethtool -K "$DEV_A" tso off gso off gro off 2>/dev/null || true
  exeB ethtool -K "$DEV_B" tso off gso off gro off 2>/dev/null || true
else
  echo "note: no ethtool — offloads stay on, queue depths are in GSO super-packets"
fi

# ── servers ───────────────────────────────────────────────────────────
exeB python3 "$LIB_DIR/probe_server.py" --udp 5405 7999 --tcp 22 >"$OUT/probe-server.log" 2>&1 &
PIDS+=($!)
exeB python3 "$LIB_DIR/bulk_sink.py" 5001 >>"$OUT/bulk-sink.log" 2>&1 &
PIDS+=($!)
sleep 1
exeA ping -c 2 -W 1 "$B_IP" >/dev/null
info "topology up (bottleneck: $RATE, one-way $DELAY, bulk queue ${BULK_LIMIT} pkt)"

# ── qdiscs ────────────────────────────────────────────────────────────
# NOTE: htb does not support the change op, so `tc qdisc replace` on an
# already-installed root fails with "Change operation not supported by
# specified qdisc". Always rebuild from a clean slate: del root, then add.
qdisc_bloat() {
  tcA qdisc del dev "$DEV_A" root 2>/dev/null || true
  tcA qdisc add dev "$DEV_A" root handle 1: htb default 10
  tcA class add dev "$DEV_A" parent 1: classid 1:10 htb rate "$RATE" ceil "$RATE" burst 64k cburst 64k
  tcA qdisc add dev "$DEV_A" parent 1:10 handle 10: netem delay "$DELAY" limit "$BULK_LIMIT"
}

qdisc_prio() { # $1 = port | dscp
  tcA qdisc del dev "$DEV_A" root 2>/dev/null || true
  tcA qdisc add dev "$DEV_A" root handle 1: htb default 20
  tcA class add dev "$DEV_A" parent 1: classid 1:10 htb rate "$PRIO_RATE" ceil "$RATE" burst 16k cburst 16k
  tcA class add dev "$DEV_A" parent 1: classid 1:20 htb rate 9750kbit ceil "$RATE" burst 64k cburst 64k
  tcA qdisc add dev "$DEV_A" parent 1:10 handle 10: netem delay "$DELAY" limit "$PRIO_LIMIT"
  tcA qdisc add dev "$DEV_A" parent 1:20 handle 20: netem delay "$DELAY" limit "$BULK_LIMIT"
  case "$1" in
    port)
      tcA filter add dev "$DEV_A" parent 1: protocol ip prio 1 u32 \
        match ip protocol 17 0xff match ip dport 5405 0xffff flowid 1:10
      tcA filter add dev "$DEV_A" parent 1: protocol ip prio 1 u32 \
        match ip protocol 6 0xff match ip dport 22 0xffff flowid 1:10
      ;;
    dscp)
      tcA filter add dev "$DEV_A" parent 1: protocol ip prio 1 u32 \
        match ip tos 0xb8 0xfc flowid 1:10
      ;;
  esac
}

# ── traffic ───────────────────────────────────────────────────────────
PP=()
run_probes() { # <label> <duration> <tos-5405> <tos-22>
  local label="$1" dur="$2" tos5="${3:-0}" tos22="${4:-0}"
  local n
  n=$(awk -v d="$dur" -v i="$PROBE_INT" 'BEGIN{printf "%d", d / i}')
  exeA python3 "$LIB_DIR/probe_client.py" --dst "$B_IP" --port 5405 --proto udp \
    --duration "$dur" --interval "$PROBE_INT" --tos "$tos5" --scen "$label" \
    >"$OUT/udp5405-$label.txt" 2>&1 &
  PP+=($!)
  exeA python3 "$LIB_DIR/probe_client.py" --dst "$B_IP" --port 7999 --proto udp \
    --duration "$dur" --interval "$PROBE_INT" --scen "$label" \
    >"$OUT/udp7999-$label.txt" 2>&1 &
  PP+=($!)
  exeA python3 "$LIB_DIR/probe_client.py" --dst "$B_IP" --port 22 --proto tcp \
    --duration "$dur" --interval "$PROBE_INT" --tos "$tos22" --scen "$label" \
    >"$OUT/ssh22-$label.txt" 2>&1 &
  PP+=($!)
  exeA ping -i "$PROBE_INT" -c "$n" "$B_IP" >"$OUT/ping-$label.txt" 2>&1 &
  PP+=($!)
}

wait_probes() {
  local p
  for p in "${PP[@]:-}"; do wait "$p" || true; done
  PP=()
}

collect() { # <label>
  grep -h '^RESULT' "$OUT/udp5405-$1.txt" "$OUT/udp7999-$1.txt" "$OUT/ssh22-$1.txt" \
    >>"$OUT/results.tsv" 2>/dev/null || true
  python3 "$LIB_DIR/pingstat.py" "$OUT/ping-$1.txt" "$1" >>"$OUT/results.tsv"
}

start_bulk() {
  exeA python3 "$LIB_DIR/bulk_send.py" "$B_IP" 5001 "$BULK_T" >"$OUT/bulk-send.log" 2>&1 &
  BPID=$!
}

# ── scenarios ─────────────────────────────────────────────────────────
info "scenario base: reference latency, no bulk"
qdisc_bloat
run_probes base "$BASE_T"
wait_probes
collect base
tcA -s qdisc show dev "$DEV_A" >"$OUT/qdisc-base.txt" 2>&1

info "scenario bloat: bulk + single deep FIFO class (the 'before')"
qdisc_bloat
start_bulk
sleep "$WARMUP"
run_probes bloat "$PROBE_T"
wait_probes
wait "$BPID" || true
collect bloat
tcA -s qdisc show dev "$DEV_A" >"$OUT/qdisc-bloat.txt" 2>&1

info "scenario prio-port: bulk + 2 classes, dport 5405/22 -> priority"
qdisc_prio port
start_bulk
sleep "$WARMUP"
run_probes prio-port "$PROBE_T"
wait_probes
wait "$BPID" || true
collect prio-port
tcA -s qdisc show dev "$DEV_A" >"$OUT/qdisc-prio-port.txt" 2>&1

info "scenario prio-dscp: bulk + 2 classes, DSCP EF (0xb8) -> priority"
qdisc_prio dscp
start_bulk
sleep "$WARMUP"
run_probes prio-dscp "$PROBE_T" 0xb8 0xb8
wait_probes
wait "$BPID" || true
collect prio-dscp
tcA -s qdisc show dev "$DEV_A" >"$OUT/qdisc-prio-dscp.txt" 2>&1

# ── report ─────────────────────────────────────────────────────────────
echo
info "results"
{
  printf '%-10s %-8s %5s %5s %6s %8s %8s %8s %8s\n' \
    scenario flow sent recv loss% p50 p95 p99 max
  awk '$1 == "RESULT" {
    printf "%-10s %-8s %5s %5s %6s %8s %8s %8s %8s\n",
      substr($2, 6), substr($3, 6), substr($4, 6), substr($5, 6),
      substr($6, 6), substr($7, 5), substr($8, 5), substr($9, 5), substr($10, 5)
  }' "$OUT/results.tsv"
}
echo
echo "bulk goodput (measured at the sink, one line per scenario):"
grep -h '^BULK' "$OUT/bulk-sink.log" 2>/dev/null || echo "  (none — see $OUT/bulk-sink.log)"

cat <<EOF

How to read it:
  base       ~16 ms everywhere (one-way $DELAY on the shaped egress; the
             return path is unshaped).
  bloat      bulk saturates the only class; every probe inflates to
             hundreds of ms (up to BULK_LIMIT packets deep). Lost replies
             stall the lock-step probes for their full 1 s window, so 'sent'
             collapses well below duration/interval — that is the same
             lock-step collapse a lost totem token inflicts on corosync.
  prio-port  udp5405 + ssh22 fall back to ~16 ms (port-matched priority
             class), udp7999 + icmp stay bloated. Bulk goodput unchanged
             (priority class borrows nothing while idle).
  prio-dscp same, but classification happens on the DSCP byte of the
             OUTER packet. This is the mechanism nylon will use: inner
             port match -> outer DSCP -> WAN qdisc (tc at the edge, or
             any DSCP-aware path). NOTE: today nothing in nylon copies
             inner priority to the outer DSCP — that is the feature.

  Files: $OUT
EOF
