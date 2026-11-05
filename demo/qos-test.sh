#!/bin/bash
# qos-test.sh — in-tunnel QoS baseline on the 3-node demo stand.
#
# What it does:
#   Replaces alice's eth0 qdisc (the stand's own bob-link shaping is re-created
#   on restore) with a test harness:
#
#     band 1:1 (prio band 0)  DSCP EF 0xb8  -> netem 15ms, shallow queue
#                              (empty until nylon learns to mark outer packets)
#     band 1:3 (prio band 2)  dst = bob     -> netem 600ms, an anti route-flip
#                              guard: via-bob must always lose against the
#                              bloated direct path
#     band 1:4 (prio band 3)  everything    -> htb 10 Mbit + netem 15ms with a
#                              300-packet queue: the bottleneck under test
#
#   Then, through the real nylon tunnel (alice -> charlie):
#     - iperf3 TCP bulk (saturates the bottleneck)
#     - UDP echo probe :5405  ("corosync")
#     - UDP echo probe :7999  (control, never prioritized)
#     - TCP echo probe :22     ("ssh")
#     - ICMP ping              (control)
#
#   All four flows ride the same encrypted outer UDP stream, so the WAN qdisc
#   cannot tell them apart — that is the whole point. Today nothing in nylon
#   mirrors inner priority onto the outer DSCP, so class 1:1 stays empty and
#   every probe bloats together with the bulk. After the priority feature
#   (config port match + outer DSCP marking) THIS SAME SCRIPT becomes the
#   acceptance test: udp5405 and ssh22 fall back to ~30 ms while udp7999 and
#   icmp stay bloated, and class 1:1 packets > 0 in tc -s class.
#
# Requirements: the demo stand up (./demo/up.sh), docker, kernel with
# sch_netem/sch_prio/sch_htb/cls_u32 (the stand itself already needs netem).
#
# Usage: ./demo/qos-test.sh [--keep-qdisc]
#   --keep-qdisc  leave the test qdisc on alice for manual inspection
#
# Output: demo/output/qos-<timestamp>/ + a summary table on stdout.

set -euo pipefail
export LC_ALL=C

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DEMO_DIR/lib.sh"

KEEP_QDISC=0
case "${1:-}" in
"") ;;
--keep-qdisc) KEEP_QDISC=1 ;;
*) die "usage: $(basename "$0") [--keep-qdisc]" ;;
esac

LIB_DIR="$REPO_ROOT/hack/qos/qoslib"
[ -f "$LIB_DIR/probe_client.py" ] || die "missing $LIB_DIR/probe_client.py"
require_cmd docker
load_env || die "demo/.env missing — run ./demo/up.sh first"

AC="$(container alice)"
BC="$(container bob)"
CC="$(container charlie)"
BOB_DOCKER="$(subnet_host_ip "$MESH_SUBNET" "$(host_octet bob)")"
CHARLIE_TUN="$(tunnel_ip charlie)"

RATE=10mbit          # bottleneck capacity on alice's egress
DELAY=15ms           # one-way delay on the direct alice-charlie path (RTT ~30 ms)
BULK_LIMIT=300       # bottleneck queue depth, packets (~450 KB -> up to ~360 ms)
BULK_T=28            # bulk duration, s
PROBE_T=15           # probe duration under load, s
IDLE_T=6             # probe duration for the idle reference, s
PROBE_INT=0.05       # probe interval, s (20 pps)
WARMUP=3             # bulk pre-fill before probes start, s
BOB_BAND_DELAY=600ms # anti route-flip guard, must lose vs the bloated direct path

OUT="$OUTPUT_DIR/qos-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

restore() {
  docker exec "$CC" pkill -f probe_server.py 2>/dev/null || true
  docker exec "$CC" pkill iperf3 2>/dev/null || true
  if [ "$KEEP_QDISC" = 0 ]; then
    info "restoring alice: dropping the test qdisc and restarting it (pre_up re-shapes bob's link)"
    docker exec "$AC" tc qdisc del dev eth0 root 2>/dev/null || true
    dc restart alice >/dev/null 2>&1 || true
    info "stand is reconverging — give the mesh ~a minute before demo/record.sh"
  else
    info "leaving the test qdisc on alice (to restore: docker exec $AC tc qdisc del dev eth0 root, then restart alice)"
  fi
}
trap restore EXIT

# ── sanity ────────────────────────────────────────────────────────────
for c in "$AC" "$BC" "$CC"; do
  docker inspect "$c" --format '{{.State.Running}}' 2>/dev/null | grep -q true \
    || die "container $c is not running — start the stand first: ./demo/up.sh"
done

docker exec "$AC" ping -c 2 -W 1 "$CHARLIE_TUN" >/dev/null 2>&1 \
  || die "alice cannot ping charlie through the tunnel — let the mesh converge and retry"

hop="$(nh alice)"
[ "$hop" = "charlie" ] || die "alice's next hop toward $TARGET_PREFIX is '${hop:-none}', expected 'charlie' — let the mesh converge and retry"

# ── helpers into containers + servers ──────────────────────────────────
docker cp "$LIB_DIR/probe_server.py" "$CC:/tmp/probe_server.py"
docker cp "$LIB_DIR/probe_client.py" "$AC:/tmp/probe_client.py"
docker cp "$LIB_DIR/pingstat.py" "$AC:/tmp/pingstat.py"
# a previous run may have left stale servers in charlie — make their ports free
docker exec "$CC" pkill -f probe_server.py 2>/dev/null || true
docker exec "$CC" pkill iperf3 2>/dev/null || true
sleep 0.3
docker exec -d "$CC" python3 /tmp/probe_server.py --udp 5405 7999 --tcp 22
docker exec -d "$CC" iperf3 -s

# ── test qdisc on alice ────────────────────────────────────────────────
info "installing the test qdisc on alice's eth0 (rate $RATE, one-way $DELAY, queue ${BULK_LIMIT} pkt)"
# Delete the root first: on the stand's existing prio root `tc qdisc replace`
# resolves to a change op (prio supports change), which KEEPS the old children
# and filters - the stand's own bob filter (flowid 1:2) would keep winning
# over ours and the 600ms guard band would never engage. htb, by contrast,
# does not support change at all - replacing an installed htb root fails
# outright (tc-prio-demo.sh hit exactly that).
docker exec "$AC" sh -c "
  tc qdisc del dev eth0 root 2>/dev/null;
  tc qdisc add dev eth0 root handle 1: prio bands 4 priomap 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 &&
  tc qdisc add dev eth0 parent 1:1 handle 10: netem delay ${DELAY} limit 100 &&
  tc qdisc add dev eth0 parent 1:3 handle 30: netem delay ${BOB_BAND_DELAY} &&
  tc qdisc add dev eth0 parent 1:4 handle 40: htb default 400 &&
  tc class add dev eth0 parent 40: classid 40:400 htb rate ${RATE} ceil ${RATE} burst 64k cburst 64k &&
  tc qdisc add dev eth0 parent 40:400 handle 41: netem delay ${DELAY} limit ${BULK_LIMIT} &&
  tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip tos 0xb8 0xfc flowid 1:1 &&
  tc filter add dev eth0 parent 1: protocol ip prio 2 u32 match ip dst ${BOB_DOCKER}/32 flowid 1:3
" || die "failed to install the test qdisc"

docker exec "$AC" tc qdisc show dev eth0 | grep -q netem || die "qdisc did not land"
sleep 3
hop="$(nh alice)"
[ "$hop" = "charlie" ] || die "next hop flipped to '$hop' right after shaping — aborting"

# ── probes ─────────────────────────────────────────────────────────────
PP=()
run_probes() { # <label> <duration>
  local label="$1" dur="$2" n
  n=$(awk -v d="$dur" -v i="$PROBE_INT" 'BEGIN{printf "%d", d / i}')
  docker exec "$AC" python3 /tmp/probe_client.py --dst "$CHARLIE_TUN" --port 5405 --proto udp \
    --duration "$dur" --interval "$PROBE_INT" --scen "$label" >"$OUT/udp5405-$label.txt" 2>&1 &
  PP+=($!)
  docker exec "$AC" python3 /tmp/probe_client.py --dst "$CHARLIE_TUN" --port 7999 --proto udp \
    --duration "$dur" --interval "$PROBE_INT" --scen "$label" >"$OUT/udp7999-$label.txt" 2>&1 &
  PP+=($!)
  docker exec "$AC" python3 /tmp/probe_client.py --dst "$CHARLIE_TUN" --port 22 --proto tcp \
    --duration "$dur" --interval "$PROBE_INT" --scen "$label" >"$OUT/ssh22-$label.txt" 2>&1 &
  PP+=($!)
  docker exec "$AC" ping -i "$PROBE_INT" -c "$n" "$CHARLIE_TUN" >"$OUT/ping-$label.txt" 2>&1 &
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
  docker exec -i "$AC" python3 /tmp/pingstat.py /dev/stdin "$1" <"$OUT/ping-$1.txt" >>"$OUT/results.tsv"
}

# ── idle reference ─────────────────────────────────────────────────────
info "idle reference (no bulk)"
run_probes idle "$IDLE_T"
wait_probes
collect idle

# ── loaded run ─────────────────────────────────────────────────────────
info "loaded: iperf3 TCP bulk through the tunnel + probes"
docker exec "$AC" iperf3 -c "$CHARLIE_TUN" -t "$BULK_T" >"$OUT/iperf.txt" 2>&1 &
IPID=$!
sleep "$WARMUP"
run_probes loaded "$PROBE_T"
wait_probes
wait "$IPID" || true
collect loaded

# ── diagnostics ─────────────────────────────────────────────────────────
docker exec "$AC" sh -c 'tc -s qdisc show dev eth0; echo; tc -s class show dev eth0' \
  >"$OUT/tc-stats.txt" 2>&1
hop="$(nh alice)"
FLIP_WARN=""
[ "$hop" = "charlie" ] || FLIP_WARN="WARNING: next hop flipped to '$hop' during the run — results are polluted; rerun"

mb="$(grep -oE '[0-9.]+ [MK]bits/sec' "$OUT/iperf.txt" | tail -1 || true)"

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
echo "bulk (iperf3 through the tunnel): ${mb:-see $OUT/iperf.txt}"
echo "EF band (class 1:1) packet counters:"
grep -E 'class .* 1:1 ' -A3 "$OUT/tc-stats.txt" || echo "  (none — see $OUT/tc-stats.txt)"
[ -n "$FLIP_WARN" ] && { echo; echo "$FLIP_WARN"; }

cat <<EOF

How to read it:
  idle    everything ~16 ms (one-way $DELAY on alice's egress; the return
          path through the bridge is unshaped) - the harness is healthy.
  loaded  BEFORE the QoS feature: all four flows bloat together because
          the encrypted outer stream hides the inner ports (udp5405 is
          statistically identical to udp7999); nothing marks outer packets
          EF yet, so class 1:1 stays empty. The UDP/TCP probes are
          lock-step, so every lost reply stalls them a full 1 s - 'sent'
          collapses to a fraction of duration/interval, exactly the way a
          lost totem token stalls corosync.
          AFTER the feature (priority_ports + outer DSCP mirroring):
          udp5405 + ssh22 fall back to ~16 ms, udp7999 and icmp stay
          bloated, and class 1:1 packets > 0.

  Files: $OUT
EOF
