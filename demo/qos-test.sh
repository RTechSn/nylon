#!/bin/bash
# qos-test.sh — in-tunnel QoS baseline on the 3-node demo stand.
#
# What it does:
#   Replaces alice's eth0 qdisc (the stand's own bob-link shaping is re-created
#   on restore) with a test harness:
#
#     band 1:1 (prio band 0)  DSCP EF 0xb8  -> netem 15ms, shallow queue
#                              (carries the priority_rules-matched flows: the
#                              rules mirror their classification onto the
#                              outer datagrams as DSCP EF)
#     band 1:3 (prio band 2)  dst = bob     -> netem 600ms, an anti route-flip
#                              guard: via-bob must always lose against the
#                              bloated direct path
#     band 1:4 (prio band 3)  everything    -> htb 10 Mbit + netem 15ms with a
#                              300-packet queue: the bottleneck under test
#
#   Then, through the real nylon tunnel (alice -> charlie):
#     - iperf3 TCP bulk (saturates the bottleneck)
#     - UDP echo probe :5405  ("corosync" — priority_rules: udp/5405 high)
#     - UDP echo probe :7999  (control, never prioritized)
#     - TCP echo probe :22     ("ssh" — priority_rules: tcp/22 high)
#     - ICMP ping              (control)
#
#   All four flows ride the same encrypted outer UDP stream. With the demo
#   configs' priority_rules (see generate-configs.sh) nylon classifies the
#   inner packets by protocol/port, orders them first within in-device
#   batches, and mirrors the classification onto the OUTER packets as DSCP
#   (EF for high) — so the WAN qdisc's class 1:1 carries the matched flows
#   past the bulk queue while the unmarked controls bloat with it.
#
# Requirements: the demo stand up (./demo/up.sh), docker, kernel with
# sch_netem/sch_prio/sch_htb/cls_u32 (the stand itself already needs netem).
#
# Usage: ./demo/qos-test.sh [--keep-qdisc] [--allow-no-rules]
#   --keep-qdisc      leave the test qdisc on alice for manual inspection
#   --allow-no-rules  record the before-state table on purpose (skips the
#                     rules precheck and downgrades its verdict to a note)
#
# Output: demo/output/qos-<timestamp>/ + a summary table on stdout.

set -euo pipefail
export LC_ALL=C

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DEMO_DIR/lib.sh"

KEEP_QDISC=0
ALLOW_NO_RULES=0
for arg in "$@"; do
  case "$arg" in
  --keep-qdisc) KEEP_QDISC=1 ;;
  --allow-no-rules) ALLOW_NO_RULES=1 ;;
  *) die "usage: $(basename "$0") [--keep-qdisc] [--allow-no-rules]" ;;
  esac
done

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

# ── QoS precheck: the stand must actually run the priority rules ──────
# The stand is three separately cached artifacts (checkout → image,
# checkout → configs, image ↔ configs) and every drift combination runs
# WITHOUT rules while looking healthy: an old binary parses the generated
# central.yaml leniently and drops its top-level priority_rules wholesale;
# a fresh binary over old configs simply has no rules anywhere. Both
# produce a confident-looking table with a 0-packet EF band. Refuse to
# spend two minutes measuring such a stand — the daemon's journal names
# the effective rule set, so assert it instead.
last_rule="$(docker logs "$AC" 2>&1 | grep -E 'priority rules (applied|cleared)' | tail -1 || true)"
if [ "$ALLOW_NO_RULES" != 1 ]; then
  case "$last_rule" in
  *"priority rules applied"*)
    info "qos precheck: $last_rule"
    ;;
  *)
    die "alice's daemon runs no priority rules — the stand is stale (old image and/or old configs); refusing to measure it.
  expected a 'priority rules applied ... source=central-global' line in the journal, found: ${last_rule:-nothing}
  rebuild the stand from the checkout you mean to test (from the repo root):
    git checkout feat/qos-priority && git pull
    docker compose --env-file demo/.env -f demo/docker-compose.yml -p nylon-demo down --remove-orphans
    ./demo/generate-configs.sh --force
    ./demo/up.sh
  (pass --allow-no-rules to record the before-state table on purpose)"
    ;;
  esac
else
  info "qos precheck skipped (--allow-no-rules): ${last_rule:-no priority-rules journal line}"
fi

# Name the binary the stand runs: dc() stamps the checkout's commit into
# the build and the daemon logs it at startup, so image-vs-checkout drift
# is visible before it costs a run.
stand_commit="$(docker logs "$AC" 2>&1 | grep -oE 'commit=[0-9a-f]+' | head -1 | cut -d= -f2 || true)"
here_commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
if [ -n "$stand_commit" ] && [ -n "$here_commit" ] && [ "$stand_commit" != "$here_commit" ]; then
  info "NOTE: the stand runs commit=$stand_commit but the checkout is $here_commit — ./demo/up.sh rebuilds from this tree"
elif [ -z "$stand_commit" ]; then
  info "NOTE: the stand's binary carries no commit stamp — bring it up via ./demo/up.sh to make drift visible"
fi
echo "journal: ${last_rule:-none}; stand_commit=${stand_commit:-unknown}" >"$OUT/qos-precheck.txt"

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
install_test_qdisc() {
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
  " && docker exec "$AC" tc qdisc show dev eth0 | grep -q netem
}

# One retry: a `docker restart` racing the install (exec into the dying
# namespace, verify in the fresh one) leaves netem invisible even though
# every tc command returned 0 - the second attempt lands in the settled
# container.
qdisc_ok=0
attempt=1
while [ "$attempt" -le 2 ]; do
  if install_test_qdisc; then
    qdisc_ok=1
    break
  fi
  if [ "$attempt" -eq 1 ]; then
    info "qdisc did not land (attempt 1/2) — retrying in 3s (a container restart can race the install)"
    sleep 3
  fi
  attempt=$((attempt + 1))
done
[ "$qdisc_ok" -eq 1 ] || die "qdisc did not land on $AC after 2 attempts — the container may be mid-restart; wait a few seconds and re-run"
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

# ── verdict ───────────────────────────────────────────────────────────
# Judge the run instead of trusting the eye: a bulk that ran with a
# 0-packet EF band is the before-state signature (no marking reached the
# wire), and with the rules active the matched flows must separate from
# the unmarked controls. Everything is derived from files in $OUT.
ef_pkt="$(awk '/class prio 1:1 /{f=1; next} f && /^ Sent /{print $4; exit}' "$OUT/tc-stats.txt" 2>/dev/null || true)"
p50_of() { # <scenario> <flow> — that flow's p50 in ms from results.tsv, empty when absent
  awk -v sc="scen=$1" -v fl="flow=$2" '
    $1 == "RESULT" && $2 == sc && $3 == fl {
      for (i = 4; i <= NF; i++)
        if ($i ~ /^p50=/) { sub(/^p50=/, "", $i); print $i; exit }
    }' "$OUT/results.tsv" 2>/dev/null || true
}
i5="$(p50_of idle udp5405)"
l5="$(p50_of loaded udp5405)"
l22="$(p50_of loaded tcp22)"
l7="$(p50_of loaded udp7999)"
verdict="$(awk -v ef="${ef_pkt:-}" -v bulk="${mb:-}" -v i5="${i5:-}" -v l5="${l5:-}" -v l7="${l7:-}" 'BEGIN {
  if (bulk == "") { print "nobulk"; exit }
  if (ef !~ /^[0-9]+$/ || ef + 0 == 0) { print "before"; exit }
  if (i5 !~ /^[0-9.]+$/ || i5 + 0 > 100) { print "unhealthy-idle"; exit }
  if (l7 !~ /^[0-9.]+$/) { print "pass"; exit } # control starved entirely: nothing to compare against
  if (l5 !~ /^[0-9.]+$/ || l5 + 0 >= l7 / 2) { print "nosep"; exit }
  print "pass"
}')"
echo "verdict=$verdict ef=${ef_pkt:-0} p50_udp5405=${l5:-?} p50_ssh22=${l22:-?} p50_udp7999=${l7:-?}" >"$OUT/verdict.txt"
case "$verdict" in
pass)
  echo "✓ PASS: EF band carried ${ef_pkt:-0} marked packets; udp5405 p50 ${l5:-?} ms and ssh22 p50 ${l22:-?} ms vs unmarked udp7999 p50 ${l7:-?} ms under load"
  ;;
before)
  echo "✗ FAIL (before-state signature): the bulk ran (${mb:-?}) but the EF band (class 1:1) carried 0 packets — no priority marking reached the wire."
  if [ "$ALLOW_NO_RULES" = 1 ]; then
    echo "  (--allow-no-rules: recorded as the before-state table on purpose)"
  else
    echo "  The precheck passed, so the daemon loaded rules yet nothing was marked —"
    echo "  inspect $OUT/tc-stats.txt (filters/classes) and alice's journal, then re-run."
    exit 1
  fi
  ;;
nosep)
  echo "✗ FAIL: marking reached the wire (${ef_pkt} EF packets) but udp5405 p50 ${l5:-?} ms did not separate from udp7999 p50 ${l7:-?} ms — check $OUT/tc-stats.txt"
  exit 1
  ;;
unhealthy-idle)
  echo "✗ FAIL: the idle reference measured ${i5:-no} ms — expected the one-way $DELAY plus an unshaped return (~16-25 ms); the host is too busy or the harness is broken, rerun when it is quiet"
  exit 1
  ;;
nobulk)
  echo "✗ FAIL: no iperf3 throughput recorded — the bulk never ran; see $OUT/iperf.txt"
  exit 1
  ;;
esac

cat <<EOF

How to read it:
  idle    everything ~16 ms (one-way $DELAY on alice's egress; the return
          path through the bridge is unshaped) - the harness is healthy.
  loaded  WITH the demo configs' priority_rules: udp5405 + ssh22 fall back
          to ~16 ms (inner port match -> outer DSCP EF -> class 1:1),
          udp7999 and icmp stay bloated with the bulk (unmarked), and
          class 1:1 packets > 0. Without the rules all four flows bloat
          together because the encrypted outer stream hides the inner
          ports. The UDP/TCP probes are lock-step, so every lost reply
          stalls them a full 1 s - 'sent' collapses to a fraction of
          duration/interval, exactly the way a lost totem token stalls
          corosync.

  Files: $OUT
EOF
