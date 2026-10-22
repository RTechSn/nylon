# Port Hopping & Multi-Flow Transport — Design Document

Status: **stage 1 implemented** (ranges + rotation + range listening; see
`integration/port_hopping_test.go` for the verification gate) · Branch: `main` · Scope: Stages 1–3 (+ Stage 4 outlook)

## 1. Background & Threat Model

nylon (this fork) already reshapes its WireGuard traffic with an AmneziaWG 2.0-compatible
obfuscation layer (`jc`/`jmin`/`jmax`, `s1`–`s4`, `h1`–`h4`, `i1`–`i5`). That defeats
signature-based DPI. It does **not** defeat volume- and port-based blocking, which is how
TSPU-class middleboxes actually kill UDP tunnels in practice:

| Behaviour | Observed effect | Implication for us |
| --- | --- | --- |
| **Fast per-flow volume ban** | A UDP flow identified by its 5-tuple passes only the first ~16–20 packets / a few KB (empirical; anything past the handshake round-trip counts as delivered). Then the flow is dropped. | Rotate the destination port *before* the budget is exhausted. Everything sent before the cut-off is delivered; we simply move to the next port. |
| **Periodic per-port bans** | Individual (ip, port) destinations go dark for minutes at a time, regardless of volume. | Pick ports randomly from a wide range, exclude recently used ports, and re-try handshakes on a fresh port. |
| **5-tuple flow identity** | The middlebox tracks (src ip, src port, dst ip, dst port, proto). Changing *either* side's port creates a new, fresh-budget flow. | Both dst-port rotation (Stages 1–2) and extra client source ports (Stage 3) reset the budget. |
| **Reverse-path budget** | The server→client direction is a flow too (server src port = the port the client sent to). | Rotation of the client's dst port automatically rotates the server's reply src port, refreshing both directions at once. |

The goal is a tunnel that survives this environment **without adding a single byte of
non-AWG-shaped traffic** — a previous proof of concept built on udp2raw worked but injected
its own keepalives, which both burned the per-flow budget and produced packets that the AWG
profile never describes. This design keeps *everything* inside the existing WireGuard/AWG
data path.

## 2. Goals, Non-Goals & Hard Constraints

**Goals**

1. **Stage 1** — a target node may be configured with a *port range*; each new connection
   (and each proactive rotation) picks a random port from the range. Single-port endpoints
   keep working unchanged.
2. **Stage 2** — a target node may be configured with *multiple* `IP:port-range` endpoints.
3. **Stage 3** — `num_connections` parallel flows to one node with `num_stagger` spacing;
   passive (no-injected-packet) liveness detection per flow; seamless switchover when a
   flow dies, so an active transfer never pauses.
4. **Stage 4 (later)** — auto-tune `num_connections`, stagger and rotation budget from
   measured per-flow loss in real time.

**Non-goals (for now)**

- No new wire protocol, no change to the AWG 2.0 wire format or the `s/h/j/i` semantics.
- No TCP transport, no udp2raw-style outer framing.
- No multiple WireGuard sessions between the same pair of nodes (see §4.4).

**Hard constraints**

- **C1 — AWG compatibility is inviolable.** Every packet we emit must be a packet the
  polyamide device already knows how to produce (transport data, keepalive, handshake
  messages, junk packets, I-packet camouflage). Port hopping introduces *zero* new packet
  types. Junk/I-packets of a handshake count toward the per-port budget, because they are
  real wire packets (they already do today).
- **C2 — Stock-peer interop where possible.** A stock (upstream-nylon or vanilla-polyamide)
  peer with a single-port endpoint must still interoperate with a range-listening node, and
  range-configured clients must degrade gracefully to a single port against a stock server.
  (Interop with *stock WireGuard clients* is only available on the vanilla-compat obf
  profile — unchanged by this work.)
- **C3 — The router side runs on a dedicated Linux VM.** We may use privileged listening
  modes (many sockets, `RLIMIT_NOFILE`, optional netfilter DNAT) on routers. Client nodes
  stay unprivileged and portable.
- **C4 — One WireGuard session per peer pair.** Port/flow changes must never force a new
  handshake, rekey, or session-key change.

## 3. What the Codebase Already Gives Us

The study of the current tree (polyamide + core + state) produced these load-bearing facts:

1. **WireGuard sessions are port-agnostic.** Transport packets are decrypted by receiver
   index, handshakes by public key; the UDP 4-tuple is not part of session identity. A peer
   may roam addresses mid-session — this is exactly how mobile clients work today.
   Anti-replay window is 8128 packets, so mild reordering across parallel flows is harmless.
2. **Multi-endpoint peers already exist.** `Peer.SetEndpoints([]conn.Endpoint)` keeps an
   ordered list; `endpoints.val[0]` is the default for data, and `SendHandshakeInitiation`
   already *round-robins* handshake attempts across the list (`lastInitIndex`), sending the
   AWG junk + I-packets + initiation to the same selected endpoint. Handshake responses and
   cookie replies go to the exact source they came from.
3. **Endpoint failover is a nylon-layer concern.** Active probes (`Ny_Probe` ping/pong,
   real obfuscated WG packets, 1 s cadence) feed RTT/loss EWMA per link; nylon re-sorts
   `SetEndpoints` best-first. Passive per-peer RX time (`peer.timers.lastReceived`) and
   handshake-staleness demotion also exist.
4. **Per-buffer routing exists in the send path.** `Peer.SendBuffers(buffers, eps)` accepts
   a per-buffer endpoint slice (used by nylon control packets via `TCElement.ToEp`), so a
   flow-striping policy can be inserted without changing the queue architecture.
5. **The bind is pluggable and the tests are virtual.** `conn.Bind` implementations are
   injected; the integration/e2e harness runs the whole stack over in-memory
   `VirtualNet` binds — ideal for emulating TSPU budget-blocking in CI.
6. **Endpoint resolution is single-port today.** `EndpointResolver` returns one
   `netip.AddrPort`, `parseEndpoint` accepts `host`, `ip`, `host:port` (+SRV), and
   `handleProbePing/Pong` match links by *exact* `AddrPort` equality. These are the places
   ranges must be threaded through.

## 4. Design

### 4.1 Configuration surface

Ranges live directly in `endpoints`; single ports remain valid (C2):

```yaml title="central.yaml"
routers:
  - id: gw
    endpoints:
      - 203.0.113.10:30000-40000   # range (Stage 1)
      - 198.51.100.7:57175         # classic single port, unchanged
      - gw.example.org:50000-60000 # range with DNS name (Stage 2)
```

```yaml title="node.yaml (router VM)"
port: 57175              # primary port; required as today
listen_ports: 30000-40000  # optional additional bind range (router side)
```

Client-side (hopping) policy is local to `node.yaml` so the censored node can tune itself
without a central round-trip:

```yaml title="node.yaml (client side, Stage 1/3)"
port_hopping:
  enabled: true            # implied when any peer endpoint is a range
  budget_packets: 12       # rotate dst port after N packets sent on one flow
  recent_ports: 64         # do not reuse the last N chosen ports
  num_connections: 1       # Stage 3 (default 1 = Stage 1 behaviour)
  num_stagger: 0ms         # Stage 3: delay between activating flows
  stall_timeout: 1500ms    # Stage 3: passive dead-flow detection window
```

`nylon-genesis` learns to emit range endpoints and sane defaults for these knobs.
Defaults: `budget_packets` below the empirical 16–20 threshold; the exact value is a
tunable because the real threshold varies by network and must be probed (§7).

### 4.2 New components

**`conn.RangeBind`** — a multi-socket `Bind` used by any node that listens on a range.

- `Open(port)` keeps today's semantics for the primary port; a range is opened via a new
  device-level setting (UAPI `listen_ports=a-b`, applied next to `listen_port`). Each port
  in the range gets one UDP socket per address family (v4/v6 as available), each socket
  contributing one `ReceiveFunc` — the device already runs one receive goroutine per
  `ReceiveFunc`, so no device changes are needed for receive.
- **Reply-port correctness (the NAT rule):** a reply must leave from exactly the port the
  peer's last packet was addressed to. Each receive function knows its local port and tags
  the endpoints it produces with that port (`srcPort` hint on the endpoint struct).
  `RangeBind.Send(bufs, ep)` selects the socket by the endpoint's `srcPort` hint, falling
  back to the primary port when absent (fresh flows the peer hasn't answered yet).
- **Scale:** the simple mode binds N sockets. Sockets are cheap; descriptors are the limit:
  the daemon raises `RLIMIT_NOFILE` to the hard cap and refuses ranges beyond a config
  ceiling (default 4096 ports) with a clear error. For wider ranges (10k–60k) the
  documented escape hatch is **DNAT mode**: nylon prints (or installs, if `--manage-firewall`
  is given) one netfilter rule redirecting the range to the primary port, and continues to
  run single-socket. Under DNAT the kernel's conntrack performs the reply-port rewriting,
  so correctness is preserved; the cost is the conntrack dependency and per-flow state in
  the kernel (fine on a dedicated router VM, and it is what the sing-box/Amnezia ecosystem
  does today). An epoll-muxed single-poller variant of `RangeBind` is a possible later
  optimization; it is not needed for the initial ceiling.
- Client nodes also use `RangeBind` in Stage 3 with `num_connections` source ports.

**`conn.RangeEndpoint`** — a stateful endpoint type for `ip:portA-portB` destinations,
created by `RangeBind.ParseEndpoint` and owned by the peer's endpoint list.

- Carries `(ip, portA, portB)` plus an embedded **hop controller** (atomics only):
  current port, packets-sent-on-current-port, recent-port ring, per-flow RX bookkeeping
  hooks (Stage 3).
- The controller is what makes rotation a per-peer, per-flow policy without widening the
  `Bind`/`Send` interfaces: the endpoint object itself flows through
  `SendBuffers` → `Send`, so the policy travels with it. (Endpoints are re-created by
  nylon's periodic sync; the controller state is migrated by matching the range value, so
  syncs do not reset rotation state.)

**Rotation policy (client role, in `Peer.SendBuffers`)** — before batching, buffers are
assigned ports:

- If the destination endpoint is a `RangeEndpoint`, the controller assigns the *current*
  port to the batch; when the running packet count reaches `budget_packets`, it rotates
  (uniform random, excluding the last `recent_ports` choices) *mid-batch*, splitting the
  batch across the old and new port. All packet types count: data, keepalives, handshake
  retries, junk and I-packets of that handshake.
- `SendHandshakeInitiation` asks the controller for a *fresh* port per attempt instead of
  reusing `lastInitIndex` on a range endpoint — so each of the up-to-18 handshake retries
  (5 s apart) lands on a different port, which also defeats periodic per-port bans during
  (re)connect. Junk + I-packets + initiation continue to go to that single port so the
  AWG-shaped burst stays coherent (C1).
- Single-port endpoints and stock peers are untouched (C2): the controller is a no-op.

**Server role** is fully passive: receive on any port in range, reply from the same port,
track nothing per client. The server does not initiate rotation; it follows the client.
This keeps the router side stateless w.r.t. hopping and correct under CGNAT.

### 4.3 nylon-layer changes

- **`EndpointResolver`/`parseEndpoint`** learn `host:portA-portB`; resolution yields an
  `AddrPortRange` (addr + inclusive range). SRV keeps supplying a single port (range with
  SRV is rejected: ambiguous). DNS names resolve the host; the range applies verbatim.
- **`NylonEndpoint.Address`** keeps the raw string; matching in `handleProbePing/Pong`
  switches from exact `AddrPort` equality to *addr equality + port ∈ range* (with single
  ports as the degenerate range). Without this, a pong returning from a rotated port would
  be treated as an unknown link — this is a real correctness item, not polish.
- **Probe targeting:** `GetWgEndpoint` returns the (cached) `RangeEndpoint`; probes then
  ride the normal send path and consume rotation like any other packet. Probe RTT stats
  remain per-link (per endpoint entry), which is what Stage 2 failover uses.
- **Learned links (`remoteInit`)**: today every new source `addr:port` creates a new
  `NylonEndpoint`. With client source-port rotation (Stage 3) this would create spurious
  links; learned links are deduplicated per peer (update-if-exists, cap per peer) and are
  never treated as hop targets by the server.
- **IPC/status/observability** grow range-aware rendering and per-flow counters (see §8).

### 4.4 Stage 3 — demux (`num_connections`, `num_stagger`)

**Model: N UDP flows under one WireGuard session.** Multiple WG *sessions* between the same
pair are impossible without a protocol redesign (a polyamide peer is identified by its
public key; keypairs are unique per peer), so "connections" here are transport flows:
flow *i* = (client source port *i* → server port rotating per budget). All flows carry
packets of the *same* session; the server's `RangeBind` reply-port rule makes each flow's
reverse path follow automatically.

- **Striping.** Outbound batches are spread across active flows (longest-run round-robin:
  keep contiguous runs per flow to bound reordering; the 8128 replay window makes any
  residual reorder harmless, and inner TCP's RACK absorbs it). Keepalives when idle go out
  on the *primary* flow only — secondary flows intentionally go silent when there is
  nothing to protect, and re-warm with fresh rotated ports when data resumes (the primary
  is always warm, so there is no start-of-transfer pause).
- **Stagger.** Flow *i* begins carrying traffic at `t0 + i × num_stagger`. Spacing the
  first packets of each flow avoids presenting the middlebox with N simultaneous new flows
  to one IP (a correlation/fingerprint signal) and decorrelates their budget burn phases.
- **Passive liveness (no injected packets, per the requirement).** Per flow we track
  (atomics, updated in the receive path): last RX time, RX packet count, TX packet count.
  A flow is *suspect* when: TX ≥ B packets in the last `stall_timeout` window **and** zero
  RX on it in that window **and** some other flow to the same peer has RX in that window.
  The cross-flow comparison is what makes the test passive-only: if nothing was sent, or
  nothing anywhere is coming back (idle / full block / peer down), no flow is marked dead —
  that case belongs to nylon's existing probe/handshake-staleness machinery. A suspect flow
  is quiesced: dropped from striping, its port rotated; a replacement flow (new source
  port) is opened one `num_stagger` later. Suspects that start receiving again are
  reinstated. All state transitions are logged and counted.
- **Switchover is seamless by construction:** the WG session, inner TCP flows, Babel routes
  and nylon probes never notice a flow change — only the UDP 4-tuples move, and the striping
  layer already stopped using the dead flow the moment it was suspect.
- **Worst case, all flows dead:** fall back to the existing behaviour — handshake retries on
  fresh ports every 5 s (rotation already guarantees freshness), nylon link demotion and
  endpoint-group failover (Stage 2). A full re-handshake does not reset the tunnel.

### 4.5 Stage 4 outlook — adaptive tuning (explicitly deferred)

The user-visible goal is "cover the stream fully without pauses, automatically". Once
per-flow TX/RX counters and rotation events exist (Stage 3 instrumentation), adaptation is
a control loop on top:

- Estimate per-flow block threshold from observed (TX-since-last-RX) at failure instants →
  set `budget_packets` to ~75% of the empirical distribution (EWMA, per network).
- Port burn rate ≈ TX rate / budget → predict port-pool exhaustion; if the pool can't
  sustain the rate, *raise* budget (accept a tail loss per port, recovered by inner TCP)
  or increase range size — surfaced as a warning with the math.
- AIMD on `num_connections`: increase while stalls are detected, decay when flows sit idle
  receiving cleanly.
- Stagger adapts to measured inter-flow correlation of block events.

This is deliberately *not* in Stages 1–3: the primitives (counters, events, hooks) land
with Stage 3, the policy lands after real-world data exists.

## 5. Port-budget arithmetic (why wide ranges matter)

At a sustained 10 Mbps ≈ 800 pps and a 12-packet budget, the client burns ≈ 67 ports/s.
With TSPU port recovery measured in minutes (empirically ~5–10), a pure-streaming client
needs a pool of ~20k–40k ports to avoid recycling a still-banned port; smaller pools
degrade gracefully (recycled banned ports are caught by the passive detector / rotation,
costing a few lost packets per miss — inner TCP recovers, and Stage 4 tunes the budget to
trade tail loss against pool size). Guidance to be written into the docs with the formula,
not a magic number.

## 6. Stage Plan & Verification Gates

Each stage lands behind defaults that keep old configs byte-compatible, and **advancing
requires the gate to pass** (per project agreement).

**Stage 1 — ranges + client-side rotation**
- Config parsing/validation (`host:port-port`, `listen_ports`), resolver ranges, range-aware
  link matching, `RangeBind` (N-socket), `RangeEndpoint` + hop controller, budget rotation
  incl. mid-batch split, fresh port per handshake attempt, UAPI `listen_ports`.
- *Gate:* unit tests (parsing, rotation distribution/recent-exclusion, budget split);
  VirtualNet integration tests: two nodes, range endpoint, emulated middlebox that blocks a
  dst port after N packets — transfer of ≫ N×|range| packets completes without a session
  break (no new handshake in the log); stock single-port peer ↔ range listener interop
  passes the existing suites; `go test ./...` green.

**Stage 2 — multiple `IP:range` endpoints**
- Mostly exercising what exists: endpoints list + metric-ordered `SetEndpoints` +
  handshake rotation across groups; per-group probe stats; genesis emits multi-endpoint
  configs; dedupe learned links.
- *Gate:* integration test with two endpoint groups where group A's ports are hard-blocked
  after first use — mesh converges to group B within existing probe/demotion timings, no
  session break; e2e `resolution_test`/`passive_roaming` still green.

**Stage 3 — demux (`num_connections`, `num_stagger`)**
- Client `RangeBind` multi-source-port, striping in `SendBuffers`, staggered activation,
  passive per-flow liveness, suspect/reinstate lifecycle, keepalive policy, metrics/IPC.
- *Gate:* VirtualNet test with budget-emulating middlebox: continuous TCP throughput over
  the tunnel shows **no stall > stall_timeout** while flows are being killed underneath;
  a flow-kill timeline in logs matches the emulated blocks; idle period produces primary-
  flow-only keepalives (assert on packet counts per flow); race detector clean.

**Stage 4 — adaptive tuning** — separate design note once Stage 3 telemetry has
real-world data.

## 7. Risks & Open Problems

1. **Reply-port races.** Client rotates mid-flight; a few replies still leave from the old
   port. The client's NAT mapping for the old flow usually outlives the race, and WG
   tolerates the loss; worst case those replies die with the old flow. Accepted.
2. **Budget vs. AWG handshake weight.** `jc` junk + up to 5 I-packets + initiation ≈ 11 of
   a 16–20 budget on one port before any data. That is by design ("everything past the
   handshake is delivered"), but profiles with large `jc` shrink effective data per port;
   docs must state it, and Stage 4 can adapt.
3. **fd ceiling / DNAT trade-off.** N-socket mode is capped; DNAT mode adds conntrack
   dependency and kernel per-flow state (timeouts must exceed our keepalive cadence, or
   replies after idle break until the client speaks — mitigated by primary-flow keepalives).
   ICMP unreachable noise for unbound ports exists only in DNAT mode and needs a suppress
   rule (documented).
4. **CGNAT source-port remapping.** The server may see a new client source port per flow.
   Peer identity is cryptographic, and range-aware matching covers it; learned-link dedupe
   prevents link-table inflation. Verified in the Stage 3 gate with a NAT-ing VirtualNet.
5. **Middlebox correlation across flows.** N parallel flows to one IP is itself a signal;
   stagger mitigates timing correlation, AWG shaping keeps per-packet signatures
   non-WireGuard. Residual risk acknowledged; observable via block-event correlation
   telemetry (Stage 4 input).
6. **Port-range collisions on the router VM** (other services inside the range): validated
   at bind time (each socket bind fails loudly, naming the port); exclusions can be added
   later if needed.
7. **Cross-platform.** `RangeBind` uses plain `net.UDPConn`s (GSO/GRO only on Linux as
   today). Router = Linux (C3). Clients: Linux/macOS/Windows fine for the small
   `num_connections` socket sets; Windows remains best-effort as upstream.
8. **Unknown true TSPU thresholds.** 16–20 packets is empirical and network-specific; the
   design treats every threshold as a tunable plus (Stage 4) measured quantity, and the VM
   test plan (§8) includes a "probe the real budget" procedure for the target network.

## 8. Test & Verification Plan

- **CI (VirtualNet):** budget-emulating middlebox bind wrapper (drops after N packets per
  4-tuple, optional per-port hard-ban schedule, optional NAT/CGNAT remap) — the Stage 1–3
  gates above run against it deterministically.
- **Interop:** existing `awg_ref_interop` suite (upstream amneziawg-go reference device)
  extended with a range listener; stock-nylon peer cases.
- **VM testbed (router = dedicated Linux VM, per the agreed deployment):**
  - Emulated middlebox on the client VM's uplink via nftables `hashlimit`/`recent`
    (N-packets-per-dst-port) and tc netem loss/latency profiles.
  - Real-network probe run: measure the actual budget (binary-search the threshold with a
    small test client), calibrate `budget_packets`.
  - Soak test: iperf-class sustained transfer for hours; assert zero tunnel-level stalls
    beyond `stall_timeout`, collect rotation/port-recycle stats.
- **Observability:** per-flow counters (tx/rx packets, rotations, suspects, reinstatements,
  port-recycle misses), exposed via the existing promtext/IPC surfaces; a `nylon status`
  section showing each peer's flows and their health.

## 9. Compatibility Matrix (post-Stage 1–3)

| Pair | Result |
| --- | --- |
| fork ↔ fork, single-port endpoints | byte-identical to today (default `num_connections=1`, no range) |
| fork client (range) ↔ fork router (range) | full hopping |
| fork peer ↔ **stock upstream nylon** peer (either side) | works: range listener includes the stock port; range client against stock server degrades to that port (budget rotation disabled) |
| stock WireGuard client ↔ vanilla-compat profile mesh | unchanged (port hopping never activates for vanilla handshakes with stock clients — obf profile gates it exactly as today) |
| AWG options (`jc/jmin/jmax/s1–s4/h1–h4/i1–i5`) | unchanged semantics; no new wire bytes (C1) — verified by golden-vector + interop suites |
