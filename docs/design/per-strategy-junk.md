# Per-Strategy Junk — Design & Work Plan

Status: **implemented (stages 1–4; the vibe1 field gate pending)** · Branch: `feat/strategy-junk` (rebased on `main` with PR #8) · Scope: the sender-local junk stream (`jc`/`jmin`/`jmax` and `i1`–`i5`) becomes a property of the obf strategy carrying the connection.

Implementation record (commits on this branch):

- **Stage 1** `feat(obf): per-strategy junk resolution` — `state.StrategyJunkOf` (one strategy's effective junk, defaults folded per field, idempotently over raw or resolved maps); `state.EffectiveStrategyJunk` became the device-fallback resolver (agreed → obf default → none) and lost its error; the seal-time agreement error is gone (the rig config that failed now seals — pinned as the acceptance case); every strategy's i-specs validate through `device.ValidateObfSpec`.
- **Stage 2** `feat(device): the per-peer JunkSource hook` — `polyamide/device/junk.go` (JunkSpec, JunkSource, JunkLabeler, the chain cache, the spec-driven draw); `SendHandshakeInitiation` consults the hook BELOW the endpoint selection (the strategy adoption ordering); the i-chain parse is once per distinct spec; UAPI behaviour byte-identical without a hook.
- **Stage 3** `feat(core): per-strategy junk wiring` — `portFactory.JunkFor`/`JunkLabel` (device.JunkSource/JunkLabeler) with the per-strategy specs cached in `refreshGroups` (dispatch loop) and read under `f.mu` on the send path; `wireDevPeer` wires the hook, the drop paths unwire it; the UAPI dump surfaces `junk_hook`/`junk_strategy`/`junk_jc`/`junk_jmin`/`junk_jmax`/`junk_i1..i5` per peer next to the hop lines; the rotation and fallback journals name the junk; the deadlock-pattern test extends to the consult.
- **Stage 4** proof & docs — `interop/awgref`: a junk-free-knob nylon device with the hook driving the wire junk completes the handshake and exchanges data with the upstream reference (which drops the junk), and the session survives a live spec switch; `integration/strategy_junk_test.go`: random-mode rotations across strategies with different junk keep the session (no re-handshake) while data flows and the hook serves each strategy's own spec; `docs/guides/obfuscation.mdx` and `docs/reference/config.mdx` document per-strategy junk and the fallback rules.

Remaining: the vibe1 field gate (the original failing central.yaml under `strategy_mode: random`, ping surviving the switches, the journal showing the junk switching with the strategy).

## 1. Problem

The strategy model (PR #8) decides, per connection, WHICH obf strategy carries it
(`obf.strategy_mode`: fixed / random / trial). The junk emission, however, is still
resolved as ONE device-global configuration: `state.EffectiveStrategyJunk` requires
every strategy a node uses to agree on `jc`/`jmin`/`jmax` and the i-set, and
`obfDeviceIPC` renders the winner onto the polyamide device as device fields
(`device.junk`, `device.ipackets`). `SendHandshakeInitiation` then prepends the same
i-packets + `device.JunkPackets()` stream to every handshake toward every peer.

The field consequence (observed on the vibe1 rig):

```
obf strategies proactive_hopping and reactive_hopping define different jc (5 vs 1),
but the AWG 2.0 device emits one junk configuration toward every peer; strategies
used by the same node must agree (or leave the junk params unset in all but one of them)
```

What we want: the junk follows the strategy of the CARRYING connection — per peer, per
connection — with the WireGuard session surviving every strategy switch. Recreating the
device to swap its junk is not an option: it drops the session and forces a full
re-handshake, which is exactly the disruption the strategy hop exists to avoid.

The receiver is NOT a constraint. AWG classifies inbound packets by (obfuscated)
message type and silently drops everything it does not recognise
(`polyamide/device/receive.go`, `default: "unknown type" → continue`), so a stock AWG
peer — the interop reference included — already tolerates any junk stream we emit.
Junk is sender-local camouflage; the receiver never needed to know our `jc`.

The S/H dialect (`s1`–`s4`, `h1`–`h4`) is also NOT in scope: it is the mesh-wide
handshake dialect the receiver must parse; it stays uniform by construction.

## 2. Options

1. **Keep the created device's junk; recreate the device on hard connection loss.**
   Cheapest wire-wise, but a strategy switch after a hard loss costs a full session
   reset (re-handshake, route flap window) — it punishes exactly the recovery path
   that should be seamless.
2. **Extend polyamide UAPI** — allow re-setting the device junk live, or add per-peer
   junk knobs to the UAPI protocol. Rejected for now: it grows the UAPI surface we
   promised to keep stock-compatible, and per-peer knobs would drag peer-level state
   into a protocol whose peer section is WireGuard's.
3. **Controller prepend-hook (chosen).** Junk *parameters* live in the controller
   (they are strategy properties), the *bytes* are still produced by polyamide: a
   per-peer in-process hook — the exact pattern `device.HopSource` already
   established for port hopping — supplies the prepend stream for each handshake
   initiation. No UAPI line changes, no wire-format change.

Why 3 wins:

- **UAPI compatibility stays exactly what it is.** That compatibility buys: stock
  `awg`/`awg-quick` tooling keeps configuring our device unchanged; the awgref
  interop harness keeps pinning the wire format; a future re-sync of polyamide with
  upstream amnezia-wg-go stays mechanical (our patch surface does not grow).
- **The session survives every switch.** The device is never recreated; a strategy
  switch is an endpoint change (WireGuard roaming) plus a junk-parameter change.
- **Every emitted byte still comes from the audited polyamide code.** The controller
  supplies numbers and specs; it cannot invent a packet shape — the same stance as
  the port-hopping design's constraint C1 ("zero new packet types").
- **Additive and trivially unwirable.** `SetJunkSource(nil)` restores stock behaviour;
  if a blocker appears, we fall back to option 1 or escalate to option 2 with the
  hook contract already proven.

## 3. Design

### 3.1 polyamide: a per-peer `JunkSource` (the hook)

New file `polyamide/device/junk.go`, mirroring `hop.go`:

```go
// JunkSpec is a resolved sender-local junk configuration: the AWG J trio plus
// the i1..i5 packet specs ("" = unset). The zero value emits no junk.
type JunkSpec struct {
        Jc, Jmin, Jmax uint32
        I              [5]string
}

// JunkSource supplies the junk prepended to every handshake initiation toward
// one peer. Implemented by the nylon core (per-strategy junk). Implementations
// MUST be safe for concurrent use and fast (no I/O): called from the send path.
type JunkSource interface {
        JunkFor(peer *Peer) (JunkSpec, bool)
}

func (peer *Peer) SetJunkSource(src JunkSource) // nil = stock device knobs
```

`SendHandshakeInitiation` consults the hook; `(spec, ok == false)` falls back to the
device-global knobs (`device.ipackets` + `device.junk`), i.e. everything configured
through UAPI behaves exactly as before. A `ok == true` **zero** spec suppresses junk
for that peer — a junkless strategy must not leak the device fallback.

Two mechanical details inside `SendHandshakeInitiation`:

- **Ordering (required for correctness):** today the i/junk buffers are assembled at
  the top of the function, but the carrying endpoint — and with it the strategy
  adoption (`hopCarrying` → `NextHopEndpoint` → `adoptCurrent`) — is only selected
  later. The prepend assembly must move BELOW the endpoint selection, so the hook
  consult sees the strategy the very handshake it decorates belongs to (otherwise the
  first handshake after a fresh wire-up would speak the old/fallback junk).
- **i-chain caching:** the i-specs are parsed into `*obfChain` once per distinct
  spec string (small map on the Device, chains are immutable) — never per handshake.

The junk datagram generation (`JunkPackets`) stays device-side, driven by the spec's
trio — the controller never builds buffers.

`SendHandshakeResponse` carries no junk today and gains none (initiations only).

### 3.2 core: `portFactory` implements `JunkSource`

The per-peer hop controller already tracks the carrying connection's strategy
(`f.currentStrategy`, adopted on every draw/rotation). It resolves the junk live:

```go
func (f *portFactory) JunkFor(*device.Peer) (device.JunkSpec, bool)
```

- `ok = false` while no strategy carries the peer (bootstrap in flight, or the
  peer's endpoints are raw host:port — no factory exists at all) → device fallback.
- Otherwise: the spec of `f.currentStrategy`, resolved per-strategy with the
  obf-level defaults folded in (see 3.3) — even when zero (see 3.1).

Wiring: one line in `wireDevPeer` (next to `SetHop`/`SetHopExternal`), which covers
both wire-up paths — `ensurePortFactories` (config apply) and the `rewireStrategy`
pass in `reconcileLinks` (carrying strategy switched). Because `JunkFor` reads the
live `currentStrategy` under `f.mu` (the same lock discipline `NextHopEndpoint`
already follows: fast, no I/O, never the device net write lock), no extra state or
plumbing is needed on a strategy switch — the next handshake simply speaks the new
strategy's junk.

### 3.3 state: per-strategy resolution; the device knobs become the fallback

- New `StrategyJunkOf(m, obf, name)`: one strategy's effective junk — its own
  trio/i-set with the obf-level defaults inherited per field (`CentralObf.applyDefaults`
  already implements the fold). This replaces `EffectiveStrategyJunk` as the source
  of truth for strategy-carried peers.
- `EffectiveStrategyJunk` loses its error and becomes the **fallback resolver**: the
  agreed junk when every used strategy concurs (all today's valid configs), else the
  obf-level default junk, else none. `obfDeviceIPC` renders that fallback — the
  knobs a raw host:port peer (no strategy, no hook) receives, and what UAPI `get`
  reports.

| connection | junk emitted |
| --- | --- |
| peer carried by a strategy (hook wired) | the carrying strategy's resolved spec — zero spec = no junk |
| raw host:port peer / bootstrap window | device fallback (agreed → obf default → none) |

Configurations where strategies disagree were previously REJECTED at seal time, so
the fallback semantics introduce no regression — they only define behaviour for
newly-legal configs. Raw peers never had per-strategy junk (they had the one agreed
set); they keep the closest equivalent.

### 3.4 What deliberately does not change

- The S/H dialect stays mesh-wide (`obfDeviceIPC` renders it exactly as today).
- No UAPI lines are added, removed or reinterpreted; awg tooling and the golden UAPI
  tests are untouched.
- Junk rides the carrying endpoint and counts against its hop budget, as today.
- Wire format of junk itself (random datagrams sized `[jmin, jmax)`, i-packet
  obfuscation chains) — unchanged, still produced by polyamide.

## 4. Work stages & verification gates

Each stage lands green (build + full unit suites) before the next begins.

**Stage 1 — state: per-strategy junk resolution**
Files: `state/obf_strategy.go`, `state/config.go` (validator wiring), tests in
`state/hop_mode_test.go`, `state/obf_defaults_test.go`.
Gate: the rig config that failed (`proactive_hopping` jc=5 vs `reactive_hopping`
jc=1) now seals; per-strategy default inheritance is pinned; the old agreement
error is gone from tests and messages.

**Stage 2 — polyamide: the hook**
Files: `polyamide/device/junk.go` (new), `send.go` (consult + ordering move),
`polyamide/device/junk_test.go` (new).
Gate: unit tests cover — per-peer override, nil/unset fallback to device knobs,
zero-spec suppression, two peers with different sources emitting different streams,
i-chain cache reuse, and the send-path contract (mirroring `hop_test.go` fixtures).

**Stage 3 — core: wiring, fallback rendering, observability**
Files: `core/nylon_window.go` (`JunkFor` + `wireDevPeer`), `core/nylon_wireguard.go`
(fallback rendering + the "obf strategies applied" journal grows the fallback
semantics), nylon IPC status (`get=nylon`: carrying strategy + active junk next to
`HopStatus`).
Gate: unit tests — the junk spec follows `currentStrategy` across a rotation drawn
under random mode; the journal line; the fallback table of 3.3.

**Stage 4 — proof & docs**
- `interop/awgref` (tag `awg_ref_interop`): nylon device with a per-peer junk source
  emitting jc/jmin/jmax + i-packets toward the reference — the reference still
  completes the handshake and exchanges data (it drops the junk). This pins that
  hook-driven junk is wire-equivalent to device-driven junk.
- `integration/`: a rotation across strategies with DIFFERENT junk keeps the session
  (no device recreation) — data flows across the switch.
- Docs: `docs/guides/obfuscation.mdx`, `docs/reference/config.mdx` (junk is
  per-strategy; the fallback rules), this document's status line.
Field gate (vibe1): the original failing central.yaml runs; `strategy_mode: random`
hops between strategies with different junk; ping survives the switches; the journal
shows the junk switching with the strategy.

## 5. Compatibility matrix

| peer | before (PR #8) | after |
| --- | --- | --- |
| nylon, strategies agree on junk | agreed junk (device) | same bytes (hook serves the identical spec) |
| nylon, strategies disagree | config rejected at seal | carrying strategy's junk; session preserved across switches |
| stock AWG / awgref receiver | drops our junk | unchanged — junk shape is identical |
| raw host:port peer | agreed junk (device) | fallback (agreed → obf default → none) |
| `awg` UAPI tooling against our device | works | unchanged (no new lines) |

## 6. Risks & rollback

- **Send-path discipline.** `JunkFor` runs in `SendHandshakeInitiation`; the same
  contract as `HopSource` (fast, `f.mu` only, no device net write lock, no I/O).
  The existing deadlock-test pattern (`core/nylon_hop_deadlock_test.go`) extends to
  the new hook.
- **First-handshake window.** The very first initiation after a fresh wire-up uses
  the fallback until a strategy is adopted; the ordering fix in 3.1 closes it for
  every handshake after the draw. One fallback-decorated handshake at cold start is
  acceptable and journalled.
- **Fallback semantics for raw peers under disagreeing strategies** — documented in
  3.3; no regression surface (such configs never sealed before).
- **Rollback.** Unwire the hook (`SetJunkSource(nil)`) → stock behaviour; the stages
  are ordered so 1–2 are inert without 3. If the params-only hook proves
  insufficient in the field, option 2 (per-peer UAPI junk knobs) is the escalation
  path, reusing the same `JunkSpec` shape.
