package core

import (
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// hopTombstoneGrace is how long an exhausted (retired) link is kept in
// Neighbour.Eps so late probe pongs still match it, before the factory
// removes it. Exhausted links are never probed and never ranked, so they are
// pure bookkeeping.
const hopTombstoneGrace = 15 * time.Second

// hopDrawnRegistryCap is the default size of a factory's drawn-port registry
// (see portFactory.registerDrawn). ensurePortFactories raises it to
// max(4 x recent_ports, this) so the registry comfortably covers the recent
// ring plus the tombstone-grace horizon of the latest rotations.
const hopDrawnRegistryCap = 64

// hopProbeFraction scales LinkDeadThreshold into the probe interval for
// factory-managed links: the stock 1s probe cadence would burn a port's whole
// packet budget in seconds while idle. The interval stays below
// LinkDeadThreshold so a single lost pong cannot flap the link inactive.
const hopProbeFraction = 0.8

// hopRotationLogInterval bounds how often the per-rotation Info line is
// emitted. Under load the carrying port rotates every budget packets, which
// at iperf rates is hundreds of rotations per second: each rotation is logged
// at Debug, and at most one Info line per interval summarises them
// ("rotations" counts the rotations covered by the line).
const hopRotationLogInterval = time.Second

// hopReactiveProbeStreak is how many consecutive unanswered probe attempts
// on the carrying endpoint trigger a reactive rotation. The peer's own
// traffic (its probe pings riding the reverse flow) keeps the link IsActive
// while OUR direction to the port is blackholed — liveness alone cannot
// expose that, but our probes going unanswered does. Three consecutive
// timeouts (at the relaxed probe cadence that is roughly 6-8s) tolerates a
// single lost pong while still rotating inside a middlebox ban window.
const hopReactiveProbeStreak = 3

// hopPoolWarnInterval bounds how often the pool-exhaustion warning fires
// while rotation is stalled (every candidate port cooling down).
const hopPoolWarnInterval = time.Minute

// portFactory manages the dynamic endpoint window of one peer whose
// configured endpoints contain port ranges. It implements device.HopSource:
// every time the device send path exhausts a carrying port's packet budget,
// the factory draws a fresh endpoint from the port pool (maximally
// dissimilar to the current one — different IP/subnet preferred), retires the
// old port into cooldown, and records the transition for the next
// reconciliation pass.
//
// Link bookkeeping is deliberately NOT done on the rotation hot path. The
// budget defaults (12 packets) make sustained load rotate the carrying port
// hundreds of times per second; dispatching retire/materialise work per
// rotation would flood the dispatch loop, links would be born as tombstones
// (the pool retires synchronously, the dispatch lags), and the neighbour
// would briefly have no healthy endpoint at all. Instead:
//
//   - the send path only touches the pool (its own locking) and two factory
//     fields (under mu): current and prev;
//   - reconcileLinks, on the dispatch loop every SyncApplicationState pass
//     (1s), materialises the current carrying port as a link — seeded with
//     the predecessor's RTT so routes stay feasible across the rotation
//     without waiting for the first probe pong — and tombstones the
//     predecessor;
//   - ports drawn and abandoned between two passes ("intermediate" ports of a
//     rotation storm) never become links at all: nothing probes them, so
//     nothing needs to match them.
//
// The predecessor link stays healthy (and keeps the neighbour's routes
// feasible) until the successor is materialised, so routing never flaps on
// rotation; the seeded metric keeps the route cost continuous.
//
// Range endpoints are NEVER expanded into individual links at config time:
// the pool keeps runtime state O(window) instead of O(range), which is what
// makes production-sized ranges (tens of thousands of ports) viable.
type portFactory struct {
	n    *Nylon
	node state.NodeId

	// mu guards current, prev, candidates, bind, the rotation-policy fields and
	// the log-rate-limit fields; the pool has its own locking.
	mu         sync.Mutex
	candidates []hopCandidate // per (endpoint × strategy) draw candidates from the peer's config
	pool       *state.PortPool
	current    netip.AddrPort // the endpoint currently carrying traffic
	prev       netip.AddrPort // the endpoint retired by the latest rotation (seed source / tombstone candidate)
	// lastProbeAt is the last relaxed-cadence probe of the current link.
	lastProbeAt time.Time

	// policies maps every candidate's strategy to its resolved rotation
	// policy (per-strategy now — the knobs moved INTO the obf strategies).
	// The mode/period/jitter fields below mirror the CURRENT strategy's
	// policy; they are re-synced whenever the carrying candidate switches
	// strategy or the config refreshes.
	policies        map[string]state.PortHoppingPolicy
	currentStrategy string

	// rotation policy of the CURRENT carrying candidate's strategy (see
	// policies); the mode governs WHEN the carrying endpoint rotates
	mode       string        // static | reactive | proactive | timed
	period     time.Duration // timed: nominal rotation interval
	jitterPct  uint32        // timed: jitter as a percentage of period
	nextRotate time.Time     // timed: deadline of the next scheduled rotation (zero = not scheduled)
	// rotateReason decorates the next rotation's log line when the rotation
	// is externally driven (reactive/timed); consumed by logRotation.
	rotateReason string

	// rewireStrategy is set on the send path when a rotation lands the
	// carrying endpoint on a DIFFERENT strategy (whose mode/budget differ);
	// reconcileLinks (dispatch loop) performs the SetHop re-wiring.
	rewireStrategy string

	// devPeer is the device peer this factory serves, cached on the dispatch
	// loop (device peers are recreated on config re-applies). External
	// rotations (reactive/timed) are driven from the dispatch loop through
	// it, never from the send path.
	devPeer *device.Peer

	// rotation log rate limiting
	lastRotationLog time.Time
	rotationCount   uint64

	// recycle_seconds epoch bookkeeping (guarded by mu): how many carrying
	// endpoints were drawn since the last clean-slate restart and when it
	// happened; recycleMin (the resolved port_hopping.recycle_seconds) is
	// the rate limit between restarts. Every recycle journal line carries
	// the epoch as swept=/elapsed= so a restart is self-evidently preceded
	// by a FULL re-exhaustion of the range (swept ≈ range size) —
	// back-to-back lines without that context read like a recycle loop
	// while a ~500-rotation sweep silently unfolded between them (the
	// per-second rotation summary folds it away).
	recycleMin        time.Duration
	drawsSinceRecycle uint64
	lastRecycleAt     time.Time

	// drawnPort registry: every address this factory ever drew (bounded FIFO).
	// Tombstoning and the remote-link learning guard consult it IN ADDITION to
	// ownsEndpoint, whose address check re-resolves the range spec host
	// through the live resolver — a DNS answer change (dual-stack A/AAAA
	// round-robin, DDNS flip) would otherwise retroactively de-own every link
	// drawn under the old address, leaving retired links never tombstoned:
	// probed at the full 1s cadence and renewed by every pong forever (the
	// "every port ever used still shows tx/rx on the router" zombie).
	drawn      map[string]struct{}
	drawnOrder []string
	drawnCap   int

	// pool-exhaustion warn rate limiting
	lastPoolWarn time.Time

	// bind is the device bind, cached on the dispatch loop. Device.Bind()
	// takes the device net WRITE lock, while the packet send path
	// (Peer.SendBuffers) holds the SAME lock in READ mode whenever it calls
	// NextHopEndpoint — calling Device.Bind() there is a guaranteed
	// self-deadlock (the write lock can never be granted while the caller's
	// own read lock is held). The cache is refreshed on every
	// ensurePortFactories pass, so a BindUpdate (listen port change) is
	// picked up within one reconciliation tick.
	bind conn.Bind
}

// registerDrawn records an address this factory drew as a carrying endpoint
// (or pinned, in static mode). Bounded FIFO: the registry only needs to cover
// the live link window plus the grace/probe-timeout horizon of the latest
// rotations — tombstoning and stale-ping learning both concern links of the
// recent past, not ports drawn an hour ago.
func (f *portFactory) registerDrawn(ap netip.AddrPort) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.drawnCap <= 0 {
		f.drawnCap = hopDrawnRegistryCap
	}
	if f.drawn == nil {
		f.drawn = make(map[string]struct{})
	}
	if _, ok := f.drawn[ap.String()]; !ok {
		f.drawn[ap.String()] = struct{}{}
		f.drawnOrder = append(f.drawnOrder, ap.String())
	}
	for len(f.drawnOrder) > f.drawnCap {
		oldest := f.drawnOrder[0]
		f.drawnOrder = f.drawnOrder[1:]
		delete(f.drawn, oldest)
	}
}

// drewEndpoint reports whether the addr:port was ever drawn by this factory
// (see registerDrawn): such a link is by construction factory-owned, whatever
// the resolver currently answers for the spec host.
func (f *portFactory) drewEndpoint(ap netip.AddrPort) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.drawn == nil {
		return false
	}
	_, ok := f.drawn[ap.String()]
	return ok
}

// ownsOrDrew reports whether the addr:port belongs to this factory's link
// lifecycle: drawn by it at any point, or lying inside one of its currently
// configured ranges (see ownsEndpoint). The union — never the intersection —
// is what tombstoning and the learning guard need: a resolver flip must
// never exempt a previously drawn port, and a spec range change must still
// cover ports inside the new ranges.
func (f *portFactory) ownsOrDrew(ap netip.AddrPort) bool {
	return f.drewEndpoint(ap) || f.ownsEndpoint(ap)
}

// bindIfReady returns the cached device bind, or nil before the factory has
// been wired on the dispatch loop.
func (f *portFactory) bindIfReady() conn.Bind {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bind
}

// candidatePolicies collects the per-strategy resolved rotation policies of
// a candidate set.
func candidatePolicies(candidates []hopCandidate) map[string]state.PortHoppingPolicy {
	m := make(map[string]state.PortHoppingPolicy, len(candidates))
	for _, c := range candidates {
		m[c.strategy] = c.policy
	}
	return m
}

// candidatePoolConfig derives the pool hygiene configuration from a
// candidate set: the conservative MAXIMUM of the strategies' recent ring,
// cooldown and candidate-sample knobs (the pool is one object shared by all
// of the peer's strategies; the WHEN knobs — mode/budget/period — stay
// per-strategy).
func candidatePoolConfig(candidates []hopCandidate) state.PortPoolConfig {
	cfg := state.PortPoolConfig{
		Recent:   int(state.DefaultPortHoppingPolicy().Recent),
		Cooldown: state.DefaultPortHoppingPolicy().Cooldown,
		Samples:  int(state.DefaultPortHoppingPolicy().CandidateSamples),
	}
	for _, c := range candidates {
		if int(c.policy.Recent) > cfg.Recent {
			cfg.Recent = int(c.policy.Recent)
		}
		if c.policy.Cooldown > cfg.Cooldown {
			cfg.Cooldown = c.policy.Cooldown
		}
		if int(c.policy.CandidateSamples) > cfg.Samples {
			cfg.Samples = int(c.policy.CandidateSamples)
		}
	}
	return cfg
}

// hopCandidate is ONE (endpoint host × obf strategy) draw target: the host
// of a tagged (or untagged) peer endpoint, the strategy's parsed port range
// and that strategy's resolved rotation policy. The factory draws carrying
// endpoints across the whole candidate set; the policy in effect is the one
// of the CURRENT carrying candidate's strategy.
type hopCandidate struct {
	host     string
	ports    state.PortRange
	strategy string
	policy   state.PortHoppingPolicy
}

// candidatesOf returns a copy of the configured draw candidates.
func (f *portFactory) candidatesOf() []hopCandidate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.candidates)
}

// strategyForAp names the strategy whose candidate range contains ap
// (resolving the candidate hosts like ownsEndpoint); "" when no candidate
// matches (e.g. a stale link after a config change).
func (f *portFactory) strategyForAp(ap netip.AddrPort) string {
	for _, c := range f.candidatesOf() {
		addr, ok := f.resolveCandidateAddr(c)
		if !ok {
			continue
		}
		if addr.Unmap() == ap.Addr().Unmap() && c.ports.Contains(ap.Port()) {
			return c.strategy
		}
	}
	return ""
}

// currentPolicyLocked returns the resolved policy of the given strategy,
// falling back to the static default for unknown names (send-path safe:
// never blocks, never allocates beyond a lookup).
func (f *portFactory) policyOfLocked(strategy string) state.PortHoppingPolicy {
	if p, ok := f.policies[strategy]; ok {
		return p
	}
	// unknown (config removed the strategy mid-flight): behave statically
	return state.DefaultPortHoppingPolicy()
}

// syncStrategyLocked mirrors the given strategy's policy into the active
// rotation fields (mode/period/jitter/recycle) and re-arms the timed
// schedule when entering timed mode. Callers hold f.mu.
func (f *portFactory) syncStrategyLocked(strategy string, now time.Time) {
	p := f.policyOfLocked(strategy)
	modeChanged := f.mode != p.Mode || f.currentStrategy != strategy
	f.currentStrategy = strategy
	f.mode = p.Mode
	f.period = p.Period
	f.jitterPct = p.JitterPct
	f.recycleMin = p.RecycleMinInterval
	if modeChanged {
		if p.Mode == state.HopModeTimed {
			f.nextRotate = now.Add(jitterInterval(p.Period, p.JitterPct))
		} else {
			f.nextRotate = time.Time{}
		}
	}
}

func (n *Nylon) getPortFactory(peer state.NodeId, candidates []hopCandidate, poolCfg state.PortPoolConfig, wgPeer *device.Peer) *portFactory {
	// CAUTION: the device bind must be acquired BEFORE any factory lock. The
	// packet send path (Peer.SendBuffers) holds the device net lock in READ
	// mode across its whole body — including the factory mutex sections inside
	// NextHopEndpoint — so acquiring the net WRITE lock (Device.Bind) while
	// holding f.mu inverts the lock order against the send path:
	//
	//      dispatch loop:  f.mu -> net.WLock
	//      send path:      net.RLock -> f.mu
	//
	// Whenever the two align, the dispatch loop parks waiting for the write
	// lock that only the sender can grant (by dropping its read lock), while
	// the sender parks waiting for f.mu that the dispatch loop holds: a
	// permanent deadlock with an idle CPU. The window is microseconds in
	// steady state, but anything that keeps a sender inside its net READ lock
	// for longer (a pool-exhaustion scan, lock contention under a rotation
	// storm) widens it to near-certainty — and every dispatch after the freeze
	// is discarded, so no link is ever materialised again. Taking the bind
	// first, with no factory lock held, removes the inversion: the sender can
	// always finish its f.mu section and release the read lock.
	bind := n.Device.Bind()

	n.portHopping.mu.Lock()
	defer n.portHopping.mu.Unlock()
	if n.portHopping.factories == nil {
		n.portHopping.factories = make(map[state.NodeId]*portFactory)
	}
	f, ok := n.portHopping.factories[peer]
	if !ok {
		f = &portFactory{
			n:    n,
			node: peer,
			pool: state.NewPortPool(nil, poolCfg),
		}
		n.portHopping.factories[peer] = f
	}
	f.mu.Lock()
	f.candidates = slices.Clone(candidates)
	f.policies = candidatePolicies(candidates)
	// the pool hygiene knobs are the conservative maximum across the
	// candidate strategies (the pool is one object; the WHEN knobs stay
	// per-strategy through syncStrategyLocked)
	f.drawnCap = max(4*poolCfg.Recent, hopDrawnRegistryCap)
	// Refresh the bind cache on the dispatch loop (see the field comment: the
	// send path must never acquire the device net write lock). The bind was
	// acquired above, OUTSIDE every factory lock — see the CAUTION at the top
	// of this function.
	f.bind = bind
	strategy := f.currentStrategy
	if strategy == "" && len(candidates) > 0 {
		strategy = candidates[0].strategy
	}
	f.syncStrategyLocked(strategy, time.Now())
	f.devPeer = wgPeer
	// a live change of cooldown_seconds applies without a restart
	f.pool.SetCooldown(poolCfg.Cooldown)
	f.mu.Unlock()
	f.refreshGroups()
	f.bootstrap()
	f.reconcileLinks()
	return f
}

// bootstrap eagerly draws the first carrying endpoint for a fresh factory.
// Without it, a peer whose only configured endpoints are ranges would have no
// links at all, no feasible routes, and nothing staging a packet to trigger
// the lazy first draw — a chicken-and-egg deadlock on an otherwise idle node.
// It also kicks off hostname resolution for range specs (the shared resolver
// only refreshes addresses that appear as links, which range specs never do).
func (f *portFactory) bootstrap() {
	f.mu.Lock()
	hasCurrent := f.current.IsValid()
	f.mu.Unlock()
	if hasCurrent {
		return
	}

	// resolve any hostname candidates in the background, then refresh the pool
	// groups once results are cached (dispatch-loop safe)
	go func() {
		for _, c := range f.candidatesOf() {
			if _, err := netip.ParseAddr(c.host); err == nil {
				continue // literal, nothing to resolve
			}
			if _, err := f.n.EndpointResolver.Resolve(net.JoinHostPort(c.host, strconv.Itoa(int(c.ports.First))), f.n.EndpointResolveExpiry); err != nil {
				f.n.Log.Debug("port hop: failed to resolve strategy host", "peer", f.node, "host", c.host, "strategy", c.strategy, "error", err)
			}
		}
		f.n.Dispatch(func() error {
			if f.n.Context.Err() != nil {
				return nil
			}
			f.mu.Lock()
			fresh := !f.current.IsValid()
			f.mu.Unlock()
			if !fresh {
				return nil
			}
			f.refreshGroups()
			f.drawAndMaterialize()
			return nil
		})
	}()

	// literal-IP groups are already usable: draw immediately
	f.drawAndMaterialize()
}

// specStrings returns a copy of the configured candidate hosts as concrete
// first-port addresses (resolver warm-up targets).
func (f *portFactory) candidateHosts() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range f.candidatesOf() {
		target := net.JoinHostPort(c.host, strconv.Itoa(int(c.ports.First)))
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

// adoptCurrent syncs the active rotation fields to the strategy owning the
// given carrying endpoint (rotation across strategies) and flags the device
// peer for re-wiring when the strategy's mode/budget differ. Safe on both
// paths (send and dispatch): it only touches factory fields.
func (f *portFactory) adoptCurrent(ap netip.AddrPort) {
	strategy := f.strategyForAp(ap)
	f.mu.Lock()
	if strategy != "" && strategy != f.currentStrategy {
		f.syncStrategyLocked(strategy, time.Now())
		f.rewireStrategy = strategy
	}
	f.mu.Unlock()
}

// drawAndMaterialize draws a fresh carrying endpoint (if the pool has usable
// groups) and materialises its link, mirroring NextHopEndpoint without
// retiring anything. In static mode the draw is the pinned endpoint instead
// of a pool selection. Runs on the dispatch loop.
func (f *portFactory) drawAndMaterialize() {
	f.mu.Lock()
	mode := f.mode
	avoid := make([]netip.AddrPort, 0, 1)
	if f.current.IsValid() {
		avoid = append(avoid, f.current)
	}
	f.mu.Unlock()

	var ap netip.AddrPort
	if mode == state.HopModeStatic {
		pinned, ok := f.pinnedEndpoint()
		if !ok {
			// no candidate resolvable yet (hostname resolving): retried on
			// the next SyncApplicationState pass
			return
		}
		ap = pinned
	} else {
		drawn, err := f.pool.Select(avoid)
		if err != nil {
			// pool not ready (e.g. hostname still resolving): retried by the
			// background resolve above and the next SyncApplicationState pass
			return
		}
		ap = drawn
	}
	f.adoptCurrent(ap)
	f.mu.Lock()
	f.current = ap
	f.lastProbeAt = time.Now()
	f.drawsSinceRecycle++
	f.mu.Unlock()
	f.registerDrawn(ap)
	neigh := f.n.RouterState.GetNeighbour(f.node)
	if neigh == nil {
		return
	}
	f.materializeCarrying(neigh, ap, netip.AddrPort{})
	if mode == state.HopModeStatic {
		f.n.Log.Info("port hop: static carrying endpoint pinned", "peer", f.node, "endpoint", ap.String())
	} else {
		f.n.Log.Info("port hop: initial carrying endpoint selected", "peer", f.node, "endpoint", ap.String())
	}
}

// pinnedEndpoint returns the static-mode carrying endpoint: the first port
// of the first resolvable candidate (config order: endpoints first, then
// strategy order within an endpoint). The listen half serves every port of
// every strategy (sockets mode binds them all; nftables mode redirects them
// all), so the first port is always a valid wire target.
func (f *portFactory) pinnedEndpoint() (netip.AddrPort, bool) {
	for _, c := range f.candidatesOf() {
		addr, ok := f.resolveCandidateAddr(c)
		if !ok {
			continue
		}
		return netip.AddrPortFrom(addr, c.ports.First), true
	}
	return netip.AddrPort{}, false
}

// hopMode returns the factory's active rotation mode.
func (f *portFactory) hopMode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode
}

// dropPortFactory removes the factory for a peer whose config no longer
// carries ranges. Must be called on the dispatch loop.
func (n *Nylon) dropPortFactory(peer state.NodeId) {
	n.portHopping.mu.Lock()
	delete(n.portHopping.factories, peer)
	n.portHopping.mu.Unlock()
}

// refreshGroups re-resolves the configured candidates into pool groups
// (literal IPs parse directly; hostnames go through the shared resolver and
// follow its cache expiry).
func (f *portFactory) refreshGroups() {
	candidates := f.candidatesOf()

	groups := make([]state.PortGroup, 0, len(candidates))
	for _, c := range candidates {
		addr, ok := f.resolveCandidateAddr(c)
		if !ok {
			continue
		}
		groups = append(groups, state.PortGroup{Addr: addr, Ports: c.ports})
	}
	if !slices.EqualFunc(f.pool.Groups(), groups, func(a, b state.PortGroup) bool {
		return a.Addr == b.Addr && a.Ports == b.Ports
	}) {
		f.pool.SetGroups(groups)
	}
}

// resolveCandidateAddr resolves the host part of a candidate to an address.
func (f *portFactory) resolveCandidateAddr(c hopCandidate) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(c.host); err == nil {
		return addr.Unmap(), true
	}
	// hostname: resolve through the shared resolver by borrowing the first
	// port of the strategy range (materialised single-port addresses resolve natively)
	ap, err := f.n.EndpointResolver.Get(net.JoinHostPort(c.host, strconv.Itoa(int(c.ports.First))))
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// ownsEndpoint reports whether the addr:port lies inside one of the factory's
// candidate ranges, i.e. whether the link was materialised by this factory
// (as opposed to a stock configured endpoint).
func (f *portFactory) ownsEndpoint(ap netip.AddrPort) bool {
	for _, c := range f.candidatesOf() {
		addr, ok := f.resolveCandidateAddr(c)
		if !ok {
			continue
		}
		if addr.Unmap() == ap.Addr().Unmap() && c.ports.Contains(ap.Port()) {
			return true
		}
	}
	return false
}

// probeInterval is the relaxed probe interval for factory-managed links.
func (f *portFactory) probeInterval() time.Duration {
	interval := time.Duration(float64(f.n.RouterTunables.LinkDeadThreshold) * hopProbeFraction)
	if interval < f.n.RouterTunables.ProbeDelay {
		interval = f.n.RouterTunables.ProbeDelay
	}
	return interval
}

// probeReady reports whether the link with the given address is the factory's
// current carrying link and is due for its relaxed-cadence probe. Unknown
// addresses (config links, other peers' links) always report ready so stock
// probe behaviour is preserved.
func (f *portFactory) probeReady(addr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.current.IsValid() || f.current.String() != addr {
		return true
	}
	if time.Since(f.lastProbeAt) >= f.probeInterval() {
		f.lastProbeAt = time.Now()
		return true
	}
	return false
}

// NextHopEndpoint implements device.HopSource. It is called from the device
// send path (never the dispatch loop) and must be fast and lock-safe. The
// rotation path deliberately performs NO dispatch-loop work: it retires the
// port in the pool (own locking), records the retired endpoint as prev, and
// lets the next reconcileLinks pass sort out the links.
func (f *portFactory) NextHopEndpoint(devPeer *device.Peer, exhausted conn.Endpoint) (conn.Endpoint, error) {
	// static mode: the carrying endpoint is pinned; there is nothing to
	// retire and nothing to draw (also reached defensively from external
	// rotations, which must not move a static pin).
	if f.hopMode() == state.HopModeStatic {
		return f.staticCarrying()
	}
	if exhausted != nil {
		ap := exhausted.DstIPPort()
		f.pool.Retire(ap)
		f.mu.Lock()
		f.prev = ap
		f.mu.Unlock()
	} else {
		// The device's hop state has no endpoint yet (first send after SetHop,
		// or a fresh peer). If the factory already drew one — the eager
		// bootstrap beat the first send, or the hop source was re-wired after a
		// config re-apply — ADOPT it instead of drawing a second port.
		// Drawing here would strand the already-materialised link as a healthy
		// ghost on a port the device never carries: nothing ever exhausts it,
		// the probe loops keep it on the full 1s cadence forever, and the peer's
		// symmetric pongs keep renewing it (measured: ghosts stayed "best link"
		// for minutes while the carrying endpoint had long rotated away).
		f.mu.Lock()
		cur := f.current
		f.mu.Unlock()
		if cur.IsValid() && !f.pool.IsCooling(cur) {
			// CAUTION: send path — use the cached bind (see the field comment).
			bind := f.bindIfReady()
			if bind == nil {
				return nil, errors.New("port hop: device bind not wired yet")
			}
			ep, err := bind.ParseEndpoint(cur.String())
			if err != nil {
				return nil, err
			}
			f.mu.Lock()
			f.lastProbeAt = time.Now()
			f.mu.Unlock()
			f.n.Log.Debug("port hop: adopting already-drawn carrying endpoint", "peer", f.node, "endpoint", cur.String())
			return ep, nil
		}
	}

	f.mu.Lock()
	avoid := make([]netip.AddrPort, 0, 1)
	if f.current.IsValid() {
		avoid = append(avoid, f.current)
	}
	f.mu.Unlock()

	ap, err := f.pool.Select(avoid)
	if err != nil {
		// recycle_seconds: every port is cooling down and the operator
		// opted into clean-slate restarts — release the retired ports and
		// draw again instead of stalling on the burned port until the
		// cooldown elapses. The gate rate-limits restarts to once per the
		// configured interval; the draw below still avoids the current
		// endpoint.
		if swept, elapsed, hadEpoch, ok := f.recycleGate(); ok {
			cleared := f.pool.Recycle()
			if cleared > 0 {
				attrs := []any{"peer", f.node, "cleared", cleared, "swept", swept}
				if hadEpoch {
					attrs = append(attrs, "elapsed", elapsed)
				}
				f.n.Log.Info("port hop: pool exhausted, auto-recycle cleared the retired-port quarantine", attrs...)
			}
			// retry the draw regardless: a concurrent rotation may have
			// won the recycle (cleared == 0) — the pool is on a clean
			// slate either way
			ap, err = f.pool.Select(avoid)
		}
	}
	if err != nil {
		f.warnPoolExhausted(err)
		return nil, err
	}
	f.mu.Lock()
	f.current = ap
	f.lastProbeAt = time.Now()
	f.drawsSinceRecycle++
	f.mu.Unlock()
	f.registerDrawn(ap)
	f.adoptCurrent(ap)
	// CAUTION: this runs on the packet send path, under Peer.SendBuffers'
	// device.net READ lock. Never call n.Device.Bind() here — it takes the
	// device.net WRITE lock and self-deadlocks. Use the cached bind.
	bind := f.bindIfReady()
	if bind == nil {
		return nil, errors.New("port hop: device bind not wired yet")
	}
	ep, err := bind.ParseEndpoint(ap.String())
	if err != nil {
		return nil, err
	}
	f.logRotation(ap)
	return ep, nil
}

// staticCarrying parses and returns the pinned static-mode carrying
// endpoint, recording it as the factory's current. Never retires anything:
// there is nothing to rotate to.
func (f *portFactory) staticCarrying() (conn.Endpoint, error) {
	ap, ok := f.pinnedEndpoint()
	if !ok {
		return nil, errors.New("port hop: no resolvable range spec for the static carrying endpoint")
	}
	// CAUTION: send path — use the cached bind (see the field comment).
	bind := f.bindIfReady()
	if bind == nil {
		return nil, errors.New("port hop: device bind not wired yet")
	}
	ep, err := bind.ParseEndpoint(ap.String())
	if err != nil {
		return nil, err
	}
	f.adoptCurrent(ap)
	f.mu.Lock()
	f.current = ap
	f.lastProbeAt = time.Now()
	f.mu.Unlock()
	return ep, nil
}

// logRotation records a carrying-endpoint rotation: Debug per rotation, plus
// a rate-limited Info line that counts how many rotations it covers, so a
// rotation storm shows up as one "rotations=N" line per second instead of N
// lines. Externally driven rotations (reactive/timed) annotate their line
// with the reason. Reactive rotations are rare, decision-driven events (one
// per detected carrying-link death) and always get their own immediate Info
// line — the rate limiter only serves the storm-prone scheduled/budgeted
// modes.
func (f *portFactory) logRotation(ap netip.AddrPort) {
	f.mu.Lock()
	now := time.Now()
	f.rotationCount++
	reason := f.rotateReason
	f.rotateReason = ""
	mode := f.mode
	emit := mode == state.HopModeReactive || now.Sub(f.lastRotationLog) >= hopRotationLogInterval
	if emit {
		count := f.rotationCount
		f.rotationCount = 0
		f.lastRotationLog = now
		f.mu.Unlock()
		attrs := []any{"peer", f.node, "endpoint", ap.String(), "rotations", count}
		if reason != "" {
			attrs = append(attrs, "reason", reason)
		}
		f.n.Log.Info("port hop: carrying endpoint rotated", attrs...)
		return
	}
	f.mu.Unlock()
	f.n.Log.Debug("port hop: carrying endpoint rotated", "peer", f.node, "endpoint", ap.String())
}

// recycleGate decides and atomically claims the opt-in auto-recycle
// (port_hopping.recycle_seconds, resolved onto the factory as recycleMin):
// when the pool has run dry and the configured interval has elapsed since
// the previous restart, it consumes the recycle epoch — the swept=/elapsed=
// journal context — under mu and reports ok; the caller then performs the
// wholesale quarantine swap and retries the draw. A zero recycleMin never
// grants (the stock stall-and-warn behaviour); a refusal inside the
// interval leaves the epoch untouched, so the context is not lost.
//
// CAUTION: this runs on the packet send path, under Peer.SendBuffers'
// device.net READ lock. The granted swap itself is PortPool.Recycle — one
// map replacement under the pool lock, O(1) — and the gate only takes f.mu
// briefly. Never do per-port work, dispatch, resolve or touch the device
// from here: a field-reported recycle that swept the quarantine per port
// on the send path is long enough to wedge the factory against the
// dispatch loop.
func (f *portFactory) recycleGate() (swept uint64, elapsed time.Duration, hadEpoch, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.recycleMin <= 0 || now.Sub(f.lastRecycleAt) < f.recycleMin {
		return 0, 0, false, false
	}
	swept = f.drawsSinceRecycle
	hadEpoch = !f.lastRecycleAt.IsZero()
	if hadEpoch {
		elapsed = now.Sub(f.lastRecycleAt)
	}
	f.drawsSinceRecycle = 0
	f.lastRecycleAt = now
	return swept, elapsed, hadEpoch, true
}

// warnPoolExhausted reports (rate-limited) that rotation is stalled because
// every candidate port is cooling down. Sustained load rotates at
// packets-per-second / budget; if that exceeds range_size / cooldown the pool
// runs dry and the carrying port overshoots its budget until a port cools
// down — the warning carries the pool stats so the trade-off is diagnosable.
func (f *portFactory) warnPoolExhausted(err error) {
	f.mu.Lock()
	now := time.Now()
	if now.Sub(f.lastPoolWarn) < hopPoolWarnInterval {
		f.mu.Unlock()
		f.n.Log.Debug("port hop: rotation stalled, port pool exhausted", "peer", f.node, "error", err.Error())
		return
	}
	f.lastPoolWarn = now
	f.mu.Unlock()
	groups, recent, cooling, retired := f.pool.Stats()
	f.n.Log.Warn("port hop: rotation stalled, port pool exhausted",
		"peer", f.node,
		"groups", groups,
		"recent", recent,
		"cooling", cooling,
		"retired", retired,
		"error", err.Error())
}

// reconcileLinks runs on the dispatch loop once per SyncApplicationState pass.
// It materialises the current carrying endpoint as a link (seeded from the
// predecessor's RTT, so routes stay feasible across rotations without
// waiting for the first probe pong) and tombstones the links of ports the
// factory has rotated away from. Ports drawn and retired between two passes
// (the intermediate ports of a rotation storm) never get links: nothing
// probed them, so nothing needs to match them.
func (f *portFactory) reconcileLinks() {
	f.mu.Lock()
	current := f.current
	prev := f.prev
	f.prev = netip.AddrPort{} // consumed
	mode := f.mode
	period := f.period
	jitterPct := f.jitterPct
	rewire := f.rewireStrategy
	devPeer := f.devPeer
	f.rewireStrategy = ""
	f.mu.Unlock()

	// a rotation landed the carrying endpoint on a different strategy:
	// re-wire the device peer's hop source to that strategy's mode/budget
	// (the send path only flags; device mutation lives here)
	if rewire != "" && devPeer != nil {
		f.wireDevPeer(devPeer)
		f.n.Log.Info("port hop: carrying strategy switched",
			"peer", f.node, "strategy", rewire, "mode", f.hopMode())
	}

	if !current.IsValid() {
		return // nothing drawn yet (bootstrap in flight)
	}

	neigh := f.n.RouterState.GetNeighbour(f.node)
	if neigh == nil {
		return
	}

	// static mode: the pin follows the configured ranges. A config change
	// may have moved or invalidated it — retire the stale carrying link and
	// let the next pass re-pin through bootstrap.
	if mode == state.HopModeStatic && current.IsValid() {
		if pinned, ok := f.pinnedEndpoint(); !ok || pinned != current {
			for _, ep := range neigh.Eps {
				if ep.IsRemote() || ep.IsExhausted() {
					continue
				}
				nep := ep.AsNylonEndpoint()
				if nep.Address != current.String() {
					continue
				}
				nep.MarkExhausted()
				f.scheduleTombstoneRemoval(nep.Address)
			}
			f.mu.Lock()
			f.current = netip.AddrPort{}
			f.mu.Unlock()
			f.n.Log.Info("port hop: static pin moved, re-pinning", "peer", f.node, "old", current.String())
			return
		}
	}

	// External rotation triggers (reactive/timed) run here, at the head of
	// the reconciliation pass, so a rotation triggered this pass is
	// materialised by the same pass.
	if mode == state.HopModeReactive || mode == state.HopModeTimed {
		if reason, due := f.externalRotationDue(mode, current, neigh); due {
			if err := f.externalRotate(mode, period, jitterPct, reason); err == nil {
				f.mu.Lock()
				current = f.current
				prev = f.prev
				f.prev = netip.AddrPort{} // consumed
				f.mu.Unlock()
			}
			// on error the rotation is retried on the next pass: a timed
			// schedule stays due (externalRotate only re-arms it on success)
			// and a reactive trigger re-arms while the link stays dead
		}
	}

	// A stalled rotation (pool exhausted) leaves the current endpoint cooling
	// in the pool: the device keeps carrying on it until the retry succeeds,
	// so keep its existing link untouched as well.
	if f.pool.IsCooling(current) {
		f.n.Log.Debug("port hop: carrying endpoint cooling down, skipping reconciliation", "peer", f.node, "endpoint", current.String())
		return
	}

	curAddr := current.String()
	var curLink state.Endpoint
	for _, ep := range neigh.Eps {
		if !ep.IsRemote() && ep.AsNylonEndpoint().Address == curAddr {
			curLink = ep
			break
		}
	}
	if curLink == nil {
		f.materializeCarrying(neigh, current, prev)
		f.n.Log.Debug("port hop: carrying link materialised at reconciliation", "peer", f.node, "endpoint", curAddr)
	} else if curLink.IsExhausted() {
		// Should not happen (the current port is never retired while current),
		// but if it does, do not rank a burned port: the tombstone removal
		// will reap it and the next pass materialises a fresh link.
		f.n.Log.Debug("port hop: carrying link is exhausted, awaiting re-materialisation", "peer", f.node, "endpoint", curAddr)
	}

	// Tombstone every other hop link of this peer: they belong to ports the
	// factory has rotated away from. This includes the predecessor recorded by
	// the latest rotation, remote (learned) links whose address lies inside
	// the factory's ranges, and anything a ping created before the factory was
	// wired — a link on an owned port that is not the carrying endpoint is by
	// construction retired (the local node owns port selection for its
	// ranges). Deferring the exhaustion to here (instead of marking it on the
	// send path) is what keeps the neighbour continuously ranked: the
	// predecessor stays the best endpoint until its successor is materialised,
	// so routes never flap on rotation.
	for _, ep := range neigh.Eps {
		nep := ep.AsNylonEndpoint()
		if ep.IsExhausted() {
			continue
		}
		if nep.Address == curAddr {
			continue
		}
		ap, err := netip.ParseAddrPort(nep.Address)
		if err != nil {
			continue
		}
		// The union of the drawn registry and the resolver-based range check:
		// a link on a port this factory DREW is retired by construction even
		// when the resolver's answer for the spec host has since changed
		// (dual-stack round-robin / DDNS) — the resolver alone de-owning it is
		// exactly how the every-port-still-talking zombies were born.
		if !f.ownsOrDrew(ap) {
			continue
		}
		nep.MarkExhausted()
		f.n.scheduleExhaustedLinkRemoval(f.node, nep.Address)
		f.n.Log.Debug("port hop: retired carrying link tombstoned", "peer", f.node, "endpoint", nep.Address)
	}
}

// externalRotationDue reports whether an externally driven rotation
// (reactive/timed) is due, and why. Must run on the dispatch loop.
func (f *portFactory) externalRotationDue(mode string, current netip.AddrPort, neigh *state.Neighbour) (string, bool) {
	if mode == state.HopModeTimed {
		f.mu.Lock()
		next := f.nextRotate
		f.mu.Unlock()
		if !next.IsZero() && !time.Now().Before(next) {
			return "timed schedule", true
		}
		return "", false
	}
	// reactive: the carrying link is judged by the same liveness model the
	// router uses for ranking — no traffic heard back for
	// link_dead_threshold, or loss-dead probe statistics (Metric() == INF).
	// A link younger than the liveness threshold is given time to prove
	// itself first, so a cold bootstrap link is not rotated away before its
	// first probe completes.
	for _, ep := range neigh.Eps {
		if ep.IsRemote() || ep.IsExhausted() {
			continue
		}
		nep := ep.AsNylonEndpoint()
		if nep.Address != current.String() {
			continue
		}
		if time.Since(nep.FirstSeen()) <= f.n.RouterTunables.LinkDeadThreshold {
			return "", false
		}
		if ep.Metric() >= state.INF {
			return "dead carrying link", true
		}
		// liveness can be sustained by the PEER's traffic (its pings ride the
		// reverse flow) while our own direction to the port is blackholed;
		// only our probes going unanswered exposes that asymmetry
		if nep.ProbeStreak() >= hopReactiveProbeStreak {
			return "unanswered carrying probes", true
		}
		return "", false
	}
	return "", false
}

// externalRotate performs a controller-driven carrying-endpoint rotation
// (reactive/timed): the device peer rotates immediately through its hop
// source, and a timed schedule is re-armed for the next period ± jitter only
// on success (a failed rotation stays due and is retried next pass). Must
// run on the dispatch loop.
func (f *portFactory) externalRotate(mode string, period time.Duration, jitterPct uint32, reason string) error {
	f.mu.Lock()
	peer := f.devPeer
	f.rotateReason = reason
	f.mu.Unlock()
	if peer == nil {
		f.mu.Lock()
		f.rotateReason = ""
		f.mu.Unlock()
		return errors.New("port hop: device peer not wired yet")
	}
	if _, err := peer.HopExternalRotate(); err != nil {
		f.mu.Lock()
		f.rotateReason = "" // not consumed by logRotation on the failure path
		f.mu.Unlock()
		f.warnPoolExhausted(err)
		return err
	}
	if mode == state.HopModeTimed {
		f.mu.Lock()
		f.nextRotate = time.Now().Add(jitterInterval(period, jitterPct))
		f.mu.Unlock()
	}
	return nil
}

// jitterInterval draws one timed-mode rotation interval: the period plus a
// uniform random jitter of jitterPct percent, so rotations do not
// synchronise across nodes or align with any periodic pattern.
func jitterInterval(period time.Duration, jitterPct uint32) time.Duration {
	if period <= 0 {
		return period
	}
	jitter := time.Duration(float64(period) * float64(jitterPct) / 100)
	if jitter <= 0 {
		return period
	}
	delta := time.Duration((rand.Float64()*2 - 1) * float64(jitter))
	return period + delta
}

// materializeCarrying registers the current carrying endpoint as a regular
// nylon link. If a healthy predecessor link exists, its RTT estimate is
// seeded onto the new link so ComputeRoutes sees a feasible, cost-continuous
// endpoint immediately (the carrying port is by construction forwarding live
// traffic — the send path drew it); the relaxed probe loop refines the
// estimate afterwards. Without a predecessor (bootstrap), the link starts
// cold and an on-demand probe validates it.
//
// Runs on the dispatch loop. ComputeRoutes is invoked only on reachability
// transitions (endpoint-less neighbour becomes ranked, or vice versa): in
// steady rotation the seeded metric keeps the neighbour's cost continuous,
// and the periodic recomputes (probe pongs, route updates) pick up exact
// values — recomputing per rotation is what a rotation storm cannot afford.
func (f *portFactory) materializeCarrying(neigh *state.Neighbour, ap netip.AddrPort, prev netip.AddrPort) {
	addr := ap.String()
	hadBest := neigh.BestEndpoint() != nil

	for i, ep := range neigh.Eps {
		if ep.IsRemote() || ep.AsNylonEndpoint().Address != addr {
			continue
		}
		if !ep.IsExhausted() {
			return // already materialized and live
		}
		// a stale tombstone for this port still lingers inside its grace
		// window (possible whenever a port is redrawn quickly — e.g. an
		// auto_recycle restart): replace it with a fresh link so the
		// carrying port is ranked again
		neigh.Eps = slices.Delete(neigh.Eps, i, i+1)
		f.n.Log.Debug("port hop: stale tombstoned link replaced on redraw", "peer", f.node, "endpoint", addr)
		break
	}
	// the cached bind keeps the factory free of the device net lock even
	// when re-materialising from the dispatch loop
	bind := f.bindIfReady()
	if bind == nil {
		return
	}
	wgEp, err := bind.ParseEndpoint(addr)
	if err != nil {
		return
	}
	link := state.NewEndpoint(addr, false, wgEp, &f.n.RouterTunables)

	if seed := f.findSeedLink(neigh, ap, prev); seed != nil {
		if rtt := seed.AsNylonEndpoint().FilteredPing(); rtt > 0 && !math.IsInf(float64(rtt), 1) {
			// CAUTION: order matters — Renew() on an inactive link resets the
			// history and the EWMA (see NylonEndpoint.Renew), so it must run
			// BEFORE the seed is planted, or it wipes it right back out.
			link.Renew()
			link.SeedRTT(rtt)
		}
	}

	neigh.Eps = append(neigh.Eps, link)
	f.n.UpdateNeighbour(f.node)

	if !link.IsActive() {
		// no predecessor to seed from: bootstrap-grade link, validate with an
		// on-demand probe (marks the link active on the first pong)
		go func() {
			if err := f.n.Probe(f.node, link.AsNylonEndpoint()); err != nil {
				f.n.Log.Debug("port hop: probe of new endpoint failed", "peer", f.node, "endpoint", addr, "error", err)
			}
		}()
		return
	}
	// seeded: the neighbour's reachability may have just been restored
	if !hadBest && neigh.BestEndpoint() != nil {
		ComputeRoutes(f.n.RouterState, f.n)
	}
}

// findSeedLink returns the healthiest hop link to use as the RTT seed source
// for a freshly drawn carrying endpoint: the link of the port the latest
// rotation retired, if it still exists and has a measurement, else any other
// healthy hop link (a rotation storm's intermediate ports have no links, so
// this falls back to the last materialised predecessor).
func (f *portFactory) findSeedLink(neigh *state.Neighbour, drawn netip.AddrPort, prev netip.AddrPort) state.Endpoint {
	var fallback state.Endpoint
	for _, ep := range neigh.Eps {
		if ep.IsRemote() || ep.IsExhausted() {
			continue
		}
		nep := ep.AsNylonEndpoint()
		ap, err := netip.ParseAddrPort(nep.Address)
		if err != nil || ap == drawn || !f.ownsEndpoint(ap) {
			continue
		}
		if prev.IsValid() && nep.Address == prev.String() {
			return ep
		}
		if fallback == nil {
			fallback = ep
		}
	}
	return fallback
}

// scheduleTombstoneRemoval is the factory's shorthand for the shared
// exhausted-link removal (grace window, still-exhausted-only safety, see
// Nylon.scheduleExhaustedLinkRemoval).
func (f *portFactory) scheduleTombstoneRemoval(addr string) {
	f.n.scheduleExhaustedLinkRemoval(f.node, addr)
}

// wireDevPeer wires the device peer's hop source to the CURRENT strategy's
// rotation mode: proactive budgets rotate on the send path; every other mode
// rotates externally from the dispatch loop. Must run on the dispatch loop.
func (f *portFactory) wireDevPeer(wgPeer *device.Peer) {
	f.mu.Lock()
	strategy := f.currentStrategy
	f.mu.Unlock()
	policy := f.policyOf(strategy)
	if policy.Mode == state.HopModeProactive {
		wgPeer.SetHop(f, int(policy.Budget))
	} else {
		// static/reactive/timed: the carrying endpoint never rotates on
		// the send path; reactive/timed rotations are driven by the
		// factory from the dispatch loop
		wgPeer.SetHopExternal(f)
	}
}

// policyOf is the lock-taking wrapper around policyOfLocked.
func (f *portFactory) policyOf(strategy string) state.PortHoppingPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policyOfLocked(strategy)
}

// peerCandidates expands a peer's advertised endpoints into draw candidates:
// every tagged or bare-host endpoint contributes one candidate per strategy
// its tags name (untagged = all strategies), carrying that strategy's parsed
// ports and resolved rotation policy. Raw host:port endpoints contribute
// nothing (stock configured links).
func (n *Nylon) peerCandidates(cfg *state.RouterCfg) ([]hopCandidate, error) {
	m := n.CentralCfg.ObfStrategies
	if len(m) == 0 {
		return nil, nil
	}
	var candidates []hopCandidate
	seen := map[string]struct{}{}
	for _, addr := range cfg.Endpoints {
		spec, err := state.ParseEndpointSpec(addr)
		if err != nil {
			continue // validation owns the error path
		}
		if !spec.HasStrategies() && (spec.Ports.Valid() || len(m) == 0) {
			continue // raw endpoint or strategyless mesh
		}
		tags, err := state.EndpointStrategyTags(spec, m)
		if err != nil {
			return nil, err
		}
		for _, name := range tags {
			key := spec.Host + "|" + name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			pr, err := state.StrategyPortRangeOf(m, name)
			if err != nil {
				return nil, err
			}
			s := m[name]
			candidates = append(candidates, hopCandidate{
				host:     spec.Host,
				ports:    pr,
				strategy: name,
				policy:   state.ResolveStrategyHopPolicy(s),
			})
		}
	}
	return candidates, nil
}

// ensurePortFactories wires a HopSource into every device peer whose
// neighbour's endpoints expand into obf strategy candidates, and unwires it
// when they no longer do. Runs on the dispatch loop from SyncApplicationState.
func (n *Nylon) ensurePortFactories() error {
	if n.Device == nil {
		return nil
	}
	n.logStrategyHopPolicies()

	for _, peer := range n.GetPeers(n.Id) {
		if !n.IsRouter(peer) {
			continue
		}
		cfg := n.GetRouter(peer)

		candidates, err := n.peerCandidates(&cfg)
		if err != nil {
			// validation normally catches this at seal/startup;
			// a live config swap that slipped through must not take
			// the daemon down — drop the factory and journal loudly
			n.Log.Error("port hop: dropping the factory, endpoint strategies failed to expand", "peer", peer, "error", err)
			if n.hasPortFactory(peer) {
				if wgPeer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(peer).PubKey)); wgPeer != nil {
					wgPeer.SetHop(nil, 0)
				}
				n.dropPortFactory(peer)
			}
			continue
		}

		wgPeer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(peer).PubKey))
		if wgPeer == nil {
			continue
		}
		if len(candidates) == 0 {
			// no strategy candidates for this peer: make sure any stale hop state is gone
			if n.hasPortFactory(peer) {
				wgPeer.SetHop(nil, 0)
				n.dropPortFactory(peer)
			}
			continue
		}
		f := n.getPortFactory(peer, candidates, candidatePoolConfig(candidates), wgPeer)
		f.wireDevPeer(wgPeer)
	}
	return nil
}

// logStrategyHopPolicies journals the effective rotation policy of every
// strategy this node may draw from (its used set), one line per strategy,
// whenever a policy changes (startup, config update). The knobs moved into
// the strategies, so the journal names the strategy instead of a source.
func (n *Nylon) logStrategyHopPolicies() {
	m := n.CentralCfg.ObfStrategies
	if len(m) == 0 {
		return
	}
	used := state.NodeUsedStrategies(&n.CentralCfg, n.LocalCfg.Id)
	n.portHopping.mu.Lock()
	if n.portHopping.appliedPolicies == nil {
		n.portHopping.appliedPolicies = make(map[string]string)
	}
	changed := map[string]bool{}
	seen := map[string]struct{}{}
	for _, name := range used {
		s := m[name]
		if s == nil {
			continue
		}
		seen[name] = struct{}{}
		sig := s.HopPolicySignature()
		if n.portHopping.appliedPolicies[name] != sig {
			n.portHopping.appliedPolicies[name] = sig
			changed[name] = true
		}
	}
	for name := range n.portHopping.appliedPolicies {
		if _, ok := seen[name]; !ok {
			delete(n.portHopping.appliedPolicies, name)
		}
	}
	n.portHopping.mu.Unlock()
	for _, name := range used {
		if !changed[name] {
			continue
		}
		p := state.ResolveStrategyHopPolicy(m[name])
		attrs := []any{"strategy", name, "mode", p.Mode}
		switch p.Mode {
		case state.HopModeProactive:
			attrs = append(attrs, "budget", p.Budget,
				"cooldown", p.Cooldown.String(), "recycle_seconds", p.RecycleMinInterval.String())
		case state.HopModeTimed:
			attrs = append(attrs, "period", p.Period.String(),
				"jitter_pct", p.JitterPct, "cooldown", p.Cooldown.String(),
				"recycle_seconds", p.RecycleMinInterval.String())
		case state.HopModeReactive:
			attrs = append(attrs, "cooldown", p.Cooldown.String(),
				"recycle_seconds", p.RecycleMinInterval.String())
		}
		n.Log.Info("port hop policy applied", attrs...)
	}
}

func (n *Nylon) hasPortFactory(peer state.NodeId) bool {
	n.portHopping.mu.Lock()
	defer n.portHopping.mu.Unlock()
	_, ok := n.portHopping.factories[peer]
	return ok
}

// hopOwnedEndpoint reports whether the addr:port lies inside a port range
// configured for the peer, i.e. a port whose link lifecycle the peer's port
// factory owns — including every port the factory has EVER DRAWN (see
// portFactory.ownsOrDrew): handleProbePing's remote-link learning must refuse
// both, or a stale ping from a retired port re-learns an immortal zombie once
// the retired link's grace removal has run.
func (n *Nylon) hopOwnedEndpoint(peer state.NodeId, ap netip.AddrPort) bool {
	n.portHopping.mu.Lock()
	f, ok := n.portHopping.factories[peer]
	n.portHopping.mu.Unlock()
	if !ok {
		return false
	}
	return f.ownsOrDrew(ap)
}

// hopProbeReady reports whether the link with the given address is due for
// probing under its factory's relaxed cadence. Addresses not managed by a
// factory (stock configured or learned links) are always due, preserving the
// stock probe behaviour.
func (n *Nylon) hopProbeReady(peer state.NodeId, addr string) bool {
	n.portHopping.mu.Lock()
	f, ok := n.portHopping.factories[peer]
	n.portHopping.mu.Unlock()
	if !ok {
		return true
	}
	return f.probeReady(addr)
}

// hopSpecResolveTargets returns one resolvable endpoint string per configured
// candidate ("host:firstport"), so the shared resolver refresh loop keeps
// their DNS entries warm. Candidates never appear as links, which is the only
// thing the refresh loop would otherwise visit.
func (n *Nylon) hopSpecResolveTargets() []string {
	n.portHopping.mu.Lock()
	defer n.portHopping.mu.Unlock()
	var out []string
	for _, f := range n.portHopping.factories {
		for _, target := range f.candidateHosts() {
			if _, err := netip.ParseAddr(target); err == nil {
				continue // literal addresses need no resolver entry
			}
			out = append(out, target)
		}
	}
	return out
}
