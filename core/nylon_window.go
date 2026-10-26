package core

import (
	"errors"
	"math"
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

	// mu guards current, prev, specs, bind and the log-rate-limit fields; the
	// pool has its own locking.
	mu      sync.Mutex
	specs   []state.EndpointSpec // range-form endpoints from the neighbour's config
	pool    *state.PortPool
	current netip.AddrPort // the endpoint currently carrying traffic
	prev    netip.AddrPort // the endpoint retired by the latest rotation (seed source / tombstone candidate)
	// lastProbeAt is the last relaxed-cadence probe of the current link.
	lastProbeAt time.Time

	// rotation log rate limiting
	lastRotationLog time.Time
	rotationCount   uint64

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

// bindIfReady returns the cached device bind, or nil before the factory has
// been wired on the dispatch loop.
func (f *portFactory) bindIfReady() conn.Bind {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bind
}

// hopFactories returns (creating if needed) the factory for a peer. Must be
// called on the dispatch loop.
func (n *Nylon) getPortFactory(peer state.NodeId, specs []state.EndpointSpec, policy state.PortHoppingPolicy) *portFactory {
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
			pool: state.NewPortPool(nil, state.PortPoolConfig{
				Recent:   int(policy.Recent),
				Cooldown: policy.Cooldown,
				Samples:  int(policy.CandidateSamples),
			}),
		}
		n.portHopping.factories[peer] = f
	}
	f.mu.Lock()
	f.specs = slices.Clone(specs)
	// Refresh the bind cache on the dispatch loop (see the field comment: the
	// send path must never acquire the device net write lock).
	f.bind = n.Device.Bind()
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

	// resolve any hostname specs in the background, then refresh the pool
	// groups once results are cached (dispatch-loop safe)
	go func() {
		for _, spec := range f.specStrings() {
			if _, err := netip.ParseAddr(spec.Host); err == nil {
				continue // literal, nothing to resolve
			}
			if _, err := f.n.EndpointResolver.Resolve(net.JoinHostPort(spec.Host, strconv.Itoa(int(spec.Ports.First))), f.n.EndpointResolveExpiry); err != nil {
				f.n.Log.Debug("port hop: failed to resolve range host", "peer", f.node, "host", spec.Host, "error", err)
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

// specStrings returns a copy of the configured range specs.
func (f *portFactory) specStrings() []state.EndpointSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.specs)
}

// drawAndMaterialize draws a fresh carrying endpoint (if the pool has usable
// groups) and materialises its link, mirroring NextHopEndpoint without
// retiring anything. Runs on the dispatch loop.
func (f *portFactory) drawAndMaterialize() {
	f.mu.Lock()
	avoid := make([]netip.AddrPort, 0, 1)
	if f.current.IsValid() {
		avoid = append(avoid, f.current)
	}
	f.mu.Unlock()

	ap, err := f.pool.Select(avoid)
	if err != nil {
		// pool not ready (e.g. hostname still resolving): retried by the
		// background resolve above and the next SyncApplicationState pass
		return
	}
	f.mu.Lock()
	f.current = ap
	f.lastProbeAt = time.Now()
	f.mu.Unlock()
	neigh := f.n.RouterState.GetNeighbour(f.node)
	if neigh == nil {
		return
	}
	f.materializeCarrying(neigh, ap, netip.AddrPort{})
	f.n.Log.Info("port hop: initial carrying endpoint selected", "peer", f.node, "endpoint", ap.String())
}

// dropPortFactory removes the factory for a peer whose config no longer
// carries ranges. Must be called on the dispatch loop.
func (n *Nylon) dropPortFactory(peer state.NodeId) {
	n.portHopping.mu.Lock()
	delete(n.portHopping.factories, peer)
	n.portHopping.mu.Unlock()
}

// refreshGroups re-resolves the configured range specs into pool groups
// (literal IPs parse directly; hostnames go through the shared resolver and
// follow its cache expiry).
func (f *portFactory) refreshGroups() {
	f.mu.Lock()
	specs := slices.Clone(f.specs)
	f.mu.Unlock()

	groups := make([]state.PortGroup, 0, len(specs))
	for _, spec := range specs {
		addr, ok := f.resolveSpecAddr(spec)
		if !ok {
			continue
		}
		groups = append(groups, state.PortGroup{Addr: addr, Ports: spec.Ports})
	}
	if !slices.EqualFunc(f.pool.Groups(), groups, func(a, b state.PortGroup) bool {
		return a.Addr == b.Addr && a.Ports == b.Ports
	}) {
		f.pool.SetGroups(groups)
	}
}

// resolveSpecAddr resolves the host part of a range spec to an address.
func (f *portFactory) resolveSpecAddr(spec state.EndpointSpec) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(spec.Host); err == nil {
		return addr.Unmap(), true
	}
	// hostname: resolve through the shared resolver by borrowing the first
	// port of the range (materialised single-port addresses resolve natively)
	ap, err := f.n.EndpointResolver.Get(net.JoinHostPort(spec.Host, strconv.Itoa(int(spec.Ports.First))))
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// ownsEndpoint reports whether the addr:port lies inside one of the factory's
// configured ranges, i.e. whether the link was materialised by this factory
// (as opposed to a stock configured endpoint).
func (f *portFactory) ownsEndpoint(ap netip.AddrPort) bool {
	for _, spec := range f.specStrings() {
		addr, ok := f.resolveSpecAddr(spec)
		if !ok {
			continue
		}
		if addr.Unmap() == ap.Addr().Unmap() && spec.Ports.Contains(ap.Port()) {
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
		f.warnPoolExhausted(err)
		return nil, err
	}
	f.mu.Lock()
	f.current = ap
	f.lastProbeAt = time.Now()
	f.mu.Unlock()

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

// logRotation records a carrying-endpoint rotation: Debug per rotation, plus
// a rate-limited Info line that counts how many rotations it covers, so a
// rotation storm shows up as one "rotations=N" line per second instead of N
// lines.
func (f *portFactory) logRotation(ap netip.AddrPort) {
	f.mu.Lock()
	now := time.Now()
	f.rotationCount++
	if now.Sub(f.lastRotationLog) >= hopRotationLogInterval {
		count := f.rotationCount
		f.rotationCount = 0
		f.lastRotationLog = now
		f.mu.Unlock()
		f.n.Log.Info("port hop: carrying endpoint rotated",
			"peer", f.node, "endpoint", ap.String(), "rotations", count)
		return
	}
	f.mu.Unlock()
	f.n.Log.Debug("port hop: carrying endpoint rotated", "peer", f.node, "endpoint", ap.String())
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
	f.mu.Unlock()

	if !current.IsValid() {
		return // nothing drawn yet (bootstrap in flight)
	}

	neigh := f.n.RouterState.GetNeighbour(f.node)
	if neigh == nil {
		return
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
	// the latest rotation. Deferring the exhaustion to here (instead of
	// marking it on the send path) is what keeps the neighbour continuously
	// ranked: the predecessor stays the best endpoint until its successor is
	// materialised, so routes never flap on rotation.
	for _, ep := range neigh.Eps {
		nep := ep.AsNylonEndpoint()
		if ep.IsRemote() || ep.IsExhausted() {
			continue
		}
		if nep.Address == curAddr {
			continue
		}
		ap, err := netip.ParseAddrPort(nep.Address)
		if err != nil || !f.ownsEndpoint(ap) {
			continue
		}
		nep.MarkExhausted()
		f.scheduleTombstoneRemoval(nep.Address)
		f.n.Log.Debug("port hop: retired carrying link tombstoned", "peer", f.node, "endpoint", nep.Address)
	}
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

	for _, ep := range neigh.Eps {
		if !ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
			return // already materialized
		}
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

// scheduleTombstoneRemoval removes the exhausted link for addr after the
// tombstone grace period (late pongs still match it until then). Safe to call
// more than once for the same address: extra runs find nothing to delete.
func (f *portFactory) scheduleTombstoneRemoval(addr string) {
	time.AfterFunc(hopTombstoneGrace, func() {
		if f.n.Context.Err() != nil {
			return
		}
		f.n.Dispatch(func() error {
			neigh := f.n.RouterState.GetNeighbour(f.node)
			if neigh == nil {
				return nil
			}
			for i, ep := range neigh.Eps {
				if !ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
					neigh.Eps = slices.Delete(neigh.Eps, i, i+1)
					break
				}
			}
			return nil
		})
	})
}

// ensurePortFactories wires a HopSource into every device peer whose
// neighbour is configured with port ranges, and unwires it when the ranges
// disappear. Runs on the dispatch loop from SyncApplicationState.
func (n *Nylon) ensurePortFactories() error {
	if n.Device == nil {
		return nil
	}
	policy := n.LocalCfg.PortHopping.Resolve()

	for _, peer := range n.GetPeers(n.Id) {
		if !n.IsRouter(peer) {
			continue
		}
		cfg := n.GetRouter(peer)

		var specs []state.EndpointSpec
		for _, addr := range cfg.Endpoints {
			spec, err := state.ParseEndpointSpec(addr)
			if err != nil {
				continue
			}
			if spec.IsRange() {
				specs = append(specs, spec)
			}
		}

		wgPeer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(peer).PubKey))
		if wgPeer == nil {
			continue
		}
		if len(specs) == 0 {
			// no ranges for this peer: make sure any stale hop state is gone
			if n.hasPortFactory(peer) {
				wgPeer.SetHop(nil, 0)
				n.dropPortFactory(peer)
			}
			continue
		}
		f := n.getPortFactory(peer, specs, policy)
		wgPeer.SetHop(f, int(policy.Budget))
	}
	return nil
}

func (n *Nylon) hasPortFactory(peer state.NodeId) bool {
	n.portHopping.mu.Lock()
	defer n.portHopping.mu.Unlock()
	_, ok := n.portHopping.factories[peer]
	return ok
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
// range spec ("host:firstport"), so the shared resolver refresh loop keeps
// their DNS entries warm. Range specs never appear as links, which is the only
// thing the refresh loop would otherwise visit.
func (n *Nylon) hopSpecResolveTargets() []string {
	n.portHopping.mu.Lock()
	defer n.portHopping.mu.Unlock()
	var out []string
	for _, f := range n.portHopping.factories {
		for _, spec := range f.specStrings() {
			if _, err := netip.ParseAddr(spec.Host); err == nil {
				continue // literal addresses need no resolver entry
			}
			out = append(out, net.JoinHostPort(spec.Host, strconv.Itoa(int(spec.Ports.First))))
		}
	}
	return out
}
