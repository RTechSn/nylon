package core

import (
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

// portFactory manages the dynamic endpoint window of one peer whose
// configured endpoints contain port ranges. It implements device.HopSource:
// every time the device send path exhausts a carrying port's packet budget,
// the factory draws a fresh endpoint from the port pool (maximally
// dissimilar to the current one — different IP/subnet preferred), retires the
// old port into cooldown, and materializes the new endpoint as a regular
// nylon link so the existing probe/metric/ranking machinery sees it.
//
// Range endpoints are NEVER expanded into individual links at config time:
// the pool keeps runtime state O(window) instead of O(range), which is what
// makes production-sized ranges (tens of thousands of ports) viable.
type portFactory struct {
        n    *Nylon
        node state.NodeId

        // mu guards current and specs; the pool has its own locking.
        mu          sync.Mutex
        specs       []state.EndpointSpec // range-form endpoints from the neighbour's config
        pool        *state.PortPool
        current     netip.AddrPort // the endpoint currently carrying traffic
        lastProbeAt time.Time      // last relaxed-cadence probe of the current link
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
        f.mu.Unlock()
        f.refreshGroups()
        f.bootstrap()
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
        f.materializeLink(ap)
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
// send path (never the dispatch loop) and must be fast and lock-safe.
func (f *portFactory) NextHopEndpoint(devPeer *device.Peer, exhausted conn.Endpoint) (conn.Endpoint, error) {
        if exhausted != nil {
                ap := exhausted.DstIPPort()
                f.pool.Retire(ap)
                f.retireLink(ap)
        }

        f.mu.Lock()
        avoid := make([]netip.AddrPort, 0, 1)
        if f.current.IsValid() {
                avoid = append(avoid, f.current)
        }
        f.mu.Unlock()

        ap, err := f.pool.Select(avoid)
        if err != nil {
                return nil, err
        }
        f.mu.Lock()
        f.current = ap
        f.mu.Unlock()

        ep, err := f.n.Device.Bind().ParseEndpoint(ap.String())
        if err != nil {
                return nil, err
        }
        f.materializeLink(ap)
        f.mu.Lock()
        f.lastProbeAt = time.Now()
        f.mu.Unlock()
        f.n.Log.Info("port hop: carrying endpoint rotated", "peer", f.node, "endpoint", ap.String())
        return ep, nil
}

// materializeLink registers the drawn endpoint as a regular nylon link and
// probes it once so it becomes active for routing and ranking.
func (f *portFactory) materializeLink(ap netip.AddrPort) {
        addr := ap.String()
        f.n.Dispatch(func() error {
                neigh := f.n.RouterState.GetNeighbour(f.node)
                if neigh == nil {
                        return nil
                }
                for _, ep := range neigh.Eps {
                        if !ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
                                return nil // already materialized
                        }
                }
                wgEp, err := f.n.Device.Bind().ParseEndpoint(addr)
                if err != nil {
                        return nil
                }
                link := state.NewEndpoint(addr, false, wgEp, &f.n.RouterTunables)
                neigh.Eps = append(neigh.Eps, link)
                f.n.UpdateNeighbour(f.node)
                // on-demand probe: validates the port and marks the link active so
                // routes through this neighbour stay feasible during rotation
                go func() {
                        if err := f.n.Probe(f.node, link.AsNylonEndpoint()); err != nil {
                                f.n.Log.Debug("port hop: probe of new endpoint failed", "peer", f.node, "endpoint", addr, "error", err)
                        }
                }()
                return nil
        })
}

// retireLink marks the exhausted endpoint's link and schedules its removal
// after the tombstone grace period.
func (f *portFactory) retireLink(ap netip.AddrPort) {
        addr := ap.String()
        f.n.Dispatch(func() error {
                neigh := f.n.RouterState.GetNeighbour(f.node)
                if neigh == nil {
                        return nil
                }
                for _, ep := range neigh.Eps {
                        if !ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
                                ep.AsNylonEndpoint().MarkExhausted()
                        }
                }
                return nil
        })
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
