package core

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

type EpPing struct {
	TimeSent time.Time
	Peer     state.NodeId
	Complete func(protocol.EndpointProbeStatus, time.Duration)
}

func (n *Nylon) sendEndpointProbes(peer state.NodeId, timeout time.Duration) ([]Future[*protocol.EndpointProbeResult], error) {
	neigh := n.RouterState.GetNeighbour(peer)
	if neigh == nil {
		return nil, fmt.Errorf("peer %q is not a neighbour", peer)
	}
	eps := slices.Clone(neigh.Eps)
	slices.SortFunc(eps, func(a, b state.Endpoint) int {
		return cmp.Compare(a.AsNylonEndpoint().Address, b.AsNylonEndpoint().Address)
	})
	probes := make([]Future[*protocol.EndpointProbeResult], 0, len(eps))
	for _, ep := range eps {
		// port hopping: skip burned carrying ports (quarantined; probing them
		// would only spend packets on a port that is about to be abandoned)
		if ep.IsExhausted() {
			continue
		}
		result, _ := n.sendEndpointProbe(neigh.Id, ep.AsNylonEndpoint(), timeout)
		probes = append(probes, result)
	}
	return probes, nil
}

func (n *Nylon) Probe(node state.NodeId, ep *state.NylonEndpoint) error {
	_, err := n.sendEndpointProbe(node, ep, 0)
	return err
}

// probeBufTTL keeps the leak-safety TTL of a probe token ahead of the
// probe timer: the AfterFunc deletes the token at exactly `timeout`, so the
// cache TTL only needs to outlive it. Fire-and-forget probes (timeout 0)
// keep the 5s default.
func probeBufTTL(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return ttlcache.DefaultTTL
	}
	return timeout + time.Second
}

func (n *Nylon) sendEndpointProbe(node state.NodeId, ep *state.NylonEndpoint, timeout time.Duration) (Future[*protocol.EndpointProbeResult], error) {
	address := ep.Address
	resolved := ""
	resultFuture, completeResult := NewFuture[*protocol.EndpointProbeResult]()
	completeEndpoint := func(status protocol.EndpointProbeStatus, latency time.Duration, err error) {
		result := &protocol.EndpointProbeResult{
			Address:   address,
			Status:    status,
			LatencyNs: int64(latency),
		}
		if resolved != "" {
			result.Resolved = new(resolved)
		}
		completeResult(result, err)
	}
	fail := func(status protocol.EndpointProbeStatus, err error) (Future[*protocol.EndpointProbeResult], error) {
		completeEndpoint(status, 0, err)
		return resultFuture, err
	}

	peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(node).PubKey))
	if peer == nil {
		return fail(protocol.EndpointProbeStatus_ENDPOINT_PROBE_SEND_ERROR, fmt.Errorf("wireguard peer %q is not configured", node))
	}
	nep, err := ep.GetWgEndpoint(n.Device, n.EndpointResolver)
	if err != nil {
		return fail(protocol.EndpointProbeStatus_ENDPOINT_PROBE_RESOLVE_ERROR, err)
	}
	nep = n.hopProbeEndpoint(peer, nep)
	resolved = nep.DstIPPort().String()
	token := rand.Uint64()
	sentAt := time.Now()
	ping := &protocol.Ny{
		Type: &protocol.Ny_ProbeOp{
			ProbeOp: &protocol.Ny_Probe{
				Token:         token,
				ResponseToken: nil,
			},
		},
	}
	var timeoutTimer *time.Timer
	if timeout > 0 {
		timeoutTimer = time.AfterFunc(timeout, func() {
			n.PingBuf.Delete(token)
			completeEndpoint(protocol.EndpointProbeStatus_ENDPOINT_PROBE_TIMEOUT, 0, nil)
			n.Dispatch(func() error { ep.RecordProbe(false); return nil })
		})
	}

	n.PingBuf.Set(token, EpPing{
		TimeSent: sentAt,
		Peer:     node,
		Complete: func(status protocol.EndpointProbeStatus, latency time.Duration) {
			if timeoutTimer != nil {
				timeoutTimer.Stop()
			}
			completeEndpoint(status, latency, nil)
		},
	}, probeBufTTL(timeout))

	go func() {
		err := n.SendNylon(ping, nep, peer)
		if err != nil {
			if timeoutTimer != nil && timeoutTimer.Stop() {
				n.Dispatch(func() error { ep.RecordProbe(false); return nil })
			}
			n.PingBuf.Delete(token)
			completeEndpoint(protocol.EndpointProbeStatus_ENDPOINT_PROBE_SEND_ERROR, 0, err)
		}
	}()

	return resultFuture, nil
}

// hopProbeEndpoint picks the endpoint a probe egresses through: when the
// link's address is where the device is currently sending to this peer, ride
// the peer's LIVE endpoint instead of the link's stored one. val[0] follows
// every authenticated arrival (SetEndpointFromPacket's reply-port symmetry),
// so it carries the freshest local reply-port hint — the probe leaves through
// the peer's current carrying port and switches with the rotation instead of
// lingering on the port the link pin last saw. This also merges the probe
// flow of the peer's advertised endpoint (same address as the arrival source
// when not NAT'd) onto the carrying port, instead of pinning a static 1 Hz
// probe-pong flow onto the first port of the range forever.
func (n *Nylon) hopProbeEndpoint(peer *device.Peer, nep conn.Endpoint) conn.Endpoint {
	if cur := peer.CurrentEndpoint(); cur != nil && cur.DstIPPort() == nep.DstIPPort() {
		return cur
	}
	return nep
}

func handleProbe(n *Nylon, pkt *protocol.Ny_Probe, endpoint conn.Endpoint, peer *device.Peer, node state.NodeId) {
	if pkt.ResponseToken == nil {
		// ping
		// build pong response
		responseToken := pkt.Token
		res := &protocol.Ny_Probe{
			Token:         pkt.Token,
			ResponseToken: &responseToken,
		}

		// send pong
		err := n.SendNylon(&protocol.Ny{Type: &protocol.Ny_ProbeOp{ProbeOp: res}}, endpoint, peer)
		if err != nil {
			n.Log.Error("Failed to send nylon packet to node", "node", node, "error", err)
			return
		}

		n.Dispatch(func() error {
			handleProbePing(n, node, endpoint)
			return nil
		})
	} else {
		// pong
		n.Dispatch(func() error {
			handleProbePong(n, node, pkt.Token, endpoint)
			return nil
		})
	}
}

func handleProbePing(n *Nylon, node state.NodeId, wgEndpoint conn.Endpoint) {
	if node == n.Id {
		return
	}
	// check if link exists
	for _, neigh := range n.RouterState.Neighbours {
		for _, dep := range neigh.Eps {
			dep := dep.AsNylonEndpoint()
			ap, err := n.EndpointResolver.Get(dep.Address)
			if err == nil && ap == wgEndpoint.DstIPPort() && neigh.Id == node {
				// we have a link

				// port hopping tombstone (burned port): the ping still matched
				// so the pong above went out symmetrically, but never
				// resurrect the quarantined link — renewing it would keep a
				// dead port ranked active until the tombstone grace removes it
				if dep.IsExhausted() {
					return
				}

				// refresh wireguard ep
				dep.WgEndpoint = wgEndpoint

				wasInactive := !dep.IsActive()
				dep.Renew()
				if wasInactive {
					ComputeRoutes(n.RouterState, n)
					n.UpdateNeighbour(node)
				}

				if n.DBG_log_probe {
					n.Log.Debug("probe from", "addr", ap.String())
				}
				return
			}
		}
	}
	// create a new link if we dont have a link
	for _, neigh := range n.RouterState.Neighbours {
		if neigh.Id == node {
			// port hopping: never learn a remote link inside a
			// factory-managed port range. The local node owns port
			// selection for those ranges (the port factory
			// materialises exactly one carrying link at a time); an
			// inbound packet from a range port that matches no
			// local link is a stale rotation artefact — the peer
			// answering or probing through a port the factory
			// rotated away from. Learning it would create an
			// immortal zombie: remote links are exempt from the
			// factory's tombstoning, are probed at the full stock
			// cadence, and every pong renews them, so the peer
			// keeps answering and the port never goes quiet.
			if n.hopOwnedEndpoint(node, wgEndpoint.DstIPPort()) {
				return
			}
			newEp := state.NewEndpoint(wgEndpoint.DstIPPort().String(), true, wgEndpoint, &n.RouterTunables)
			newEp.Renew()
			// Port hopping / NAT churn hygiene: a peer's flow rotates its SOURCE
			// mapping too (per-flow NAT allocations change on every destination
			// rotation). The freshly learned link is by definition where the peer
			// lives NOW; any older remote link of this peer is a rotation leftover
			// whose only life support is the 1 Hz probe->pong loop through its own
			// pinned hint port — the pongs renew it, which keeps the NAT mapping
			// alive, which keeps the pongs coming. Supersede them (exhaust now,
			// grace removal later); late pongs cannot resurrect them (the
			// IsExhausted guards in this file). Configured (non-remote) links are
			// the operator's explicit multipath and stay untouched; a genuinely
			// still-alive source re-learns its link on the peer's next ping.
			for _, ep := range neigh.Eps {
				if !ep.IsRemote() || ep.IsExhausted() {
					continue
				}
				old := ep.AsNylonEndpoint()
				if old == newEp || old.Address == newEp.Address {
					continue
				}
				old.MarkExhausted()
				n.scheduleExhaustedLinkRemoval(node, old.Address)
				n.Log.Debug("probe from new source: superseded older remote link", "node", node, "link", old.Address, "new", newEp.Address)
			}
			neigh.Eps = append(neigh.Eps, newEp)
			// push route update to improve convergence time
			ComputeRoutes(n.RouterState, n)
			n.UpdateNeighbour(node)
			return
		}
	}
}

// adoptLinkEndpoint re-pins the neighbour link matching an inbound nylon
// packet's arrival endpoint to that endpoint. A link's stored wireguard
// endpoint otherwise only follows probe pings, which a port-hopping peer may
// not send for a full relaxed probe interval — or at all, when its rotation
// period is shorter — so the stored endpoint can linger on a port the peer
// rotated away from while its data and control traffic have long since moved
// on. Route updates and other control traffic keep flowing on the peer's
// CURRENT carrying port, making their arrival endpoint the freshest flow to
// answer and probe through. Probe pongs are deliberately NOT adopted (see
// handleProbePong): a pong is sent to wherever OUR ping came from, so
// adopting it pins the link's outbound port onto itself.
//
// Must run on the dispatch loop.
func (n *Nylon) adoptLinkEndpoint(node state.NodeId, ep conn.Endpoint) {
	if ep == nil {
		return
	}
	ap := ep.DstIPPort()
	for _, neigh := range n.RouterState.Neighbours {
		if neigh.Id != node {
			continue
		}
		for _, dep := range neigh.Eps {
			dep := dep.AsNylonEndpoint()
			lap, err := n.EndpointResolver.Get(dep.Address)
			if err == nil && lap == ap {
				if dep.WgEndpoint != ep {
					dep.WgEndpoint = ep
				}
				return
			}
		}
		return
	}
}

// scheduleExhaustedLinkRemoval removes the neighbour's link for addr after the
// tombstone grace (hopTombstoneGrace), but ONLY if it is still exhausted by
// then — a port redrawn inside the grace window materialises a FRESH
// (non-exhausted) link that must survive the stale timer, and a source
// genuinely still alive re-learns its link on the peer's next ping. Used by
// the port factory's rotation tombstoning and by the remote-link supersede
// path in handleProbePing. Safe to call more than once for the same address:
// extra runs find nothing eligible to delete.
func (n *Nylon) scheduleExhaustedLinkRemoval(node state.NodeId, addr string) {
	time.AfterFunc(hopTombstoneGrace, func() {
		if n.Context.Err() != nil {
			return
		}
		n.Dispatch(func() error {
			neigh := n.RouterState.GetNeighbour(node)
			if neigh == nil {
				return nil
			}
			for i, ep := range neigh.Eps {
				if ep.AsNylonEndpoint().Address == addr && ep.IsExhausted() {
					neigh.Eps = slices.Delete(neigh.Eps, i, i+1)
					break
				}
			}
			return nil
		})
	})
}

// hopArrivalSig is the arrival signature used to rate-limit data-traffic
// adoption: the peer's source address plus the local reply-port hint of the
// port the packet arrived on.
type hopArrivalSig struct {
	addr netip.AddrPort
	hint uint16
}

// hopAdoptDataArrival re-pins the neighbour link matching an inbound DATA
// packet's arrival endpoint to that endpoint (see adoptLinkEndpoint). Data is
// the freshest and most abundant signal of which local port the peer's flow
// is currently addressed to — relying only on probe pings and control traffic
// left the pin a full probe/adoption cycle behind every rotation, and every
// reader of the pin (the 1 Hz probe stream, the 1s SetEndpoints refresh of the
// device peer endpoint) kept answering through the port the peer just rotated
// away from.
//
// Runs on the TC hot path: the signature check is a lock-free sync.Map read,
// so the cost per packet is negligible, and the adoption itself is dispatched
// at most once per arrival-port change (per rotation), never per packet.
// Nylon protocol packets are deliberately excluded — their adoption paths
// are the existing, pong-aware ones (see handleNylonPacket).
func (n *Nylon) hopAdoptDataArrival(peer *device.Peer, ep conn.Endpoint) {
	if ep == nil {
		return
	}
	nt := n.PeerMap.Load()
	if nt == nil {
		return
	}
	node, ok := (*nt)[state.NyPublicKey(peer.GetPublicKey())]
	if !ok {
		return
	}
	sig := hopArrivalSig{addr: ep.DstIPPort()}
	if h, ok := ep.(interface{ PortHint() uint16 }); ok {
		sig.hint = h.PortHint()
	}
	if v, loaded := n.portHopping.hintSigs.Load(node); loaded && v.(hopArrivalSig) == sig {
		return
	}
	n.portHopping.hintSigs.Store(node, sig)
	n.Dispatch(func() error {
		n.adoptLinkEndpoint(node, ep)
		return nil
	})
}

func handleProbePong(n *Nylon, node state.NodeId, token uint64, ep conn.Endpoint) {
	linkHealth, ok := n.PingBuf.GetAndDelete(token)
	if !ok {
		return
	}
	health := linkHealth.Value()
	if health.Peer != "" && health.Peer != node {
		n.Log.Warn("probe came back from wrong peer", "expected", health.Peer, "actual", node)
		return
	}
	receivedAt := time.Now()
	latency := receivedAt.Sub(health.TimeSent)
	health.Complete(protocol.EndpointProbeStatus_ENDPOINT_PROBE_REPLIED, latency)

	// check if link exists
	for _, neigh := range n.RouterState.Neighbours {
		for _, dep := range neigh.Eps {
			dpLink := dep.AsNylonEndpoint()
			ap, err := n.EndpointResolver.Get(dpLink.Address)
			if err == nil && ap == ep.DstIPPort() && neigh.Id == node {
				// we have a link
				if n.DBG_log_probe {
					n.Log.Debug("probe back", "peer", node, "ping", latency)
				}

				// port hopping tombstone (burned port): the in-flight probe
				// measurement was already completed above, but the quarantined
				// link must not be renewed — late pongs are exactly what the
				// grace window exists for
				if dpLink.IsExhausted() {
					return
				}

				dpLink.Renew()
				dpLink.UpdatePing(latency)
				if nep := dpLink.AsNylonEndpoint(); nep != nil {
					nep.RecordProbe(true)
				}

				// NOTE: do NOT adopt the pong's endpoint into dpLink.WgEndpoint.
				// The address is identical to the link's by the match condition
				// above, so the only new information a pong can carry is the
				// local port our own probe ping happened to leave from —
				// re-adopting it is zero-information self-reinforcement that
				// pins this link's outbound socket to one port indefinitely
				// (measured: 94-96% of a peer's probe traffic locked onto a
				// single stale port across many rotations, a static flow TSPU
				// volume-bans within seconds). Inbound pings already track
				// genuine endpoint migrations (handleProbePing), and
				// GetWgEndpoint re-resolves whenever the resolver's answer
				// changes.

				ComputeRoutes(n.RouterState, n)
				return
			}
		}
	}
	// A pong that matches no link is an expected artefact of endpoint churn:
	// the link (a hop port rotated away from, or a learned remote endpoint
	// that expired) is reaped while a probe in flight to it is still coming
	// back. Warn once per (peer, address) per hour, then Debug — a storm of
	// these under load would otherwise bury the journal without carrying new
	// information.
	key := string(node) + "|" + ep.DstToString()
	if n.router.pongWarns == nil {
		n.router.pongWarns = make(map[string]time.Time)
	}
	if last, ok := n.router.pongWarns[key]; !ok || time.Since(last) >= time.Hour {
		n.router.pongWarns[key] = time.Now()
		n.Log.Warn("probe came back and couldn't find link", "from", ep.DstToString(), "node", node)
		return
	}
	n.Log.Debug("probe came back and couldn't find link", "from", ep.DstToString(), "node", node)
}

func (n *Nylon) probeLinks(active bool) error {
	// probe links
	for _, neigh := range n.RouterState.Neighbours {
		for _, ep := range neigh.Eps {
			// port hopping: never spend packets on a carrying port that already
			// burned its budget (it is quarantined and only kept for late pongs)
			if ep.IsExhausted() {
				continue
			}
			if ep.IsActive() == active {
				// port hopping: factory-managed carrying links probe at a relaxed
				// cadence (see portFactory.probeReady) so idle probing does not burn
				// the port budget — but ONLY while the link is active. An inactive
				// link (never answered, or went dead) is probed at the stock
				// cadence: gating its recovery behind the relaxed interval stalled
				// tunnel setup for a full probe interval whenever the first
				// probe's pong was lost (integration: TestPortAsEndpointHoppingGate).
				if active && !n.hopProbeReady(neigh.Id, ep.AsNylonEndpoint().Address) {
					continue
				}
				_, err := n.sendEndpointProbe(neigh.Id, ep.AsNylonEndpoint(), n.ProbeTimeout)
				if err != nil {
					n.Log.Debug("probe failed", "error", err)
				}
			}
		}
	}
	return nil
}

func (n *Nylon) probeNew() error {
	// probe for new dp links
	for _, peer := range n.GetPeers(n.Id) {
		if !n.IsRouter(peer) {
			continue
		}
		neigh := n.RouterState.GetNeighbour(peer)
		if neigh == nil {
			continue
		}
		cfg := n.GetRouter(peer)
		for _, address := range cfg.Endpoints {
			// port hopping: range-form endpoints (e.g. "1.2.3.4:30000-40000")
			// are owned by the port factory, which materialises concrete
			// addr:port links as they are drawn; they are never probed as-is
			if spec, err := state.ParseEndpointSpec(address); err == nil && spec.IsRange() {
				continue
			}
			idx := slices.IndexFunc(neigh.Eps, func(link state.Endpoint) bool {
				return !link.IsRemote() && link.AsNylonEndpoint().Address == address
			})
			if idx == -1 {
				// add the link to the neighbour
				dpl := state.NewEndpoint(address, false, nil, &n.RouterTunables)
				neigh.Eps = append(neigh.Eps, dpl)
				idx = len(neigh.Eps) - 1
			}
			dpl := neigh.Eps[idx].AsNylonEndpoint()
			if _, err := n.EndpointResolver.Get(dpl.Address); err != nil {
				continue
			}
			if err := n.Probe(peer, dpl); err != nil {
				n.Log.Debug("discovery probe failed", "peer", peer, "address", dpl.Address, "error", err)
			}
		}
	}
	return nil
}
