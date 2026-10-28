package core

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

// newZombieTestFactory builds a factory for neighbour "b" owning the range
// 192.168.1.2:30000-30099 (registered with the Nylon's portHopping state, so
// hopOwnedEndpoint sees it) and draws its first carrying endpoint.
func newZombieTestFactory(t *testing.T, n *Nylon) (*portFactory, netip.AddrPort) {
	t.Helper()
	ip := netip.MustParseAddr("192.168.1.2")
	pool := state.NewPortPool([]state.PortGroup{{Addr: ip, Ports: state.PortRange{First: 30000, Last: 30099}}},
		state.PortPoolConfig{Recent: 16, Cooldown: time.Hour, Samples: 4})
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind(), specs: []state.EndpointSpec{
		{Host: ip.String(), Ports: state.PortRange{First: 30000, Last: 30099}},
	}}
	n.portHopping.factories = map[state.NodeId]*portFactory{"b": f}
	f.drawAndMaterialize()
	f.mu.Lock()
	cur := f.current
	f.mu.Unlock()
	if !cur.IsValid() {
		t.Fatal("the factory failed to draw a carrying endpoint")
	}
	return f, cur
}

// TestProbePingDoesNotLearnRemoteLinksInsideFactoryRanges pins the zombie
// incubation fix: a probe ping arriving from a port inside a factory-managed
// range, matching no local link, must NOT learn a remote link. Such a ping is
// by construction a stale rotation artefact (the peer answering or probing
// through a port the local node rotated away from); learning it creates an
// immortal zombie — remote links are exempt from the factory's tombstoning,
// are probed at the full stock cadence, and every pong renews them, so the
// peer keeps answering and the port never goes quiet (field report: the
// operator's router showed a tx/rx rate on every port ever used, including
// the very first ones, a dozen rotations later).
func TestProbePingDoesNotLearnRemoteLinksInsideFactoryRanges(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")
	_, cur := newZombieTestFactory(t, n)

	// a ping from an owned range port that matches no link (not the carrying
	// endpoint): must be ignored
	zEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30042")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	handleProbePing(n, "b", wrappedEndpoint{zEp})
	if l := remoteLinkByAddr(neigh, "192.168.1.2:30042"); l != nil {
		t.Fatalf("a ping from a factory-owned port learned a remote link (%s) — zombie incubation; the carrying endpoint is %s", l.AsNylonEndpoint().Address, cur)
	}
	if got := len(neigh.Eps); got != 1 {
		t.Fatalf("the neighbour must hold exactly the carrying link, got %d links", got)
	}

	// control: an address outside every factory range still learns a remote
	// link (that is the stock endpoint-roaming behaviour)
	rEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.9:51820")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	handleProbePing(n, "b", wrappedEndpoint{rEp})
	if l := remoteLinkByAddr(neigh, "192.168.1.9:51820"); l == nil {
		t.Fatal("a ping from an unowned address must still learn a remote link (endpoint roaming)")
	}
}

// TestReconcileTombstonesRemoteLinksInsideFactoryRanges pins the zombie
// cleanup backstop: reconciliation tombstones every non-current link whose
// address lies inside the factory's ranges, INCLUDING remote (learned) links
// (e.g. incubated before the factory was wired, or by an older build). A link
// on an owned port that is not the carrying endpoint is by construction
// retired; remote links outside the ranges keep the stock behaviour.
func TestReconcileTombstonesRemoteLinksInsideFactoryRanges(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")
	f, cur := newZombieTestFactory(t, n)

	// a zombie remote link inside the factory's range
	zEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30042")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	zombie := state.NewEndpoint("192.168.1.2:30042", true, zEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, zombie)

	// a genuine learned remote endpoint outside the range
	gEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.9:51820")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	genuine := state.NewEndpoint("192.168.1.9:51820", true, gEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, genuine)

	f.reconcileLinks()

	if !zombie.IsExhausted() {
		t.Fatal("a remote link inside the factory's range must be tombstoned (an owned non-carrying port is retired by construction)")
	}
	if genuine.IsExhausted() {
		t.Fatal("a learned remote endpoint outside the factory's ranges must keep stock behaviour")
	}
	if l := hopLinkByAddr(neigh, cur.String()); l == nil || l.IsExhausted() {
		t.Fatal("the carrying link must stay healthy")
	}
}

// TestAdoptLinkEndpointFollowsControlTraffic pins the stale-pin fix: a link's
// stored wireguard endpoint follows the arrival endpoint of every non-pong
// nylon packet (route updates, seqno requests and acks ride the peer's
// CURRENT carrying port, so they are the freshest flow to answer and probe
// through), while endpoints matching no link — and nil endpoints — are
// ignored.
func TestAdoptLinkEndpointFollowsControlTraffic(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	oldEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.1:1234")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("192.168.1.1:1234", false, oldEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)

	// control traffic arrives through a differently-tagged endpoint on the
	// same address (a range listener's TaggedEndpoint pinned to the current
	// carrying port): the link's stored endpoint must follow it
	fresh := wrappedEndpoint{oldEp}
	n.adoptLinkEndpoint("b", fresh)
	if link.WgEndpoint != conn.Endpoint(fresh) {
		t.Fatalf("the link's stored endpoint did not follow control traffic (still %T)", link.WgEndpoint)
	}

	// an endpoint matching no link of the neighbour: must not disturb it
	otherEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.1:9999")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n.adoptLinkEndpoint("b", wrappedEndpoint{otherEp})
	if link.WgEndpoint != conn.Endpoint(fresh) {
		t.Fatal("an endpoint matching no link must not disturb the link's stored endpoint")
	}

	// nil endpoint (defensive): no-op
	n.adoptLinkEndpoint("b", nil)
	if link.WgEndpoint != conn.Endpoint(fresh) {
		t.Fatal("a nil endpoint must be a no-op")
	}
}

// remoteLinkByAddr returns the neighbour's REMOTE link with the given address.
func remoteLinkByAddr(neigh *state.Neighbour, addr string) state.Endpoint {
	for _, ep := range neigh.Eps {
		if ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
			return ep
		}
	}
	return nil
}

// flipZombieFactorySpec simulates the DNS answer flip that produced the
// "every port still talking" field report: the range spec (and the pool
// groups) move to a different address, so ownsEndpoint no longer recognises
// links drawn under the OLD address — only the factory's drawn-port registry
// still knows they belong to this factory's lifecycle.
func flipZombieFactorySpec(t *testing.T, f *portFactory, first, last uint16) {
	t.Helper()
	flip := netip.MustParseAddr("192.168.9.9")
	f.mu.Lock()
	f.specs = []state.EndpointSpec{{Host: flip.String(), Ports: state.PortRange{First: first, Last: last}}}
	f.mu.Unlock()
	f.pool.SetGroups([]state.PortGroup{{Addr: flip, Ports: state.PortRange{First: first, Last: last}}})
}

// TestReconcileTombstonesDrawnPortsUnderSpecFlip pins the drawn-registry fix:
// a retired link must be tombstoned because the factory DREW its port, even
// when the spec host's resolution has since changed (dual-stack A/AAAA
// round-robin, DDNS flip). With the resolver-based ownsEndpoint alone, every
// link drawn before the flip was de-ownwed at its rotation moment: never
// exhausted, probed at the full 1s cadence, renewed by every pong — the
// router showed a live tx/rx rate on every port ever used.
func TestReconcileTombstonesDrawnPortsUnderSpecFlip(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")
	f, first := newZombieTestFactory(t, n)

	// a second draw rotates the carrying endpoint so the first link is
	// non-current at the next reconciliation pass
	f.drawAndMaterialize()
	f.mu.Lock()
	second := f.current
	f.mu.Unlock()
	if second == first {
		t.Fatal("the second draw must select a different carrying endpoint")
	}

	// control: after the flip the resolver-based check no longer owns the
	// first port (this is the regression the registry exists for)
	flipZombieFactorySpec(t, f, 30000, 30099)
	f.mu.Lock()
	specs := slices.Clone(f.specs)
	f.mu.Unlock()
	_ = specs
	ap, err := netip.ParseAddrPort(first.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.ownsEndpoint(ap) {
		t.Fatal("control: ownsEndpoint must be false for a pre-flip drawn port after the spec moved")
	}

	f.reconcileLinks()

	old := hopLinkByAddr(neigh, first.String())
	if old == nil || !old.IsExhausted() {
		t.Fatal("a link on a port the factory DREW must be tombstoned even after the spec resolution flipped (registry-owned)")
	}
	cur := hopLinkByAddr(neigh, second.String())
	if cur == nil || cur.IsExhausted() {
		t.Fatal("the current carrying link must stay healthy")
	}
}

// TestProbePingLearningGuardCoversDrawnPorts pins the learning-guard half of
// the registry: after a retired link's grace removal, a stale probe ping
// from that port (the peer answering or probing through a port the factory
// rotated away from) must NOT learn a remote link — even when the resolver
// has since flipped and no longer recognises the port as in-range. Learning
// it would incubate an immortal zombie: remote links are probed at the full
// 1s cadence and renewed by every pong.
func TestProbePingLearningGuardCoversDrawnPorts(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")
	f, first := newZombieTestFactory(t, n)

	// the rotation completed and the grace has run: the retired link is gone
	old := hopLinkByAddr(neigh, first.String())
	if old == nil {
		t.Fatal("the drawn link must have been materialised")
	}
	old.AsNylonEndpoint().MarkExhausted()
	for i, ep := range neigh.Eps {
		if ep.AsNylonEndpoint().Address == first.String() {
			neigh.Eps = slices.Delete(neigh.Eps, i, i+1)
			break
		}
	}

	// the spec moves away (resolver flip): the in-range check alone would
	// now happily learn the stale port as a remote link
	flipZombieFactorySpec(t, f, 30000, 30099)

	zEp, err := conn.NewStdNetBind().ParseEndpoint(first.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	handleProbePing(n, "b", wrappedEndpoint{zEp})
	if l := remoteLinkByAddr(neigh, first.String()); l != nil {
		t.Fatalf("a stale ping from a registry-drawn retired port learned a remote link (%s) — zombie incubation", l.AsNylonEndpoint().Address)
	}
}

// TestLearnedRemoteLinkSupersedesOlderOnes pins the NAT-churn hygiene on the
// receiver: when a peer's flow rotates its SOURCE mapping (per-flow NAT
// allocations change on every destination rotation), the freshly learned
// remote link supersedes the peer's older remote links. Without the
// supersede, every old mapping kept its own immortal 1 Hz probe->pong loop
// (the pongs renew the link, the probes keep the NAT mapping alive).
func TestLearnedRemoteLinkSupersedesOlderOnes(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	r1Ep, err := conn.NewStdNetBind().ParseEndpoint("10.1.1.1:1111")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r1 := state.NewEndpoint("10.1.1.1:1111", true, r1Ep, &n.RouterTunables)
	r1.Renew()
	neigh.Eps = append(neigh.Eps, r1)

	cfgEp, err := conn.NewStdNetBind().ParseEndpoint("10.2.2.2:2222")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg := state.NewEndpoint("10.2.2.2:2222", false, cfgEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, cfg)

	// the peer's source rotates: a ping from a NEW address
	r2Ep, err := conn.NewStdNetBind().ParseEndpoint("10.3.3.3:3333")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	handleProbePing(n, "b", wrappedEndpoint{r2Ep})

	r2 := remoteLinkByAddr(neigh, "10.3.3.3:3333")
	if r2 == nil {
		t.Fatal("the new source must be learned (endpoint roaming)")
	}
	if !r1.IsExhausted() {
		t.Fatal("the older remote link must be superseded when a new source is learned")
	}
	if cfg.IsExhausted() {
		t.Fatal("a configured (non-remote) link is the operator's multipath and must not be superseded")
	}

	// a late pong for the superseded link must not resurrect it
	n.PingBuf.Set(0xC0FFEE, EpPing{
		TimeSent: time.Now(),
		Peer:     "b",
		Complete: func(protocol.EndpointProbeStatus, time.Duration) {},
	}, ttlcache.DefaultTTL)
	handleProbePong(n, "b", 0xC0FFEE, wrappedEndpoint{r1Ep})
	if !r1.IsExhausted() {
		t.Fatal("a late pong must not renew a superseded (exhausted) remote link")
	}

	// a genuinely still-alive source re-learns its link once the superseded
	// one is gone: the ping path above is the only recovery a remote source
	// has (note: re-learning it supersedes r2 in turn — roaming semantics)
	for i, ep := range neigh.Eps {
		if ep.AsNylonEndpoint().Address == r1.Address {
			neigh.Eps = slices.Delete(neigh.Eps, i, i+1)
			break
		}
	}
	handleProbePing(n, "b", wrappedEndpoint{r1Ep})
	r1b := remoteLinkByAddr(neigh, "10.1.1.1:1111")
	if r1b == nil || r1b.IsExhausted() {
		t.Fatal("a genuinely alive source must be able to re-learn its link after the grace removal")
	}
}

// TestHopProbeEndpointRidesCurrentPeerEndpoint pins the probe egress merge:
// when the link being probed points at the address the device is currently
// sending to, the probe must ride the peer's LIVE endpoint (fresh reply-port
// hint) instead of the link's stored pin — so the 1 Hz probe stream switches
// ports with the rotation, and the advertised-endpoint probe flow merges onto
// the carrying port instead of pinning a static flow onto the first port.
func TestHopProbeEndpointRidesCurrentPeerEndpoint(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)

	p := &device.Peer{}
	live, err := conn.NewStdNetBind().ParseEndpoint("10.0.0.5:9999")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p.SetEndpoints([]conn.Endpoint{live})

	sameAddr, err := conn.NewStdNetBind().ParseEndpoint("10.0.0.5:9999")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := n.hopProbeEndpoint(p, sameAddr); got != conn.Endpoint(live) {
		t.Fatalf("a probe to the peer's current address must ride the LIVE endpoint object (got %T, want the stored val[0])", got)
	}

	other, err := conn.NewStdNetBind().ParseEndpoint("10.0.0.6:9999")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := n.hopProbeEndpoint(p, other); got != conn.Endpoint(other) {
		t.Fatal("a probe to a different address must keep the link's own endpoint (multipath)")
	}

	empty := &device.Peer{}
	if got := n.hopProbeEndpoint(empty, other); got != conn.Endpoint(other) {
		t.Fatal("a peer without a current endpoint must keep the link's own endpoint")
	}
}

// TestHopAdoptDataArrivalDispatchesOnChange pins the TC data-arrival adoption
// rate limiter: the FIRST arrival through a new (address, reply-port) pair
// dispatches a link-pin adoption, and subsequent packets through the SAME pair
// do not. Arrivals from peers not in the PeerMap are ignored.
func TestHopAdoptDataArrivalDispatchesOnChange(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	linkEp, err := conn.NewStdNetBind().ParseEndpoint("10.1.1.1:1111")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("10.1.1.1:1111", false, linkEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)

	peer := &device.Peer{}
	nt := map[state.NyPublicKey]state.NodeId{state.NyPublicKey(device.NoisePublicKey{}): "b"}
	n.PeerMap.Store(&nt)

	// first data arrival through port 30001: one adoption dispatched
	// (the arrival endpoint is passed unwrapped: the range listener's
	// TaggedEndpoint implements PortHint directly)
	a1 := hintWrap(t, "10.1.1.1:1111", 30001)
	n.hopAdoptDataArrival(peer, a1)
	if got := len(n.DispatchChannel); got != 1 {
		t.Fatalf("first arrival through a new hint must dispatch exactly one adoption, got %d", got)
	}
	drainDispatch(t, n)
	if link.WgEndpoint != conn.Endpoint(a1) {
		t.Fatal("the dispatched adoption must have re-pinned the link")
	}

	// the same (address, hint) signature again: no dispatch
	n.hopAdoptDataArrival(peer, hintWrap(t, "10.1.1.1:1111", 30001))
	if got := len(n.DispatchChannel); got != 0 {
		t.Fatalf("a repeated arrival signature must not dispatch (got %d)", got)
	}

	// the rotation: same address, new reply-port hint -> dispatch
	a2 := hintWrap(t, "10.1.1.1:1111", 30042)
	n.hopAdoptDataArrival(peer, a2)
	if got := len(n.DispatchChannel); got != 1 {
		t.Fatalf("an arrival through the next carrying port must dispatch exactly one adoption, got %d", got)
	}
	drainDispatch(t, n)
	if link.WgEndpoint != conn.Endpoint(a2) {
		t.Fatal("the link pin must have followed the rotation")
	}

	// a peer not in the PeerMap: ignored entirely
	empty := map[state.NyPublicKey]state.NodeId{}
	n.PeerMap.Store(&empty)
	n.hopAdoptDataArrival(peer, hintWrap(t, "10.9.9.9:9", 1))
	if got := len(n.DispatchChannel); got != 0 {
		t.Fatalf("an arrival from an unknown peer must not dispatch (got %d)", got)
	}
}

// hintWrap builds an endpoint carrying a local reply-port hint, mirroring the
// range listener's TaggedEndpoint.
type hintWrapEndpoint struct {
	conn.Endpoint
	hintPort uint16
}

func (h *hintWrapEndpoint) PortHint() uint16 { return h.hintPort }

func hintWrap(t *testing.T, ap string, hint uint16) conn.Endpoint {
	t.Helper()
	ep, err := conn.NewStdNetBind().ParseEndpoint(ap)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &hintWrapEndpoint{Endpoint: ep, hintPort: hint}
}
