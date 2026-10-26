package core

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

// newHopFixturesNylon builds a minimal Nylon for the port-hopping regression
// tests: a router "a" with a single neighbour "b", an empty routing state (so
// ComputeRoutes and PushFullTable degenerate to no-ops on the Router
// interface), and a silent polyamide device so probe goroutines fail
// gracefully on LookupPeer instead of nil-panicking. No goroutines are
// started: DispatchChannel is drained manually by the tests.
func newHopFixturesNylon(t *testing.T, deadThreshold time.Duration) *Nylon {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancelCause(context.Background())
	tunables := state.DefaultRouterTunables()
	tunables.LinkDeadThreshold = deadThreshold

	n := &Nylon{
		Trace:           &NylonTrace{},
		RouterTunables:  tunables,
		Context:         ctx,
		Cancel:          cancel,
		DispatchChannel: make(chan func() error, 128),
		Log:             logger,
		PingBuf: ttlcache.New[uint64, EpPing](
			ttlcache.WithTTL[uint64, EpPing](5*time.Second),
			ttlcache.WithDisableTouchOnHit[uint64, EpPing](),
		),
		EndpointResolver: state.NewEndpointResolver(state.NewDNSResolver(nil)),
		ConfigState: state.ConfigState{
			CentralCfg: state.CentralCfg{
				Routers: []state.RouterCfg{{NodeCfg: state.NodeCfg{Id: "b"}}},
			},
			LocalCfg: state.LocalCfg{Id: "a"},
		},
	}
	n.router.log = logger
	n.RouterState = &state.RouterState{
		RouterTunables:  &n.RouterTunables,
		Id:              "a",
		SelfSeqno:       make(map[netip.Prefix]uint16),
		Routes:          make(map[netip.Prefix]state.SelRoute),
		RouteSelectedAt: make(map[netip.Prefix]time.Time),
		Sources:         make(map[state.Source]state.FD),
		Neighbours:      []*state.Neighbour{{Id: "b", Routes: make(map[netip.Prefix]state.NeighRoute)}},
		Advertised:      make(map[netip.Prefix]state.Advertisement),
	}
	dev := device.NewDevice(tun.NewDummyDevice("hopfix", 1420), conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, "hopfix"))
	n.Device = dev
	t.Cleanup(func() {
		_ = dev.Bind().Close()
		dev.Close()
		n.Cancel(nil)
	})
	return n
}

// drainDispatch runs everything currently queued on the dispatch channel on
// the test goroutine (the unit fixtures never start the dispatch loop).
func drainDispatch(t *testing.T, n *Nylon) {
	t.Helper()
	for {
		select {
		case fn := <-n.DispatchChannel:
			if err := fn(); err != nil {
				t.Fatalf("dispatched function failed: %v", err)
			}
		default:
			return
		}
	}
}

func hopTestPool(ip netip.Addr, first, last uint16) *state.PortPool {
	return state.NewPortPool([]state.PortGroup{{Addr: ip, Ports: state.PortRange{First: first, Last: last}}},
		state.PortPoolConfig{Recent: 4, Cooldown: time.Hour, Samples: 4})
}

// TestHopFactoryAdoptsDrawnEndpoint pins the bootstrap-race fix: when the
// device draws its FIRST carrying endpoint (exhausted == nil) but the factory
// already has one (the eager bootstrap beat the first send, or the hop source
// was re-wired), the existing endpoint must be adopted. The old behaviour drew
// a SECOND port, stranding the bootstrap port's materialised link as a healthy
// ghost: nothing ever exhausted it, it was probed at the full 1s cadence
// forever, and the peer's symmetric pongs kept renewing it.
func TestHopFactoryAdoptsDrawnEndpoint(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	ip := netip.MustParseAddr("192.168.1.2")
	pool := hopTestPool(ip, 30000, 30009)
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind()}

	// simulate the eager bootstrap having drawn and adopted a port
	boot, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("bootstrap Select: %v", err)
	}
	f.current = boot
	f.lastProbeAt = time.Now()

	// the device's first draw must return the SAME port, not a second one
	ep, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("NextHopEndpoint(first draw): %v", err)
	}
	if got := ep.DstIPPort(); got != boot {
		t.Fatalf("first draw returned %v, want the already-drawn carrying endpoint %v (a second draw strands the bootstrap link as a ghost)", got, boot)
	}

	// a budget-exhausted rotation must still retire the old port and draw a
	// fresh one — adoption must not have broken rotation
	next, err := f.NextHopEndpoint(nil, ep)
	if err != nil {
		t.Fatalf("NextHopEndpoint(rotation): %v", err)
	}
	if got := next.DstIPPort(); got == boot {
		t.Fatal("rotation returned the exhausted endpoint again")
	}
	drainDispatch(t, n)

	// the rotated-to endpoint materialises as a healthy link
	neigh := n.RouterState.GetNeighbour("b")
	var link state.Endpoint
	for _, ep := range neigh.Eps {
		if !ep.IsRemote() && ep.AsNylonEndpoint().Address == next.DstIPPort().String() {
			link = ep
		}
	}
	if link == nil {
		t.Fatalf("rotated endpoint %v was not materialised as a link", next.DstIPPort())
	}
	if link.IsExhausted() {
		t.Fatal("the freshly drawn carrying link must not be exhausted")
	}

	// a hop-state reset (config re-apply) re-adopts the current endpoint
	// instead of drawing yet another port
	again, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("NextHopEndpoint(re-wire): %v", err)
	}
	if got := again.DstIPPort(); got != next.DstIPPort() {
		t.Fatalf("re-wire returned %v, want the current endpoint %v", got, next.DstIPPort())
	}
}

// TestHopFactoryAdoptionSkipsCoolingEndpoint guards the adoption path against
// re-adopting a port that is quarantined in the pool: if the current endpoint
// somehow went into cooldown, the first draw must pick a fresh port instead.
func TestHopFactoryAdoptionSkipsCoolingEndpoint(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	ip := netip.MustParseAddr("192.168.1.2")
	pool := hopTestPool(ip, 30000, 30009)
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind()}

	cur, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	f.current = cur
	pool.Retire(cur) // burned between draws

	ep, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("NextHopEndpoint: %v", err)
	}
	if got := ep.DstIPPort(); got == cur {
		t.Fatal("adopted an endpoint that is cooling down; a fresh port must be drawn instead")
	}
}

// TestHopFactoryMaterializesRetiredPortAsTombstone pins the retire/materialise
// ordering race: when a drawn port is retired (pool cooldown) before its
// materialisation dispatch runs, the link must be BORN exhausted and scheduled
// for removal. The old behaviour created it healthy — retireLink's
// MarkExhausted dispatch had already run against a link list that did not
// contain the port, so the orphan never stopped probing (a ghost).
func TestHopFactoryMaterializesRetiredPortAsTombstone(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	ip := netip.MustParseAddr("192.168.1.2")
	pool := hopTestPool(ip, 30000, 30009)
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind()}

	ap, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	// the send path retires the port (budget burned) before the materialise
	// closure gets to run — exactly the retireLink-before-materializeLink race
	pool.Retire(ap)
	f.retireLink(ap)
	f.materializeLink(ap)
	drainDispatch(t, n)

	neigh := n.RouterState.GetNeighbour("b")
	var link state.Endpoint
	for _, ep := range neigh.Eps {
		if !ep.IsRemote() && ep.AsNylonEndpoint().Address == ap.String() {
			link = ep
		}
	}
	if link == nil {
		t.Fatalf("tombstone link for %v was not materialised (late pongs must still match it)", ap)
	}
	if !link.IsExhausted() {
		t.Fatal("a port retired before materialisation must be born as an exhausted tombstone, not a healthy ghost")
	}
}

// wrappedEndpoint mimics what production sees on a range listener: an inbound
// conn.Endpoint with the same address as the link's cached one but a different
// dynamic type (a *conn.TaggedEndpoint pinning the local receive port). The
// pong handler must not adopt it into the link's WgEndpoint.
type wrappedEndpoint struct {
	conn.Endpoint
}

// TestProbePongDoesNotRetagLink pins the ping-tag lock-in fix: a probe pong
// carries no new information (its address equals the link's by the match
// condition; its only delta is the local port OUR OWN ping left from), so
// adopting it into WgEndpoint is zero-information self-reinforcement that
// pinned one static outbound flow to a stale port across many rotations. The
// pong must renew the link and record the measurement, nothing more.
func TestProbePongDoesNotRetagLink(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	origEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30001")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("192.168.1.2:30001", false, origEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)

	completed := false
	n.PingBuf.Set(0xC0FFEE, EpPing{
		TimeSent: time.Now(),
		Peer:     "b",
		Complete: func(protocol.EndpointProbeStatus, time.Duration) { completed = true },
	}, time.Second)

	// same address, different endpoint object (the tag is the only delta)
	handleProbePong(n, "b", 0xC0FFEE, wrappedEndpoint{origEp})

	if !completed {
		t.Fatal("the in-flight probe measurement was not completed")
	}
	if !link.IsActive() {
		t.Fatal("the pong must still renew the healthy link")
	}
	if link.WgEndpoint != conn.Endpoint(origEp) {
		t.Fatalf("the pong retagged the link's WgEndpoint to %T — zero-information self-reinforcement that pins the outbound socket", link.WgEndpoint)
	}
}

// TestProbePongDoesNotResurrectTombstone pins the tombstone guard: a late pong
// matching an exhausted (burned port) link must complete the in-flight probe
// measurement but must NOT renew the quarantined link.
func TestProbePongDoesNotResurrectTombstone(t *testing.T) {
	n := newHopFixturesNylon(t, 300*time.Millisecond)
	neigh := n.RouterState.GetNeighbour("b")

	origEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30001")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("192.168.1.2:30001", false, origEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)
	link.MarkExhausted()
	link.Renew() // warm tombstone: active until it decays

	// let the link decay past LinkDeadThreshold so a Renew would be observable
	time.Sleep(450 * time.Millisecond)
	if link.IsActive() {
		t.Fatal("precondition: the tombstone should have decayed to inactive")
	}

	completed := false
	n.PingBuf.Set(0xBEEF, EpPing{
		TimeSent: time.Now(),
		Peer:     "b",
		Complete: func(protocol.EndpointProbeStatus, time.Duration) { completed = true },
	}, time.Second)

	handleProbePong(n, "b", 0xBEEF, wrappedEndpoint{origEp})

	if !completed {
		t.Fatal("the late pong must still complete the in-flight probe measurement")
	}
	if link.IsActive() {
		t.Fatal("a pong renewed the exhausted tombstone — quarantined ports must not be resurrected")
	}
	if !link.IsExhausted() {
		t.Fatal("the tombstone lost its exhausted flag")
	}
}

// TestProbePingSkipsTombstoneAndKeepsMigration pins both sides of the ping
// handler: a ping matching a tombstone must not resurrect it, while a ping
// matching a healthy link must keep adopting the endpoint (that is the
// legitimate NAT/endpoint-migration tracking — the pong retag removal must not
// have gutted it).
func TestProbePingSkipsTombstoneAndKeepsMigration(t *testing.T) {
	n := newHopFixturesNylon(t, 300*time.Millisecond)
	neigh := n.RouterState.GetNeighbour("b")

	origEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30001")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tomb := state.NewEndpoint("192.168.1.2:30001", false, origEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, tomb)
	tomb.MarkExhausted()
	tomb.Renew()
	time.Sleep(450 * time.Millisecond)
	if tomb.IsActive() {
		t.Fatal("precondition: the tombstone should have decayed to inactive")
	}

	// a ping to the burned port: must not resurrect the tombstone
	handleProbePing(n, "b", wrappedEndpoint{origEp})
	if tomb.IsActive() {
		t.Fatal("a ping renewed the exhausted tombstone — quarantined ports must not be resurrected")
	}

	// a healthy link: the ping retag (endpoint migration tracking) stays
	healthyEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30002")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("192.168.1.2:30002", false, healthyEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)

	handleProbePing(n, "b", wrappedEndpoint{healthyEp})
	if !link.IsActive() {
		t.Fatal("the ping must renew the healthy link")
	}
	if link.WgEndpoint != conn.Endpoint(wrappedEndpoint{healthyEp}) {
		t.Fatalf("the ping no longer tracks endpoint migration (WgEndpoint = %T); only the pong retag was removed", link.WgEndpoint)
	}
}
