package core

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
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
	return newHopFixturesNylonWithLog(t, deadThreshold, io.Discard)
}

// newHopFixturesNylonWithLog is newHopFixturesNylon with a custom log sink
// (used by the rate-limit tests to count emitted lines).
func newHopFixturesNylonWithLog(t *testing.T, deadThreshold time.Duration, w io.Writer) *Nylon {
	t.Helper()
	// LevelDebug so the rate-limit tests can count the demoted Debug lines too
	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
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

// hopLinkByAddr returns the neighbour's non-remote link with the given
// address, or nil.
func hopLinkByAddr(neigh *state.Neighbour, addr string) state.Endpoint {
	for _, ep := range neigh.Eps {
		if !ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
			return ep
		}
	}
	return nil
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
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind(),
		specs: []state.EndpointSpec{{Host: ip.String(), Ports: state.PortRange{First: 30000, Last: 30009}}}}

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

	// materialise the adopted endpoint's link the way the bootstrap path
	// would have, and give it a measurement (an active, measured predecessor)
	f.reconcileLinks()
	if bootLink := hopLinkByAddr(n.RouterState.GetNeighbour("b"), boot.String()); bootLink == nil {
		t.Fatal("precondition: the adopted carrying link must be materialised before rotation")
	} else {
		bootLink.AsNylonEndpoint().Renew()
		bootLink.AsNylonEndpoint().UpdatePing(20 * time.Millisecond)
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
	// link bookkeeping is reconciled lazily, not dispatched per rotation
	f.reconcileLinks()

	// the rotated-to endpoint materialises as a healthy link
	neigh := n.RouterState.GetNeighbour("b")
	link := hopLinkByAddr(neigh, next.DstIPPort().String())
	if link == nil {
		t.Fatalf("rotated endpoint %v was not materialised as a link", next.DstIPPort())
	}
	if link.IsExhausted() {
		t.Fatal("the freshly drawn carrying link must not be exhausted")
	}
	// the rotated-away port must be tombstoned by the same pass
	if old := hopLinkByAddr(neigh, boot.String()); old == nil || !old.IsExhausted() {
		t.Fatal("the retired carrying link must be tombstoned by reconciliation")
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

// TestHopRotationStormKeepsEndpointHealthy pins the load-stability rework:
// with the default budget (12 packets) a saturated link rotates its carrying
// port hundreds of times per second. The rotation hot path must not enqueue
// dispatch work (a storm would drown the dispatch loop and links would be
// born as tombstones — the pool retires synchronously, the dispatch lags),
// the neighbour must never lose its healthy endpoint (routes must not flap
// to infinity between rotations), and the intermediate ports of the storm
// must never become links.
func TestHopRotationStormKeepsEndpointHealthy(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	ip := netip.MustParseAddr("192.168.1.2")
	// a wide range with a long cooldown: 60 rotations must not exhaust it
	pool := state.NewPortPool([]state.PortGroup{{Addr: ip, Ports: state.PortRange{First: 30000, Last: 30999}}},
		state.PortPoolConfig{Recent: 16, Cooldown: time.Hour, Samples: 4})
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind(), specs: []state.EndpointSpec{
		{Host: ip.String(), Ports: state.PortRange{First: 30000, Last: 30999}},
	}}
	neigh := n.RouterState.GetNeighbour("b")

	// bootstrap: the first carrying endpoint is drawn and materialised, then
	// measured (simulates the first probe pongs)
	f.drawAndMaterialize()
	f.mu.Lock()
	first := f.current
	f.mu.Unlock()
	firstLink := hopLinkByAddr(neigh, first.String())
	if firstLink == nil {
		t.Fatal("bootstrap did not materialise the carrying link")
	}
	// CAUTION: order matters — Renew() on a cold (inactive) link resets the
	// history and EWMA, so the measurement must be planted after activation
	// (mirrors the production seed ordering in materializeCarrying). More
	// than MinimumConfidenceWindow samples so the confidence-gated
	// StabilizedPing reports the real RTT, like a link that carried
	// traffic for a while.
	firstLink.AsNylonEndpoint().Renew()
	for i := 0; i < 20; i++ {
		firstLink.AsNylonEndpoint().UpdatePing(20 * time.Millisecond)
	}
	beforeMetric := firstLink.Metric()
	if beforeMetric == state.INF {
		t.Fatal("precondition: the predecessor link must have a finite metric")
	}

	// rotation storm: rotate 60 times as fast as the send path can, without
	// draining the dispatch loop (it is busy — that is the storm scenario)
	cur, err := f.bind.ParseEndpoint(first.String())
	if err != nil {
		t.Fatalf("parse first endpoint: %v", err)
	}
	for i := 0; i < 60; i++ {
		cur, err = f.NextHopEndpoint(nil, cur)
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	if q := len(n.DispatchChannel); q != 0 {
		t.Fatalf("the rotation hot path enqueued %d dispatch closures; rotation bookkeeping must be reconciled lazily", q)
	}

	// a single reconciliation pass (the 1s SyncApplicationState tick) absorbs
	// the whole storm
	f.reconcileLinks()

	f.mu.Lock()
	final := f.current
	f.mu.Unlock()
	finalLink := hopLinkByAddr(neigh, final.String())
	if finalLink == nil {
		t.Fatal("the carrying endpoint was not materialised by reconciliation")
	}
	if finalLink.IsExhausted() {
		t.Fatal("the current carrying link must never be a tombstone")
	}
	if !finalLink.IsActive() {
		t.Fatal("the seeded carrying link must be active immediately (routes must not wait for the first pong)")
	}
	if got := finalLink.Metric(); got != beforeMetric {
		t.Fatalf("route cost not continuous across the storm: metric %d, want %d (the predecessor's)", got, beforeMetric)
	}
	if best := neigh.BestEndpoint(); best == nil || best.AsNylonEndpoint().Address != final.String() {
		t.Fatalf("BestEndpoint must be the current carrying link, got %v", best)
	}
	if !firstLink.IsExhausted() {
		t.Fatal("the predecessor link must be tombstoned once its successor is materialised")
	}
	// the storm's intermediate ports never became links
	if len(neigh.Eps) != 2 {
		t.Fatalf("expected exactly current + predecessor links after the storm, got %d: %v", len(neigh.Eps), neigh.Eps)
	}
}

// TestHopRotationLogRateLimited pins the journal behaviour under load: one
// Info line per second that counts the rotations it covers ("rotations=N"),
// everything else Debug. A rotation storm must not flood the journal.
func TestHopRotationLogRateLimited(t *testing.T) {
	lb := &lockedBuffer{}
	n := newHopFixturesNylonWithLog(t, time.Hour, lb)
	ip := netip.MustParseAddr("192.168.1.2")
	pool := state.NewPortPool([]state.PortGroup{{Addr: ip, Ports: state.PortRange{First: 30000, Last: 30999}}},
		state.PortPoolConfig{Recent: 16, Cooldown: time.Hour, Samples: 4})
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind()}

	cur, err := f.bind.ParseEndpoint("192.168.1.2:30001")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 0; i < 10; i++ {
		cur, err = f.NextHopEndpoint(nil, cur)
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	out := lb.String()
	if got := strings.Count(out, "level=INFO"); got != 1 {
		t.Fatalf("expected exactly 1 Info rotation line (the first rotation logs immediately), got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "rotations=1") {
		t.Fatalf("the first rotation must log its own Info line:\n%s", out)
	}
	if got := strings.Count(out, "level=DEBUG"); got != 9 {
		t.Fatalf("expected the remaining 9 rotations inside the interval at Debug, got %d", got)
	}
	if !strings.Contains(out, "carrying endpoint rotated") {
		t.Fatalf("rotations must still be logged:\n%s", out)
	}
}

// TestHopPoolExhaustionWarnRateLimited pins the pool-exhaustion warning: at
// most one Warn per minute while rotation is stalled, Debug in between. The
// warning must carry the pool stats so the capacity trade-off (range size /
// cooldown vs packets-per-second / budget) is diagnosable.
func TestHopPoolExhaustionWarnRateLimited(t *testing.T) {
	lb := &lockedBuffer{}
	n := newHopFixturesNylonWithLog(t, time.Hour, lb)
	ip := netip.MustParseAddr("192.168.1.2")
	pool := state.NewPortPool([]state.PortGroup{{Addr: ip, Ports: state.PortRange{First: 30000, Last: 30001}}},
		state.PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 2})
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind()}

	cur, err := f.bind.ParseEndpoint("192.168.1.2:30000")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// rotate until the 2-port pool is exhausted (1h cooldown)
	var lastErr error
	for i := 0; i < 4; i++ {
		cur, lastErr = f.NextHopEndpoint(nil, cur)
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("precondition: the pool should have been exhausted")
	}
	// trigger the stall path a few more times inside the warn interval
	for i := 0; i < 3; i++ {
		if _, err := f.NextHopEndpoint(nil, cur); err == nil {
			t.Fatal("expected the exhausted pool to keep failing")
		}
	}
	out := lb.String()
	if got := strings.Count(out, "level=WARN"); got != 1 {
		t.Fatalf("expected exactly 1 pool-exhaustion Warn per interval, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "rotation stalled") || !strings.Contains(out, "cooling=2") {
		t.Fatalf("the Warn must name the stall and the pool stats:\n%s", out)
	}
}

// TestProbePongUnmatchedWarnRateLimited pins the unmatched-pong warning
// rate limit: a churn artefact (a probe returning after its link was reaped)
// warns once per (peer, address) per hour and drops to Debug afterwards —
// under load these fire in bursts and must not bury the journal.
func TestProbePongUnmatchedWarnRateLimited(t *testing.T) {
	lb := &lockedBuffer{}
	n := newHopFixturesNylonWithLog(t, time.Hour, lb)

	ep, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30914")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 0; i < 3; i++ {
		n.PingBuf.Set(uint64(0x1000+i), EpPing{
			TimeSent: time.Now(),
			Peer:     "b",
			Complete: func(protocol.EndpointProbeStatus, time.Duration) {},
		}, time.Second)
		handleProbePong(n, "b", uint64(0x1000+i), ep)
	}
	out := lb.String()
	if got := strings.Count(out, "level=WARN"); got != 1 {
		t.Fatalf("expected exactly 1 unmatched-pong Warn, got %d:\n%s", got, out)
	}
	if got := strings.Count(out, "couldn't find link"); got != 3 {
		t.Fatalf("every unmatched pong must still be logged (1 Warn + 2 Debug), got %d:\n%s", got, out)
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
