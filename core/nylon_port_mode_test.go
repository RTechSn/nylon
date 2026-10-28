package core

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/state"
)

// portModeFactory builds a factory literal in the style of the hop-fixtures
// tests, with the rotation policy preset for the given mode.
func portModeFactory(t *testing.T, n *Nylon, mode string, period time.Duration, jitter uint32) *portFactory {
	t.Helper()
	ip := netip.MustParseAddr("192.168.1.2")
	f := &portFactory{n: n, node: "b", pool: hopTestPool(ip, 30000, 30009), bind: conn.NewStdNetBind(),
		specs:     []state.EndpointSpec{{Host: ip.String(), Ports: state.PortRange{First: 30000, Last: 30009}}},
		mode:      mode,
		period:    period,
		jitterPct: jitter,
	}
	return f
}

// TestPortModeStaticPinsFirstPort verifies the static carrying endpoint: the
// first draw and every subsequent request (including a defensive exhausted
// hand-over) return the FIRST port of the range, and nothing is ever retired
// into the pool.
func TestPortModeStaticPinsFirstPort(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	f := portModeFactory(t, n, state.HopModeStatic, 0, 0)

	first, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("first draw: %v", err)
	}
	if got := first.DstIPPort(); got != netip.MustParseAddrPort("192.168.1.2:30000") {
		t.Fatalf("static carrying = %v, want 192.168.1.2:30000 (first port of the range)", got)
	}

	// a defensive exhausted hand-over must NOT move the pin and must NOT
	// retire the pinned port into cooldown
	again, err := f.NextHopEndpoint(nil, first)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if again.DstIPPort() != first.DstIPPort() {
		t.Fatalf("static carrying moved to %v; the pin must never rotate", again.DstIPPort())
	}
	if f.pool.IsCooling(netip.MustParseAddrPort("192.168.1.2:30000")) {
		t.Fatal("static mode retired the pinned port into cooldown")
	}

	// the eager draw pins as well
	f2 := portModeFactory(t, n, state.HopModeStatic, 0, 0)
	f2.drawAndMaterialize()
	f2.mu.Lock()
	cur := f2.current
	f2.mu.Unlock()
	if !cur.IsValid() || cur.Port() != 30000 {
		t.Fatalf("static drawAndMaterialize pinned %v, want :30000", cur)
	}
}

// TestPortModeStaticRepinOnRangeChange verifies that a config change of the
// range re-pins the static carrying endpoint: the stale link is tombstoned,
// the current endpoint is cleared, and the next pass pins the new range's
// first port.
func TestPortModeStaticRepinOnRangeChange(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	f := portModeFactory(t, n, state.HopModeStatic, 0, 0)
	f.drawAndMaterialize()

	neigh := n.RouterState.GetNeighbour("b")
	if neigh == nil {
		t.Fatal("neighbour b missing")
	}
	old := hopLinkByAddr(neigh, "192.168.1.2:30000")
	if old == nil {
		t.Fatal("static link was not materialised")
	}

	// the operator narrows the range: 30200-30209
	f.mu.Lock()
	f.specs = []state.EndpointSpec{{Host: "192.168.1.2", Ports: state.PortRange{First: 30200, Last: 30209}}}
	f.mu.Unlock()
	f.refreshGroups()

	f.reconcileLinks()

	if !old.IsExhausted() {
		t.Fatal("the stale static link was not tombstoned on re-pin")
	}
	f.mu.Lock()
	cur := f.current
	f.mu.Unlock()
	if cur.IsValid() {
		t.Fatalf("current endpoint %v survived the re-pin; it must be cleared for the next pass", cur)
	}

	// the next pass re-pins to the new range's first port
	f.bootstrap()
	f.mu.Lock()
	cur = f.current
	f.mu.Unlock()
	if !cur.IsValid() || cur.Port() != 30200 {
		t.Fatalf("re-pinned carrying = %v, want :30200", cur)
	}
}

// TestPortModeTimedTriggerPredicate verifies the timed trigger schedule:
// not due before the deadline, due at/after it.
func TestPortModeTimedTriggerPredicate(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	f := portModeFactory(t, n, state.HopModeTimed, time.Minute, 0)
	neigh := n.RouterState.GetNeighbour("b")

	f.mu.Lock()
	f.current = netip.MustParseAddrPort("192.168.1.2:30000")
	f.nextRotate = time.Now().Add(time.Minute)
	f.mu.Unlock()
	if _, due := f.externalRotationDue(state.HopModeTimed, f.current, neigh); due {
		t.Fatal("timed rotation due before its deadline")
	}

	f.mu.Lock()
	f.nextRotate = time.Now().Add(-time.Second)
	f.mu.Unlock()
	reason, due := f.externalRotationDue(state.HopModeTimed, f.current, neigh)
	if !due || reason != "timed schedule" {
		t.Fatalf("overdue timed rotation: due=%v reason=%q", due, reason)
	}
}

// TestPortModeReactiveTriggerPredicate verifies the reactive trigger: a dead
// carrying link past its grace rotates, a young link is given time to prove
// itself, and a healthy link never rotates.
func TestPortModeReactiveTriggerPredicate(t *testing.T) {
	// a tiny liveness threshold so the grace window passes within the test
	n := newHopFixturesNylon(t, 20*time.Millisecond)
	f := portModeFactory(t, n, state.HopModeReactive, 0, 0)
	neigh := n.RouterState.GetNeighbour("b")

	cur := netip.MustParseAddrPort("192.168.1.2:30000")
	f.mu.Lock()
	f.current = cur
	f.mu.Unlock()

	// a cold, never-validated link younger than the grace window: not due
	// (the on-demand probe must get its chance)
	link := state.NewEndpoint(cur.String(), false, nil, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)
	if _, due := f.externalRotationDue(state.HopModeReactive, cur, neigh); due {
		t.Fatal("reactive rotation due inside the young-link grace window")
	}

	// past the grace and still never heard back: dead => due
	time.Sleep(40 * time.Millisecond)
	reason, due := f.externalRotationDue(state.HopModeReactive, cur, neigh)
	if !due || reason != "dead carrying link" {
		t.Fatalf("dead carrying link: due=%v reason=%q", due, reason)
	}

	// the same link renewed (heard back): healthy => not due
	link.Renew()
	if _, due := f.externalRotationDue(state.HopModeReactive, cur, neigh); due {
		t.Fatal("reactive rotation due on a healthy carrying link")
	}
}

// TestPortModeExternalRotateWithoutDevicePeer verifies the error path of the
// external rotation before the factory has been wired to a device peer.
func TestPortModeExternalRotateWithoutDevicePeer(t *testing.T) {
	n := newHopFixturesNylonWithLog(t, time.Hour, io.Discard)
	f := portModeFactory(t, n, state.HopModeTimed, time.Minute, 0)
	if err := f.externalRotate(state.HopModeTimed, time.Minute, 0, "timed schedule"); err == nil {
		t.Fatal("externalRotate succeeded without a device peer")
	}
	f.mu.Lock()
	reason := f.rotateReason
	f.mu.Unlock()
	if reason != "" {
		t.Fatalf("rotateReason leaked %q on the failure path", reason)
	}
}

// TestJitterIntervalBounds verifies the timed-mode interval draw: the result
// stays within period ± jitterPct percent, zero jitter is exact, and the
// maximum jitter keeps the interval positive.
func TestJitterIntervalBounds(t *testing.T) {
	period := 10 * time.Second

	// zero jitter: exact
	for range 32 {
		if got := jitterInterval(period, 0); got != period {
			t.Fatalf("jitterInterval(period, 0) = %v, want exactly %v", got, period)
		}
	}

	// 10%: within [9s, 11s]
	for range 1000 {
		got := jitterInterval(period, 10)
		if got < 9*time.Second || got > 11*time.Second {
			t.Fatalf("jitterInterval(period, 10) = %v, outside [9s, 11s]", got)
		}
	}

	// 50% (the ceiling): within [5s, 15s]
	for range 1000 {
		got := jitterInterval(period, 50)
		if got < 5*time.Second || got > 15*time.Second {
			t.Fatalf("jitterInterval(period, 50) = %v, outside [5s, 15s]", got)
		}
	}

	// degenerate inputs pass through
	if got := jitterInterval(0, 10); got != 0 {
		t.Fatalf("jitterInterval(0, 10) = %v, want 0", got)
	}
}

// TestResolveHopPolicyNylonWrapper verifies the Nylon-level policy
// resolution used by ensurePortFactories: central router entry wins over
// node.yaml, node.yaml wins when central has no hop fields.
func TestResolveHopPolicyNylonWrapper(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)

	// no hop fields anywhere: the static default
	p, src := n.resolveHopPolicy()
	if p.Mode != state.HopModeStatic || src != "default" {
		t.Fatalf("default policy: %+v source=%q", p, src)
	}

	// node.yaml pair applies when central has none
	n.LocalCfg.PortMode = state.HopModeTimed
	secs := uint32(90)
	n.LocalCfg.PortHopping = &state.PortHoppingCfg{PeriodSeconds: &secs}
	p, src = n.resolveHopPolicy()
	if p.Mode != state.HopModeTimed || p.Period != 90*time.Second || src != "node" {
		t.Fatalf("node policy: %+v source=%q", p, src)
	}

	// a central entry for THIS node wins wholesale
	n.CentralCfg.Routers = append(n.CentralCfg.Routers, state.RouterCfg{
		NodeCfg:     state.NodeCfg{Id: "a"},
		PortMode:    state.HopModeProactive,
		PortHopping: &state.PortHoppingCfg{BudgetPackets: uint32ptr2(24)},
	})
	p, src = n.resolveHopPolicy()
	if p.Mode != state.HopModeProactive || p.Budget != 24 || src != "central" {
		t.Fatalf("central policy: %+v source=%q", p, src)
	}
}

func uint32ptr2(v uint32) *uint32 { return &v }
