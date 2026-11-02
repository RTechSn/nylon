//go:build integration

package integration

import (
	"expvar"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/perf"
	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/state"
)

func boolptr(v bool) *bool { return &v }

// stormTestRange is the server's port range for the rotation-storm stress
// tests: small enough that a hot storm sweeps it many times per second with
// auto_recycle, large enough that sweeps are not degenerate.
var stormTestRange = conn.PortRange{First: 30000, Last: 30049}

// stormRig builds the same shape as portModeRig but with the storm-test range.
func stormRig(t *testing.T) (*VirtualHarness, int, int, *VirtualLink, *VirtualLink) {
	t.Helper()
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234" // client's advertised endpoint
	bRange := "192.168.1.2"  // server's range address

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
	}

	bIdx := vh.IndexOf("b")
	vh.Central.Routers[bIdx].Endpoints = append(vh.Central.Routers[bIdx].Endpoints,
		bRange+":"+stormTestRange.String())

	fwd := vh.AddLinkRange(a1, "b", bRange, stormTestRange)
	rev := vh.AddLinkFromAddr(bRange, a1)

	return vh, vh.IndexOf("a"), bIdx, fwd, rev
}

// TestProactiveStormKeepsDispatchHealthy reproduces the operator's regime —
// proactive rotation at hundreds of rotations per second over a small range
// with auto_recycle — and asserts that the dispatch loop keeps up: the
// DispatchChannel (cap 128) must never saturate, because a saturated channel
// DISCARDS control-plane work (probe passes, exhausted-link removals, route
// handling), and a discarded removal leaks the tombstoned link forever.
//
// The rig heats BOTH directions: the client's storm rotates the destination
// port ~budget^-1 x pps times per second, and the server's replies/data ride
// the hinted port, so the client's arrival signature changes per rotation —
// the port-hopping data-arrival adoption dispatches once per rotation.
func TestProactiveStormKeepsDispatchHealthy(t *testing.T) {
	vh, aIdx, bIdx, fwd, rev := stormRig(t)

	vh.Local[aIdx].PortHoppingMode = state.HopModeProactive
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:   uint32ptr(2),
		RecentPorts:     uint32ptr(8),
		CooldownSeconds: uint32ptr(180),
		AutoRecycle:     boolptr(true),
	}

	errs := vh.Start()
	defer vh.Stop()

	var aDeliv, bDeliv atomic.Int64
	vh.Net.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		switch {
		case node == "b" && data[0] == 111:
			aDeliv.Add(1)
		case node == "a" && data[0] == 112:
			bDeliv.Add(1)
		}
		return true
	}

	na := vh.Nylons[aIdx].Load()
	nb := vh.Nylons[bIdx].Load()

	// queue-depth monitor: the dispatch channel must never approach its
	// capacity under the storm. Sampled from the test goroutine — len(chan)
	// is race-free.
	var maxA, maxB atomic.Int64
	go func() {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-vh.Context.Done():
				return
			case <-ticker.C:
				if d := int64(len(na.DispatchChannel)); d > maxA.Load() {
					maxA.Store(d)
				}
				if d := int64(len(nb.DispatchChannel)); d > maxB.Load() {
					maxB.Store(d)
				}
			}
		}
	}()

	// warmup: let both nodes boot (b starts 500ms after a) and the first
	// carrying endpoint materialise before the storm starts.
	time.Sleep(2 * time.Second)

	// storm: 2 x 1000 pkt/s, budget 2 -> ~500 rotations/s; the 50-port range
	// is swept and auto-recycled ~10x per second (the operator's regime, an
	// order of magnitude harsher: 500 ports at ~650 rotations/s).
	const runLen = 12 * time.Second
	dropsAtStart := perf.DispatchDropsTotal.Load()
	deadline := time.Now().Add(runLen)
	pktsAtStart := fwd.ForwardPackets()
	revPortsAtStart := len(rev.ReverseTimeline())
	for time.Now().Before(deadline) {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled")
		case err := <-errs:
			t.Fatal(err)
		default:
		}
		vh.Net.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		vh.Net.Send("b", "10.0.0.2", "10.0.0.1", []byte{112}, 64)
		time.Sleep(time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)

	// rotations ~ wire packets / budget (every budget-th packet rotates the
	// carrying port; distinct ports saturate at the range size under recycling)
	const budget = 2
	rotations := int(float64(fwd.ForwardPackets()-pktsAtStart) / float64(budget))
	revPorts := len(rev.ReverseTimeline()) - revPortsAtStart
	t.Logf("storm stats: ~%d forward rotations in %.1fs (%.0f/s, %d fwd packets), %d distinct reply ports, deliveries a->b=%d b->a=%d",
		rotations, runLen.Seconds(), float64(rotations)/runLen.Seconds(), fwd.ForwardPackets()-pktsAtStart, revPorts, aDeliv.Load(), bDeliv.Load())
	t.Logf("dispatch queue depth: client max=%d/128, server max=%d/128", maxA.Load(), maxB.Load())
	if v := expvar.Get("nylon:DispatchLatency (µs)"); v != nil {
		t.Logf("dispatch latency histogram: %s", v.String())
	}

	if rotations < 2000 {
		t.Fatalf("storm did not materialise: only %d rotations in %s (need >= 2000 for a storm)", rotations, runLen)
	}

	// The invariant under test: the control plane keeps up with the storm.
	// A full channel discards control-plane functions (probe passes,
	// exhausted-link removals, ...). Leave headroom: anything sustained above
	// a quarter of the old 128-slot capacity is a saturation signal.
	const depthLimit = 32
	if maxA.Load() > depthLimit {
		t.Errorf("client dispatch queue saturated under the rotation storm: max depth %d > %d (dropped control-plane work)", maxA.Load(), depthLimit)
	}
	if maxB.Load() > depthLimit {
		t.Errorf("server dispatch queue saturated under the rotation storm: max depth %d > %d (dropped control-plane work)", maxB.Load(), depthLimit)
	}

	// nothing may be discarded at all: the coalesced producer must leave the
	// loop enough headroom to absorb scheduling stalls
	if got := perf.DispatchDropsTotal.Load() - dropsAtStart; got != 0 {
		t.Errorf("%d control-plane functions were discarded under the rotation storm (perf.DispatchDropsTotal)", got)
	}

	// the tunnel must deliver continuously through the storm
	if got := aDeliv.Load(); got < 8000 {
		t.Errorf("only %d/12000 a->b packets delivered through the storm", got)
	}
	if got := bDeliv.Load(); got < 8000 {
		t.Errorf("only %d/12000 b->a packets delivered through the storm", got)
	}
}

// TestStormSurvivesDispatchBlackout is the resilience discriminator for the
// operator's field report ("after a while: dispatch channel is full,
// discarded function"): the dispatch loop is single-threaded, so whenever the
// process cannot run it for a stretch - cgroup CPU-quota throttling on a busy
// VPS, a GC pause, machine hiccup - every producer keeps enqueueing. With a
// per-rotation producer at ~1800/s (budget 1 at 2000 pkt/s per direction), a
// 600ms stall queues ~1000 functions - past even a 512-slot channel - and
// the overflow is DISCARDED (the report's dropped probe passes and
// exhausted-link removals, the latter leaking tombstones forever); with the
// coalesced producer the same stall queues a bounded handful and nothing is
// lost.
//
// The rig reproduces the stall directly: a dispatched closure that sleeps
// blocks the loop exactly like an unscheduled goroutine would. Both nodes'
// loops are blacked out simultaneously - the client's arrivals (server
// replies from the rotated port) and the server's arrivals (client data on
// the rotated port) are both storm-rate producers.
func TestStormSurvivesDispatchBlackout(t *testing.T) {
	vh, aIdx, bIdx, fwd, rev := stormRig(t)

	vh.Local[aIdx].PortHoppingMode = state.HopModeProactive
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:   uint32ptr(1),
		RecentPorts:     uint32ptr(8),
		CooldownSeconds: uint32ptr(180),
		AutoRecycle:     boolptr(true),
	}

	errs := vh.Start()
	defer vh.Stop()

	var aDeliv, bDeliv atomic.Int64
	vh.Net.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		switch {
		case node == "b" && data[0] == 111:
			aDeliv.Add(1)
		case node == "a" && data[0] == 112:
			bDeliv.Add(1)
		}
		return true
	}

	na := vh.Nylons[aIdx].Load()
	nb := vh.Nylons[bIdx].Load()

	var maxDepthA, maxDepthB atomic.Int64
	go func() {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-vh.Context.Done():
				return
			case <-ticker.C:
				if d := int64(len(na.DispatchChannel)); d > maxDepthA.Load() {
					maxDepthA.Store(d)
				}
				if d := int64(len(nb.DispatchChannel)); d > maxDepthB.Load() {
					maxDepthB.Store(d)
				}
			}
		}
	}()

	time.Sleep(2 * time.Second)

	// hot storm: budget 1 -> one rotation per packet; 2000 pkt/s per direction
	// is a producer rate ~3x the operator's ~650/s, on BOTH nodes
	storm := func(d time.Duration) {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			select {
			case <-vh.Context.Done():
				return
			case err := <-errs:
				t.Error(err)
				return
			default:
			}
			vh.Net.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			vh.Net.Send("b", "10.0.0.2", "10.0.0.1", []byte{112}, 64)
			time.Sleep(500 * time.Microsecond)
		}
	}
	storm(2 * time.Second)

	// the blackout: block BOTH dispatch loops for 600ms mid-storm - longer
	// than even the deepened 512-slot queue can absorb at this producer rate
	dropsBefore := perf.DispatchDropsTotal.Load()
	blackoutA := core.NewDispatchFuture(na, func() (struct{}, error) {
		time.Sleep(600 * time.Millisecond)
		return struct{}{}, nil
	})
	blackoutB := core.NewDispatchFuture(nb, func() (struct{}, error) {
		time.Sleep(600 * time.Millisecond)
		return struct{}{}, nil
	})
	storm(1500 * time.Millisecond)
	if _, err := blackoutA.Await(vh.Context); err != nil {
		t.Fatalf("client blackout closure did not run: %v", err)
	}
	if _, err := blackoutB.Await(vh.Context); err != nil {
		t.Fatalf("server blackout closure did not run: %v", err)
	}
	storm(2 * time.Second)
	time.Sleep(500 * time.Millisecond)

	rotations := fwd.ForwardPackets() // budget 1: packets == rotations
	t.Logf("blackout storm: ~%d rotations, deliveries a->b=%d b->a=%d, max queue depth client=%d server=%d, dispatch drops during blackout phase=%d",
		rotations, aDeliv.Load(), bDeliv.Load(), maxDepthA.Load(), maxDepthB.Load(), perf.DispatchDropsTotal.Load()-dropsBefore)
	_ = rev

	if rotations < 4000 {
		t.Fatalf("storm did not materialise: only %d rotations", rotations)
	}

	// THE invariant: a 600ms loop stall on both nodes in the middle of a
	// ~1800/s rotation storm must not discard ANY control-plane work
	if got := perf.DispatchDropsTotal.Load() - dropsBefore; got != 0 {
		t.Errorf("the dispatch blackout discarded %d control-plane functions under the rotation storm", got)
	}

	// and the tunnel keeps delivering throughout
	if got := aDeliv.Load(); got < 4000 {
		t.Errorf("only %d a->b packets delivered through the storm + blackout", got)
	}
	if got := bDeliv.Load(); got < 4000 {
		t.Errorf("only %d b->a packets delivered through the storm + blackout", got)
	}
}
