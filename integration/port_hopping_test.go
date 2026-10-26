//go:build integration

package integration

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// hopTestFlowBudget is the middlebox per-flow budget (TSPU volume-ban
// emulation): every (src flow, dst flow) is dropped after this many packets.
// The worst-case empirical TSPU budget is ~16-20 packets per flow.
const hopTestFlowBudget = 16

// hopTestRange is the server's port range in these tests.
var hopTestRange = conn.PortRange{First: 30000, Last: 30099}

func uint32ptr(v uint32) *uint32 { return &v }

// TestPortAsEndpointHoppingGate is the port-as-endpoint acceptance gate: a
// client whose only configured endpoint for the server is a port range must
// sustain traffic through a middlebox that permanently bans every flow after
// 16 packets, by rotating its carrying port well before the budget is spent
// (rotation budget 12 < 16).
func TestPortAsEndpointHoppingGate(t *testing.T) {
	//defer goleak.VerifyNone(t)
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234"  // client's advertised endpoint
	b1 := "192.168.1.2:30000" // server's primary endpoint
	bRange := "192.168.1.2"   // server's range address

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
		b1: "b",
	}

	// the server advertises a port range; the exact endpoint entry above is
	// appended automatically by the harness and keeps a stock link alive too
	bIdx := vh.IndexOf("b")
	vh.Central.Routers[bIdx].Endpoints = append(vh.Central.Routers[bIdx].Endpoints,
		bRange+":"+hopTestRange.String())

	// the client runs the hopping policy: rotate after 12 wire packets,
	// short cooldown so the 100-port test range never runs dry
	aIdx := vh.IndexOf("a")
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:    uint32ptr(12),
		CooldownSeconds:  uint32ptr(5),
		RecentPorts:      uint32ptr(32),
		CandidateSamples: uint32ptr(16),
	}

	// client -> server: any port of the range reaches the server; the
	// middlebox bans each (client, server:port) flow after 16 packets
	fwd := vh.AddLinkRange(a1, "b", bRange, hopTestRange).WithFlowBudget(hopTestFlowBudget)
	// server -> client: the reply source port follows the flow (range
	// listener semantics); per-flow budget as well
	rev := vh.AddLinkFromAddr(bRange, a1).WithFlowBudget(hopTestFlowBudget)
	_ = rev

	errs := vh.Start()

	vn := vh.Net
	var deliveries atomic.Int64
	var firstDelivery, lastDelivery atomic.Int64
	start := time.Now()
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && src.String() == "10.0.0.1" && dst.String() == "10.0.0.2" && data[0] == 111 {
			now := time.Since(start).Milliseconds()
			firstDelivery.CompareAndSwap(0, now)
			lastDelivery.Store(now)
			deliveries.Add(1)
		}
		return true
	}

	// sustained traffic: 1 packet per 100ms for 15 seconds (150 packets)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 150; i++ {
			select {
			case <-vh.Context.Done():
				return
			case <-time.After(100 * time.Millisecond):
				vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
	case err := <-errs:
		t.Fatal(err)
	}
	// let in-flight packets settle
	time.Sleep(500 * time.Millisecond)
	vh.Stop()

	got := deliveries.Load()
	t.Logf("delivered %d/150 packets through the budget middlebox; %d distinct carrying ports",
		got, fwd.DistinctDstPorts())

	if got < 120 {
		t.Errorf("only %d/150 packets were delivered; port hopping failed to sustain traffic", got)
	}
	if ports := fwd.DistinctDstPorts(); ports < 8 {
		t.Errorf("only %d distinct carrying ports were used; rotation is not happening", ports)
	}
	if first, last := firstDelivery.Load(), lastDelivery.Load(); last-first < 10_000 {
		t.Errorf("delivery window was only %d ms; expected sustained delivery for the full run", last-first)
	}
}

// TestPortAsEndpointRangeOnlyHoppingGate is the range-only variant of the
// acceptance gate: the server advertises NOTHING but the port range — the
// exact shape of a real deployment behind TSPU, where there is no static
// endpoint to fall back to. Every packet (data, probes, handshake initiations
// and their AWG junk) must ride the carrying endpoint, so the rotation runs
// mid-batch on the send path — the situation that deadlocked the factory when
// it still called Device.Bind() from NextHopEndpoint (the send path holds the
// device net lock in read mode there; Device.Bind() takes the write lock).
//
// The stock gate test above does not exercise this: the harness appends the
// server's concrete endpoint, so data bypasses the carrying port and rotations
// rarely happen mid-batch.
func TestPortAsEndpointRangeOnlyHoppingGate(t *testing.T) {
	//defer goleak.VerifyNone(t)
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234" // client's advertised endpoint
	bRange := "192.168.1.2"  // server's range address

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	// deliberately NO concrete endpoint for b: range only
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
	}

	bIdx := vh.IndexOf("b")
	vh.Central.Routers[bIdx].Endpoints = append(vh.Central.Routers[bIdx].Endpoints,
		bRange+":"+hopTestRange.String())

	// the client runs the hopping policy: rotate after 12 wire packets,
	// short cooldown so the 100-port test range never runs dry
	aIdx := vh.IndexOf("a")
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:    uint32ptr(12),
		CooldownSeconds:  uint32ptr(5),
		RecentPorts:      uint32ptr(32),
		CandidateSamples: uint32ptr(16),
	}

	fwd := vh.AddLinkRange(a1, "b", bRange, hopTestRange).WithFlowBudget(hopTestFlowBudget)
	rev := vh.AddLinkFromAddr(bRange, a1).WithFlowBudget(hopTestFlowBudget)
	_ = rev

	errs := vh.Start()

	vn := vh.Net
	var deliveries atomic.Int64
	var firstDelivery, lastDelivery atomic.Int64
	start := time.Now()
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && src.String() == "10.0.0.1" && dst.String() == "10.0.0.2" && data[0] == 111 {
			now := time.Since(start).Milliseconds()
			firstDelivery.CompareAndSwap(0, now)
			lastDelivery.Store(now)
			deliveries.Add(1)
		}
		return true
	}

	// sustained traffic: 1 packet per 100ms for 15 seconds (150 packets)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 150; i++ {
			select {
			case <-vh.Context.Done():
				return
			case <-time.After(100 * time.Millisecond):
				vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second): // generous: the OLD code deadlocks here
	case err := <-errs:
		t.Fatal(err)
	}
	// let in-flight packets settle
	time.Sleep(500 * time.Millisecond)
	vh.Stop()

	got := deliveries.Load()
	t.Logf("delivered %d/150 packets through the budget middlebox; %d distinct carrying ports",
		got, fwd.DistinctDstPorts())

	if got < 120 {
		t.Errorf("only %d/150 packets were delivered; port hopping failed to sustain traffic", got)
	}
	if ports := fwd.DistinctDstPorts(); ports < 8 {
		t.Errorf("only %d distinct carrying ports were used; rotation is not happening", ports)
	}
	if first, last := firstDelivery.Load(), lastDelivery.Load(); last-first < 10_000 {
		t.Errorf("delivery window was only %d ms; expected sustained delivery for the full run", last-first)
	}
}

// TestPortAsEndpointSinglePortStall is the control for the gate test: with
// the same middlebox but a single static port (no range, no hopping), the
// flow is banned after its budget and delivery stops permanently.
func TestPortAsEndpointSinglePortStall(t *testing.T) {
	//defer goleak.VerifyNone(t)
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234"
	b1 := "192.168.1.2:30000"

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
		b1: "b",
	}

	// single static port with the same per-flow budget, both directions
	vh.AddLink(a1, b1).WithFlowBudget(hopTestFlowBudget)
	vh.AddLink(b1, a1).WithFlowBudget(hopTestFlowBudget)

	errs := vh.Start()

	vn := vh.Net
	var deliveries atomic.Int64
	var lastDelivery atomic.Int64
	start := time.Now()
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && src.String() == "10.0.0.1" && dst.String() == "10.0.0.2" && data[0] == 111 {
			lastDelivery.Store(time.Since(start).Milliseconds())
			deliveries.Add(1)
		}
		return true
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 150; i++ {
			select {
			case <-vh.Context.Done():
				return
			case <-time.After(100 * time.Millisecond):
				vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
	case err := <-errs:
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	vh.Stop()

	got := deliveries.Load()
	last := lastDelivery.Load()
	t.Logf("delivered %d packets on a static port; last delivery at %d ms", got, last)

	// the middlebox bans the only flow after ~16 packets; deliveries must
	// stop permanently within the first few seconds
	if got > 45 {
		t.Errorf("%d packets were delivered through a 16-packet flow budget; the middlebox is not biting", got)
	}
	if last > 8_000 {
		t.Errorf("last delivery at %d ms; expected the static flow to be permanently banned early", last)
	}
}

// TestPortAsEndpointNoGhostLinks pins the ghost-link class of defects found on
// the physical rig: the eager bootstrap drew a carrying port, the device's
// first send then drew a SECOND one, and the bootstrap port's materialised
// link lived on as a healthy ghost — never exhausted (the device never carried
// it), probed at the full 1s cadence forever, and kept alive by the peer's
// symmetric pongs. Ghosts burn budget on stale ports and pin static flows that
// TSPU volume-bans.
//
// Invariants asserted (sampled on the dispatch loop for a consistent view):
//  1. at every instant, every healthy (non-exhausted) factory link is either
//     the current carrying endpoint or a port that was carrying very recently
//     (transitional tombstone states resolve in milliseconds);
//  2. after the traffic stops and the 15s tombstone grace elapses, exactly ONE
//     non-remote link remains: the current carrying endpoint. Ghosts are never
//     reaped, so the pre-fix build accumulates them and fails this count.
func TestPortAsEndpointNoGhostLinks(t *testing.T) {
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234" // client's advertised endpoint
	bRange := "192.168.1.2"  // server's range address
	bPorts := conn.PortRange{First: 30000, Last: 30499}

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	// range only: no concrete endpoint for the server, the rig's shape
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
	}

	bIdx := vh.IndexOf("b")
	vh.Central.Routers[bIdx].Endpoints = append(vh.Central.Routers[bIdx].Endpoints,
		bRange+":"+bPorts.String())

	aIdx := vh.IndexOf("a")
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:    uint32ptr(12),
		CooldownSeconds:  uint32ptr(5),
		RecentPorts:      uint32ptr(32),
		CandidateSamples: uint32ptr(16),
	}

	fwd := vh.AddLinkRange(a1, "b", bRange, bPorts)
	vh.AddLinkFromAddr(bRange, a1)

	errs := vh.Start()
	defer vh.Stop()

	vn := vh.Net
	var deliveries atomic.Int64
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && data[0] == 111 {
			deliveries.Add(1)
		}
		return true
	}

	n := vh.Nylons[aIdx].Load()
	peer := n.Device.LookupPeer(device.NoisePublicKey(vh.Central.Routers[bIdx].PubKey))
	if peer == nil {
		t.Fatal("device peer for the server was not configured")
	}

	// linkSnapshot is collected ON the dispatch loop (consistent view of
	// RouterState while the daemon mutates it).
	type linkSnapshot struct {
		carrying string
		healthy  []string // non-remote, non-exhausted link addresses
	}
	snapshot := func() linkSnapshot {
		ch := make(chan linkSnapshot, 1)
		n.Dispatch(func() error {
			s := linkSnapshot{}
			if st, ok := peer.HopStatus(); ok {
				s.carrying = st.Carrying
			}
			neigh := n.RouterState.GetNeighbour("b")
			if neigh != nil {
				for _, ep := range neigh.Eps {
					if ep.IsRemote() || ep.IsExhausted() {
						continue
					}
					s.healthy = append(s.healthy, ep.AsNylonEndpoint().Address)
				}
			}
			ch <- s
			return nil
		})
		select {
		case s := <-ch:
			return s
		case <-time.After(10 * time.Second):
			t.Fatal("dispatch loop stalled while sampling link state")
			return linkSnapshot{}
		}
	}

	// wait until the hop policy is wired and the first carrying endpoint exists
	deadline := time.Now().Add(15 * time.Second)
	for {
		if s := snapshot(); s.carrying != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no carrying endpoint was drawn within 15s")
		}
		select {
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(200 * time.Millisecond):
		}
	}

	// traffic phase: 12 packets/s through a 12-packet budget rotates the
	// carrying port roughly every second; ~12s of traffic => ~10 rotations
	txStart := time.Now()
	for txStart.Add(12 * time.Second).After(time.Now()) {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled during traffic phase")
		case err := <-errs:
			t.Fatal(err)
		default:
			vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			time.Sleep(100 * time.Millisecond)
		}
	}

	if got := deliveries.Load(); got < 50 {
		t.Errorf("only %d packets were delivered during the traffic phase; port hopping is broken", got)
	}
	if ports := fwd.DistinctDstPorts(); ports < 5 {
		t.Errorf("only %d distinct carrying ports were used; rotation is not happening", ports)
	}

	// invariant 1: while quiescing, every healthy factory link was (very
	// recently) a carrying endpoint — a healthy link that was never carried is
	// a ghost. Track the carrying history over a window comfortably longer
	// than the transitional retire/materialise dispatch gap (milliseconds).
	type sample struct {
		at       time.Time
		carrying string
		healthy  []string
	}
	var samples []sample
	quit := time.Now().Add(16 * time.Second) // > 15s tombstone grace
	for time.Now().Before(quit) {
		select {
		case err := <-errs:
			t.Fatal(err)
		default:
		}
		s := snapshot()
		samples = append(samples, sample{at: time.Now(), carrying: s.carrying, healthy: s.healthy})
		time.Sleep(250 * time.Millisecond)
	}

	// carryLast maps each observed carrying port to the last instant it was
	// carrying; transitional states (tombstone not yet marked exhausted)
	// reference a port that was carrying within the last few samples.
	carryLast := map[string]time.Time{}
	for _, s := range samples {
		if s.carrying != "" {
			carryLast[s.carrying] = s.at
		}
	}
	finalCarrying := samples[len(samples)-1].carrying
	for i, s := range samples {
		for _, h := range s.healthy {
			last, carried := carryLast[h]
			if !carried {
				t.Fatalf("sample %d: healthy link %s was NEVER a carrying endpoint — a ghost link survived (carrying=%s)", i, h, s.carrying)
			}
			// a healthy link may lag the rotation by a dispatch tick (ms), not
			// by seconds: anything still probed > 6s after it last carried is a
			// stale ghost, unless it is the final carrying port itself
			if s.at.Sub(last) > 6*time.Second && h != finalCarrying {
				t.Fatalf("sample %d: healthy link %s was still probed %v after it last carried — a stale ghost", i, h, s.at.Sub(last))
			}
		}
	}

	// invariant 2: after the grace period, the only HEALTHY non-remote link is
	// the current carrying endpoint. Exhausted links may still be present when
	// a rotation happened shortly before the check (idle pong traffic sustains
	// ~one rotation per budget period), but each of them must be a legitimate
	// tombstone of a port that actually carried — never a never-carried ghost.
	neigh := n.RouterState.GetNeighbour("b")
	if neigh == nil {
		t.Fatal("neighbour for the server disappeared")
	}
	var healthy, tombstones []string
	for _, ep := range neigh.Eps {
		if ep.IsRemote() {
			continue
		}
		if ep.IsExhausted() {
			tombstones = append(tombstones, ep.AsNylonEndpoint().Address)
			continue
		}
		healthy = append(healthy, ep.AsNylonEndpoint().Address)
	}
	if len(healthy) != 1 {
		t.Fatalf("after the tombstone grace, %d healthy non-remote links remain (%v); want exactly the current carrying endpoint — ghosts are never reaped", len(healthy), healthy)
	}
	if st, ok := peer.HopStatus(); !ok || st.Carrying != healthy[0] {
		t.Fatalf("the surviving healthy link %v is not the current carrying endpoint (%v)", healthy, st.Carrying)
	}
	for _, tomb := range tombstones {
		if _, carried := carryLast[tomb]; !carried {
			t.Fatalf("an exhausted link for %s was never a carrying endpoint — a tombstone with no rotation behind it", tomb)
		}
	}
}
