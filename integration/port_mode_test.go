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

// portModeRange is the server's port range for the port-mode tests.
var portModeRange = conn.PortRange{First: 30000, Last: 30099}

// portModeRig builds the range-only rig shape (no concrete endpoint for the
// server) shared by the mode tests: client "a" reaching server "b" whose only
// advertised endpoint is the port range.
func portModeRig(t *testing.T) (*VirtualHarness, int, int, *VirtualLink) {
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
		bRange+":"+portModeRange.String())

	fwd := vh.AddLinkRange(a1, "b", bRange, portModeRange)
	vh.AddLinkFromAddr(bRange, a1)

	return vh, vh.IndexOf("a"), bIdx, fwd
}

// portModeDeliveries starts the rig and returns a delivery counter for data
// packets (marker 111) from a to b, plus the error channel.
func portModeDeliveries(vh *VirtualHarness) (*atomic.Int64, *atomic.Int64, chan error) {
	errs := vh.Start()
	var deliveries atomic.Int64
	var lastMs atomic.Int64
	start := time.Now()
	vh.Net.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && data[0] == 111 {
			deliveries.Add(1)
			lastMs.Store(time.Since(start).Milliseconds())
		}
		return true
	}
	return &deliveries, &lastMs, errs
}

// TestPortModeStaticPinsTheRangeStart verifies static mode end to end: the
// client's carrying endpoint is pinned to the first port of the range, the
// device runs without a packet budget (externally driven rotation that never
// fires), and sustained traffic flows on exactly that one port.
func TestPortModeStaticPinsTheRangeStart(t *testing.T) {
	vh, aIdx, bIdx, fwd := portModeRig(t)

	vh.Local[aIdx].PortMode = state.HopModeStatic
	// an explicitly configured budget is meaningless in static mode and must
	// be ignored (not rejected) per the config contract
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets: uint32ptr(12),
	}

	deliveries, _, errs := portModeDeliveries(vh)
	defer vh.Stop()

	// sustained traffic: 1 packet per 100ms for 8 seconds
	for i := 0; i < 80; i++ {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled")
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
			vh.Net.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		}
	}
	time.Sleep(500 * time.Millisecond)

	n := vh.Nylons[aIdx].Load()
	peer := n.Device.LookupPeer(device.NoisePublicKey(vh.Central.Routers[bIdx].PubKey))
	if peer == nil {
		t.Fatal("device peer for the server was not configured")
	}
	st, ok := peer.HopStatus()
	if !ok {
		t.Fatal("hop is not active for the server peer")
	}
	if !st.External || st.Budget != 0 {
		t.Errorf("static mode must run unbudgeted (external rotation), got budget=%d external=%v", st.Budget, st.External)
	}
	if st.Carrying != "192.168.1.2:30000" {
		t.Errorf("static carrying endpoint = %q, want the first port of the range 192.168.1.2:30000", st.Carrying)
	}

	if got := deliveries.Load(); got < 70 {
		t.Errorf("only %d/80 packets delivered through the pinned static port", got)
	}
	if ports := fwd.CarriedPorts(); len(ports) != 1 || ports[0] != 30000 {
		t.Errorf("static mode must carry on exactly the first range port, carried %v", ports)
	}
}

// TestPortModeTimedRotatesOnSchedule verifies timed mode end to end: with
// period_seconds=2 and zero jitter the carrying endpoint rotates roughly
// every two seconds (the 1s reconciliation pass adds up to a second of
// latency), traffic is delivered continuously across rotations, and no other
// rotation trigger exists (no packet budget).
func TestPortModeTimedRotatesOnSchedule(t *testing.T) {
	vh, aIdx, bIdx, fwd := portModeRig(t)

	vh.Local[aIdx].PortMode = state.HopModeTimed
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		PeriodSeconds:   uint32ptr(2),
		PeriodJitterPct: uint32ptr(0),
		CooldownSeconds: uint32ptr(2),
		RecentPorts:     uint32ptr(32),
	}

	deliveries, lastMs, errs := portModeDeliveries(vh)
	defer vh.Stop()

	// sustained traffic: 1 packet per 100ms for 10 seconds => ~5 scheduled
	// rotations at a 2s period
	for i := 0; i < 100; i++ {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled")
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
			vh.Net.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		}
	}
	time.Sleep(500 * time.Millisecond)

	n := vh.Nylons[aIdx].Load()
	peer := n.Device.LookupPeer(device.NoisePublicKey(vh.Central.Routers[bIdx].PubKey))
	if peer == nil {
		t.Fatal("device peer for the server was not configured")
	}
	st, ok := peer.HopStatus()
	if !ok {
		t.Fatal("hop is not active for the server peer")
	}
	if !st.External || st.Budget != 0 {
		t.Errorf("timed mode must run unbudgeted (external rotation), got budget=%d external=%v", st.Budget, st.External)
	}

	if got := deliveries.Load(); got < 90 {
		t.Errorf("only %d/100 packets delivered across timed rotations", got)
	}
	if last := lastMs.Load(); last < 9_000 {
		t.Errorf("delivery stopped at %d ms; timed rotation must not interrupt traffic", last)
	}
	// rotations at ~2s,~4s,~6s,~8s,~10s (plus the initial draw): the middlebox
	// must have seen at least 4 distinct ports, and the pure-schedule mode
	// must not churn anywhere near a packet budget would (12-packet budget at
	// 10 pps + probes would rotate ~10 times in 10s)
	if ports := fwd.DistinctDstPorts(); ports < 4 {
		t.Errorf("only %d distinct carrying ports in 10s at period=2s; the schedule is not firing", ports)
	} else if ports > 8 {
		t.Errorf("%d distinct carrying ports in 10s at period=2s; timed mode is rotating far faster than its schedule", ports)
	}
}

// TestPortModeReactiveRotatesOnDeadCarryingLink verifies reactive mode end to
// end: without a packet budget the client stays on its carrying port while
// the flow lives; when the middlebox bans the flow (16-packet budget, TSPU
// emulation) the carrying link goes dead and ONLY THEN does the client rotate
// to a fresh port and recover. Rotation count stays small compared to the
// proactive mode under the same load.
func TestPortModeReactiveRotatesOnDeadCarryingLink(t *testing.T) {
	vh, aIdx, bIdx, fwd := portModeRig(t)

	// a shorter liveness threshold keeps the death->rotation->recovery cycle
	// inside the test window (the router tunables are shared by the rig)
	tun := state.DefaultRouterTunables()
	tun.LinkDeadThreshold = 2 * time.Second
	vh.Tunables = &tun

	vh.Local[aIdx].PortMode = state.HopModeReactive
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		CooldownSeconds: uint32ptr(2),
		RecentPorts:     uint32ptr(32),
	}

	// the middlebox bans every (client flow, server:port) after 16 packets —
	// the flow carrying the link dies quickly and repeatedly
	fwd.WithFlowBudget(hopTestFlowBudget)

	deliveries, lastMs, errs := portModeDeliveries(vh)
	defer vh.Stop()

	// sustained traffic: 1 packet per 100ms for 18 seconds
	for i := 0; i < 180; i++ {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled")
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
			vh.Net.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		}
	}
	time.Sleep(500 * time.Millisecond)

	n := vh.Nylons[aIdx].Load()
	peer := n.Device.LookupPeer(device.NoisePublicKey(vh.Central.Routers[bIdx].PubKey))
	if peer == nil {
		t.Fatal("device peer for the server was not configured")
	}
	st, ok := peer.HopStatus()
	if !ok {
		t.Fatal("hop is not active for the server peer")
	}
	if !st.External || st.Budget != 0 {
		t.Errorf("reactive mode must run unbudgeted (external rotation), got budget=%d external=%v", st.Budget, st.External)
	}

	// each 16-packet flow lives ~1.6s at 10 pps, then the link needs
	// LinkDeadThreshold (2s) to be declared dead, then the rotation lands on
	// the next reconciliation pass (<=1s): a cycle is ~5s => at least 2
	// rotations and a stream of recovered deliveries in 18s
	if ports := fwd.DistinctDstPorts(); ports < 2 {
		t.Errorf("only %d distinct carrying ports; reactive rotation on the dead carrying link did not happen", ports)
	}
	if got := deliveries.Load(); got < 20 {
		t.Errorf("only %d packets delivered; reactive mode failed to recover after flow bans", got)
	}
	if last := lastMs.Load(); last < 15_000 {
		t.Errorf("delivery stopped at %d ms of an 18s run; recovery after the last ban did not happen", last)
	}
}
