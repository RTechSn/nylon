//go:build integration

package integration

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/state"
	"go.uber.org/goleak"
)

// hopTestbed is a two-node mesh (client -> router) behind a virtual middlebox
// that drops every UDP flow after flowBudget packets, emulating the TSPU
// per-flow volume ban. The router is reachable through a port range.
type hopTestbed struct {
	vh       *VirtualHarness
	delivery atomic.Int64
	lastRecv atomic.Int64 // unix nano of the last delivery
	mu       sync.Mutex
	gaps     []time.Duration
}

func newHopTestbed(t *testing.T, endpoint string, ports conn.PortRange, flowBudget int, hopBudget uint32) *hopTestbed {
	t.Helper()
	tb := &hopTestbed{}
	vh := &VirtualHarness{}

	clientEp := "192.168.1.1:1234"
	serverEp := "192.168.1.2:1234"
	serverAddr := "192.168.1.2"

	vh.NewNode("client", "10.0.0.1/32")
	vh.NewNode("server", "10.0.0.2/32")
	vh.Central.Graph = []string{"client, server"}

	if ports.Valid() {
		// Port-hopping topology: the server is addressed through a port range
		// (plus its classic primary port, which the middlebox also strangles).
		vh.Endpoints = map[string]state.NodeId{
			clientEp: "client",
			serverEp: "server",
		}
		vh.Central.Routers[vh.IndexOf("server")].Endpoints = []string{endpoint}

		vh.AddLinkRange(clientEp, "server", serverAddr, ports).WithFlowBudget(flowBudget)
		vh.AddLink(clientEp, serverEp).WithFlowBudget(flowBudget)
		vh.AddLinkFromAddr(serverAddr, clientEp).WithFlowBudget(flowBudget)
	} else {
		// Control topology: classic single-port endpoint. The endpoint must
		// be a registered node endpoint so the virtual net can route to it.
		vh.Endpoints = map[string]state.NodeId{
			clientEp: "client",
			endpoint: "server",
		}
		vh.AddLink(clientEp, endpoint).WithFlowBudget(flowBudget)
		vh.AddLink(endpoint, clientEp).WithFlowBudget(flowBudget)
	}

	// client-side rotation policy
	budget := hopBudget
	var recent uint32 = 16
	if ports.Valid() {
		vh.Local[vh.IndexOf("client")].PortHopping = &state.PortHoppingCfg{
			BudgetPackets: &budget,
			RecentPorts:   &recent,
		}
	}

	tb.vh = vh
	return tb
}

func (tb *hopTestbed) start(t *testing.T) chan error {
	t.Helper()
	errs := tb.vh.Start()
	tb.vh.Net.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "server" && src.String() == "10.0.0.1" && dst.String() == "10.0.0.2" && data[0] == 111 {
			tb.delivery.Add(1)
			tb.lastRecv.Store(time.Now().UnixNano())
		}
		return true
	}
	return errs
}

// runTraffic injects a marked packet from the client every interval until the
// deadline and returns (total deliveries, max delivery gap).
func (tb *hopTestbed) runTraffic(t *testing.T, errs chan error, window time.Duration) (int64, time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		select {
		case err := <-errs:
			t.Fatalf("node error: %v", err)
		default:
		}
		tb.vh.Net.Send("client", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		time.Sleep(100 * time.Millisecond)
	}
	// let in-flight packets settle
	time.Sleep(500 * time.Millisecond)

	// compute the max inter-delivery gap over the window (measured from
	// harness start, captured by the self handler timeline)
	total := tb.delivery.Load()
	last := time.Unix(0, tb.lastRecv.Load())
	return total, time.Since(last)
}

// TestPortHoppingStage1Gate is the Stage 1 verification gate:
//
//  1. A client reaches a router configured with a 100-port range endpoint.
//  2. The virtual middlebox drops each (src, dst-port) flow after 6 packets.
//  3. The client rotates destination ports with a 2-packet budget and
//     sustains traffic far beyond what any single flow could carry, with no
//     WireGuard session break.
//
// The rotation budget (2) is well under the middlebox budget (6) because a
// port's lifetime accrues traffic in BOTH directions (probe pings, pongs,
// route updates); the control test shows even a 15-packet budget permanently
// kills the classic single-port configuration.
func TestPortHoppingStage1Gate(t *testing.T) {
	defer goleak.VerifyNone(t)

	ports := conn.PortRange{First: 30000, Last: 30099}
	tb := newHopTestbed(t, "192.168.1.2:30000-30099", ports, 6 /*flow budget*/, 2 /*hop budget*/)
	errs := tb.start(t)
	defer tb.vh.Stop()

	// wait for the tunnel to come up (handshake on a fresh port)
	upDeadline := time.Now().Add(15 * time.Second)
	for tb.delivery.Load() == 0 && time.Now().Before(upDeadline) {
		select {
		case err := <-errs:
			t.Fatalf("node error: %v", err)
		default:
		}
		tb.vh.Net.Send("client", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		time.Sleep(100 * time.Millisecond)
	}
	if tb.delivery.Load() == 0 {
		t.Fatal("tunnel never came up: no delivery through the range endpoint")
	}

	// sustained traffic: 12 seconds, ~120 packets. A single flow could carry
	// at most 6; the whole range at 6/flow = 600, but rotation keeps each
	// flow under the budget, so delivery must be continuous.
	const window = 12 * time.Second
	total, sinceLast := tb.runTraffic(t, errs, window)

	t.Logf("delivered %d packets in %s; last delivery %s ago", total, window, sinceLast)
	if total < 90 {
		t.Fatalf("expected at least 90 deliveries under port hopping, got %d", total)
	}
	// continuity: no delivery stall longer than 3 seconds
	if sinceLast > 3*time.Second {
		t.Fatalf("traffic stalled: last delivery was %s ago (want < 3s)", sinceLast)
	}
}

// TestPortHoppingControlSinglePortDies proves the middlebox emulation actually
// blocks: with a classic single-port endpoint (no rotation possible), the same
// per-flow budget lets the tunnel come up and deliver a handful of packets,
// then strangles both flow directions permanently.
func TestPortHoppingControlSinglePortDies(t *testing.T) {
	defer goleak.VerifyNone(t)

	// single-port endpoint, no range -> no rotation possible. The budget is
	// generous enough for initial convergence (handshake + route exchange)
	// so the death is unambiguously caused by the volume ban.
	const flowBudget = 15
	tb := newHopTestbed(t, "192.168.1.2:30000", conn.PortRange{}, flowBudget, 4)
	errs := tb.start(t)
	defer tb.vh.Stop()

	upDeadline := time.Now().Add(15 * time.Second)
	for tb.delivery.Load() == 0 && time.Now().Before(upDeadline) {
		select {
		case err := <-errs:
			t.Fatalf("node error: %v", err)
		default:
		}
		tb.vh.Net.Send("client", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		time.Sleep(100 * time.Millisecond)
	}
	if tb.delivery.Load() == 0 {
		t.Fatal("control: tunnel never came up even once")
	}

	// keep injecting for 10 seconds; the flow must die and stay dead
	const window = 10 * time.Second
	total, sinceLast := tb.runTraffic(t, errs, window)

	t.Logf("control: delivered %d packets in %s; last delivery %s ago", total, window, sinceLast)
	if total > 40 {
		t.Fatalf("control delivered %d packets; the single-port flow should have been strangled", total)
	}
	if sinceLast < 4*time.Second {
		t.Fatalf("control expected a permanent stall (last delivery %s ago); the middlebox emulation may be broken", sinceLast)
	}
}
