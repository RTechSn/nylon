//go:build integration

package integration

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// The per-strategy junk acceptance gate (design §4, stage 4): random-mode
// rotations land the connection on two strategies carrying DIFFERENT junk —
// the configuration the device-global model rejected at seal — and the
// WireGuard session must survive every switch (no device recreation, no
// re-handshake) while data keeps flowing and the per-peer junk hook serves
// each carrying strategy's own spec.
func TestStrategyJunkRotationKeepsSession(t *testing.T) {
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234" // client's advertised endpoint
	bHost := "192.168.1.2"   // server's strategy host
	alphaPorts := conn.PortRange{First: 30000, Last: 30009}
	betaPorts := conn.PortRange{First: 31000, Last: 31009}

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
		bHost+"[alpha,beta]")
	aIdx := vh.IndexOf("a")

	// Two strategies with DIFFERENT junk (the shape per-strategy junk
	// legalised) and identical proactive rotation policies, so sustained
	// traffic rotates across both.
	p := &state.PortHoppingCfg{
		BudgetPackets:    uint32ptr(12),
		CooldownSeconds:  uint32ptr(5),
		RecentPorts:      uint32ptr(32),
		CandidateSamples: uint32ptr(16),
	}
	vh.Central.Obf = &state.CentralObf{
		StrategyMode: state.StrategyModeRandom,
		Strategy: map[string]*state.ObfStrategy{
			"alpha": {
				Ports:           alphaPorts.String(),
				PortHoppingMode: state.HopModeProactive,
				PortHopping:     p,
				Jc:              uint32ptr(2),
				Jmin:            uint32ptr(40),
				Jmax:            uint32ptr(41),
				I1:              "<b 0xc0ff>",
			},
			"beta": {
				Ports:           betaPorts.String(),
				PortHoppingMode: state.HopModeProactive,
				PortHopping:     p,
				Jc:              uint32ptr(1),
				Jmin:            uint32ptr(80),
				Jmax:            uint32ptr(81),
			},
		},
	}

	fwdAlpha := vh.AddLinkRange(a1, "b", bHost, alphaPorts)
	fwdBeta := vh.AddLinkRange(a1, "b", bHost, betaPorts)
	vh.AddLinkFromAddr(bHost, a1)

	errs := vh.Start()
	defer vh.Stop()

	vn := vh.Net
	var deliveries atomic.Int64
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && src.String() == "10.0.0.1" && dst.String() == "10.0.0.2" && data[0] == 111 {
			deliveries.Add(1)
		}
		return true
	}

	n := vh.Nylons[aIdx].Load()
	peer := n.Device.LookupPeer(device.NoisePublicKey(vh.Central.Routers[bIdx].PubKey))
	if peer == nil {
		t.Fatal("device peer for the server was not configured")
	}

	// The hook's live view, sampled ON the dispatch loop: the carrying
	// strategy's label and the junk spec it serves. The mutex only guards
	// the test's read against the dispatch-side writes.
	var mu sync.Mutex
	served := map[string]device.JunkSpec{}
	carrying := ""
	sample := func() {
		ch := make(chan struct{}, 1)
		n.Dispatch(func() error {
			if spec, label, ok := peer.JunkStatus(); ok && label != "" {
				mu.Lock()
				served[label] = spec
				mu.Unlock()
			}
			if hs, ok := peer.HopStatus(); ok {
				mu.Lock()
				carrying = hs.Carrying
				mu.Unlock()
			}
			ch <- struct{}{}
			return nil
		})
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Error("dispatch loop stalled while sampling the junk hook")
		}
	}

	// wait for the first carrying endpoint (the connection established)
	deadline := time.Now().Add(15 * time.Second)
	for {
		sample()
		mu.Lock()
		car := carrying
		mu.Unlock()
		if car != "" {
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

	// the session anchor: once data flows, the handshake timestamp is fixed
	// for the rest of the run (RekeyAfterTime is 120s, far beyond the test)
	deadline = time.Now().Add(15 * time.Second)
	for deliveries.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no data was delivered before the traffic phase")
		}
		vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		time.Sleep(100 * time.Millisecond)
	}
	sessionStart := peer.Status().LatestHandshakeTime().Unix()
	if sessionStart == 0 {
		t.Fatal("no completed handshake after the first delivery")
	}

	// traffic phase: 10 pps for 12s through a 12-packet budget rotates the
	// carrying endpoint roughly every second, alternating strategies under
	// random mode; sample the hook alongside
	txEnd := time.Now().Add(12 * time.Second)
	for time.Now().Before(txEnd) {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled during traffic phase")
		case err := <-errs:
			t.Fatal(err)
		default:
			vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			sample()
			time.Sleep(100 * time.Millisecond)
		}
	}

	// data kept flowing across the switches
	if got := deliveries.Load(); got < 60 {
		t.Errorf("only %d packets were delivered during the traffic phase; the session did not survive the strategy switches", got)
	}

	// rotations happened on BOTH strategies
	if ports := fwdAlpha.DistinctDstPorts(); ports < 2 {
		t.Errorf("only %d distinct carrying ports in alpha's range; rotations are not reaching the alpha strategy", ports)
	}
	if ports := fwdBeta.DistinctDstPorts(); ports < 2 {
		t.Errorf("only %d distinct carrying ports in beta's range; rotations are not reaching the beta strategy", ports)
	}

	// the hook served each carrying strategy's OWN junk
	mu.Lock()
	defer mu.Unlock()
	alphaSpec, alphaSeen := served["alpha"]
	betaSpec, betaSeen := served["beta"]
	if !alphaSeen || !betaSeen {
		t.Fatalf("the junk hook must serve both strategies across the rotations, served: %v", served)
	}
	if alphaSpec != (device.JunkSpec{Jc: 2, Jmin: 40, Jmax: 41, I: [5]string{"<b 0xc0ff>"}}) {
		t.Errorf("alpha's spec: %+v", alphaSpec)
	}
	if betaSpec != (device.JunkSpec{Jc: 1, Jmin: 80, Jmax: 81}) {
		t.Errorf("beta's spec: %+v", betaSpec)
	}
	if len(served) != 2 {
		t.Errorf("unexpected strategies served by the hook: %v", served)
	}

	// the session survived every switch: the peer's handshake is still the
	// original one — no re-handshake, no device recreation
	if end := peer.Status().LatestHandshakeTime().Unix(); end != sessionStart {
		t.Errorf("the session did not survive the strategy switches (re-handshake): %d -> %d", sessionStart, end)
	}
}
