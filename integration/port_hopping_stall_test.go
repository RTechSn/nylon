//go:build integration

package integration

import (
	"bytes"
	"net/netip"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// TestPortAsEndpointIdleActorStall reproduces a field report from the physical
// test rig: shortly after the first carrying-endpoint rotations, the nylon
// dispatch loop stops consuming (channel len=128, every periodic function is
// discarded) while the process stays alive. The rig ran the deployment shape
// where the server advertises ONLY a port range, and it stalled while idle —
// a handshake retransmit batch rotated mid-batch on the send path and
// deadlocked the factory against the device net lock.
//
// This test runs the same shape (range-only endpoint, hopping policy) through
// an idle phase (retransmit-driven rotations) and a light traffic phase
// (budget-driven rotations), watching BOTH dispatch loops with a heartbeat.
// If a loop stops consuming, all goroutine stacks are dumped to pinpoint the
// blocker.
func TestPortAsEndpointIdleActorStall(t *testing.T) {
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234" // client's advertised endpoint
	bRange := "192.168.1.2"  // server's range address
	bPorts := conn.PortRange{First: 30000, Last: 30499}

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	// range only: no concrete endpoint for the server, exactly like the rig
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
	}

	bIdx := vh.IndexOf("b")
	vh.Central.Routers[bIdx].Endpoints = append(vh.Central.Routers[bIdx].Endpoints,
		bRange+":"+bPorts.String())

	// the client runs the hopping policy from the rig (recent=64, cooldown=180)
	aIdx := vh.IndexOf("a")
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:    uint32ptr(12),
		CooldownSeconds:  uint32ptr(180),
		RecentPorts:      uint32ptr(64),
		CandidateSamples: uint32ptr(16),
	}

	// clean links, NO middlebox budget: the rig stalls on a plain LAN
	vh.AddLinkRange(a1, "b", bRange, bPorts)
	vh.AddLinkFromAddr(bRange, a1)

	errs := vh.Start()
	defer vh.Stop()

	// heartbeat watchdog: a function dispatched to each node's loop must run
	// within the deadline; otherwise dump all goroutine stacks and fail.
	beat := func(name string, idx int) {
		n := vh.Nylons[idx].Load()
		if n == nil {
			return
		}
		hb := make(chan struct{})
		n.Dispatch(func() error {
			close(hb)
			return nil
		})
		select {
		case <-hb:
			return
		case <-vh.Context.Done():
			return
		case <-time.After(10 * time.Second):
			var buf bytes.Buffer
			pprof.Lookup("goroutine").WriteTo(&buf, 2)
			t.Fatalf("node %s: dispatch loop stalled (channel len=%d)\n%s",
				name, len(n.DispatchChannel), buf.String())
		}
	}

	// phase 1: idle — mirrors the rig (handshake retransmits drive rotations)
	idleDeadline := time.After(15 * time.Second)
	for {
		select {
		case <-idleDeadline:
			goto traffic
		case err := <-errs:
			t.Fatal(err)
		default:
			beat("a", aIdx)
			beat("b", bIdx)
			time.Sleep(2 * time.Second)
		}
	}

traffic:
	// phase 2: light traffic to force rotations faster than probes alone
	vn := vh.Net
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		return true // absorb delivered packets
	}
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for i := 0; i < 300; i++ {
			select {
			case <-vh.Context.Done():
				return
			case <-time.After(100 * time.Millisecond):
				vn.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
			}
		}
	}()
	for {
		select {
		case <-sendDone:
			return
		case err := <-errs:
			t.Fatal(err)
		default:
			beat("a", aIdx)
			beat("b", bIdx)
			time.Sleep(2 * time.Second)
		}
	}
}

// hopDeadlockObfProfile is a minimal AWG 2.0 profile (from the field rig): the
// junk packets (jc=5) plus the sender-local I1-I5 make every handshake
// initiation an 11-buffer batch. With a 12-packet rotation budget, a handshake
// that starts with 0 < budget-left < 11 rotates MID-BATCH inside
// Peer.SendBuffers — the exact shape that deadlocked the field rig.
var hopDeadlockObfProfile = state.ObfProfile{
	Jc:   5,
	Jmin: 250,
	Jmax: 800,
	S1:   32,
	S2:   28,
	S3:   20,
	S4:   16,
	H1:   state.ObfHeaderRange{Min: 100, Max: 5000000},
	H2:   state.ObfHeaderRange{Min: 10000000, Max: 200000000},
	H3:   state.ObfHeaderRange{Min: 400000000, Max: 800000000},
	H4:   state.ObfHeaderRange{Min: 1000000000, Max: 2100000000},
}

var hopDeadlockObfA = &state.ObfPeerParams{
	Protocol: "random",
	I1:       "<rd 40><rd 38><r 26><rc 23>",
	I2:       "<rc 21><r 34><r 22><rd 36><r 29>",
	I3:       "<r 25><rd 12><b 0xb249c082c55904a210a6b008><r 37>",
	I4:       "<r 28><b 0xf530397c9e3ec6ffda464d51d200><r 13><b 0xf1f76e9a95afb26b718229><b 0x430ecb5e90aa5cf199f732bd12>",
	I5:       "<b 0x5f54aefac1a012fc79be5488><rd 23><t><r 10><rd 21>",
}

var hopDeadlockObfB = &state.ObfPeerParams{
	Protocol: "random",
	I1:       "<rd 29><r 13><r 23><t>",
	I2:       "<rc 36><t><r 22><b 0x62ca887d><rc 31>",
	I3:       "<rc 5><t><rd 9><r 18><b 0x2d39605eae2f>",
	I4:       "<rc 8><b 0xc58f75cfbf88069660b5c2><rc 28><b 0xbeefc9fb><rd 19><rc 8>",
	I5:       "<b 0x6dc7a7395fca4003c9><rc 18><rc 16><b 0xc3731e29422f9c><b 0x6062a6fb><r 8>",
}

// TestPortAsEndpointMidBatchRotationDeadlock pins the field-rig deadlock:
// the handshake retransmit batch (11 AWG buffers) is larger than the budget
// left on the carrying port, so the rotation happens mid-batch inside
// Peer.SendBuffers, which holds the device net lock in READ mode. A HopSource
// that then acquires Device.Bind() (the device net WRITE lock) self-deadlocks
// and, with it, the whole nylon dispatch loop (SetHop waits for the hop mutex
// that the stuck sender never releases).
//
// The test reproduces the shape deterministically: wire the factory, send one
// handshake initiation (draws a fresh port with a 12 budget and spends 11 on
// the batch), then send another initiation — the batch is now bigger than the
// budget left (1) and must rotate mid-batch. The call must return promptly;
// the buggy build hangs here forever.
func TestPortAsEndpointMidBatchRotationDeadlock(t *testing.T) {
	vh := &VirtualHarness{}

	a1 := "192.168.1.1:1234" // client's advertised endpoint
	bRange := "192.168.1.2"  // server's range address
	bPorts := conn.PortRange{First: 30000, Last: 30499}

	vh.NewNode("a", "10.0.0.1/32")
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
	}

	// AWG profile so handshake initiations are 11-buffer batches (5 junk + 5
	// I-packets + the init itself), like the field rig
	prof := hopDeadlockObfProfile
	vh.Central.Obf = &prof
	bIdx := vh.IndexOf("b")
	aIdx := vh.IndexOf("a")
	vh.Central.Routers[aIdx].Obf = hopDeadlockObfA
	vh.Central.Routers[bIdx].Obf = hopDeadlockObfB
	vh.Central.Routers[bIdx].Endpoints = append(vh.Central.Routers[bIdx].Endpoints,
		bRange+":"+bPorts.String())

	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		BudgetPackets:    uint32ptr(12),
		CooldownSeconds:  uint32ptr(180),
		RecentPorts:      uint32ptr(64),
		CandidateSamples: uint32ptr(16),
	}

	vh.AddLinkRange(a1, "b", bRange, bPorts)
	vh.AddLinkFromAddr(bRange, a1)

	errs := vh.Start()
	defer vh.Stop()

	// resolve the client's device peer for the server
	n := vh.Nylons[vh.IndexOf("a")].Load()
	peer := n.Device.LookupPeer(device.NoisePublicKey(vh.Central.Routers[bIdx].PubKey))
	if peer == nil {
		t.Fatal("device peer for the server was not configured")
	}

	// wait until the hop policy is wired (SyncApplicationState runs within ~1s)
	wired := false
	for range 100 {
		if _, ok := peer.HopStatus(); ok {
			wired = true
			break
		}
		select {
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !wired {
		t.Fatal("hop policy was not wired onto the device peer")
	}

	// 1) one handshake initiation: draws a fresh carrying port (budget 12)
	//    and spends most of it (5 junk + 5 I + init). Probe traffic on the
	//    carrying port also spends budget units, so the exact remainder is
	//    read back from the device instead of assumed.
	done := make(chan error, 1)
	go func() { done <- peer.SendHandshakeInitiation(false) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first SendHandshakeInitiation did not return")
	}
	first, ok := peer.HopStatus()
	if !ok || first.Carrying == "" {
		t.Fatal("no carrying endpoint was drawn")
	}

	// 2) a batch addressed to the carrying port that is exactly one buffer
	//    larger than the remaining budget: the last buffer rotates
	//    MID-BATCH inside Peer.SendBuffers — the exact field-rig deadlock
	//    shape. The call must return promptly; the buggy build hangs here
	//    forever holding the device net read lock and the hop mutex.
	//    In-flight probe traffic can spend budget (or exhaust it, rotating
	//    and refilling) between the HopStatus read and the batch, so the
	//    sized batch is retried until a rotation is observed.
	rotationDeadline := time.Now().Add(20 * time.Second)
	for {
		st, ok := peer.HopStatus()
		if !ok || st.Carrying == "" {
			t.Fatal("carrying endpoint disappeared")
		}
		batchLen := st.BudgetLeft + 1
		if batchLen < 2 {
			batchLen = 2 // keep the multi-buffer mid-batch shape
		}
		batch := make([][]byte, batchLen)
		eps := make([]conn.Endpoint, batchLen)
		ep, err := n.Device.Bind().ParseEndpoint(st.Carrying)
		if err != nil {
			t.Fatalf("failed to parse carrying endpoint %s: %v", st.Carrying, err)
		}
		for i := range batch {
			batch[i] = make([]byte, 64)
			eps[i] = ep
		}
		sent := make(chan error, 1)
		go func() { sent <- peer.SendBuffers(batch, eps) }()
		select {
		case err := <-sent:
			if err != nil {
				t.Fatalf("SendBuffers failed: %v", err)
			}
		case <-time.After(10 * time.Second):
			var buf bytes.Buffer
			pprof.Lookup("goroutine").WriteTo(&buf, 2)
			t.Fatalf("SendBuffers with a mid-batch rotation did not return within 10s — the device net lock self-deadlock is back:\n%s", buf.String())
		}
		after, ok := peer.HopStatus()
		if !ok || after.Carrying == "" {
			t.Fatal("carrying endpoint disappeared after mid-batch rotation")
		}
		if after.Carrying != st.Carrying {
			break // rotated
		}
		if time.Now().After(rotationDeadline) {
			t.Fatalf("carrying endpoint did not rotate (%s); expected a fresh port after the budget was spent", st.Carrying)
		}
	}
}
