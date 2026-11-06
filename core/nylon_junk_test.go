package core

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// The per-strategy junk fixtures: two strategies over one host — "alpha"
// (30000-30009) carrying a full junk spec and "beta" (31000-31009) junkless —
// the exact shape the per-strategy reform legalised (strategies disagreeing
// on their junk). Every drawn endpoint names its strategy through its port.

// jptr is the pointer helper for the junk knobs.
func jptr(v uint32) *uint32 { return &v }

// junkStrategyNylon builds the hop-fixtures nylon with alpha/beta strategies
// under random mode, alpha carrying a junk spec and beta junkless.
func junkStrategyNylon(t *testing.T, w *bytes.Buffer) *Nylon {
	t.Helper()
	n := newHopFixturesNylonWithLog(t, time.Hour, w)
	n.CentralCfg.Obf = &state.CentralObf{
		StrategyMode: state.StrategyModeRandom,
		Strategy: map[string]*state.ObfStrategy{
			"alpha": {Ports: "30000-30009", Jc: jptr(5), Jmin: jptr(64), Jmax: jptr(320), I1: "<b 0xc0ff>"},
			"beta":  {Ports: "31000-31009"},
		},
	}
	return n
}

// TestPortFactoryJunkFollowsCarryingStrategy pins the hook's core contract:
// the junk spec follows currentStrategy across rotations drawn under random
// mode — alpha's connections speak alpha's junk, beta's (junkless) speak a
// ZERO spec that must not leak the device fallback.
func TestPortFactoryJunkFollowsCarryingStrategy(t *testing.T) {
	var buf bytes.Buffer
	n := junkStrategyNylon(t, &buf)
	f := strategyModeFactory(t, n, "")

	alphaSpec := device.JunkSpec{Jc: 5, Jmin: 64, Jmax: 320, I: [5]string{"<b 0xc0ff>"}}
	want := map[string]device.JunkSpec{"alpha": alphaSpec, "beta": {}}

	ep, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("first draw: %v", err)
	}
	seen := map[string]int{}
	for i := 0; i < 12; i++ {
		strategy := strategyOfAp(ep.DstIPPort())
		if strategy == "" {
			t.Fatalf("draw %d: endpoint outside both ranges: %v", i, ep.DstIPPort())
		}
		seen[strategy]++

		spec, ok := f.JunkFor(nil)
		if !ok {
			t.Fatalf("draw %d: a carrying strategy must resolve its junk (strategy=%s)", i, strategy)
		}
		if spec != want[strategy] {
			t.Fatalf("draw %d (strategy %s): junk %+v, want %+v", i, strategy, spec, want[strategy])
		}
		if label := f.JunkLabel(); label != strategy {
			t.Fatalf("draw %d: label %q, want the carrying strategy %q", i, label, strategy)
		}

		// the rotation: the drawn endpoint becomes the exhausted one
		ep, err = f.NextHopEndpoint(nil, ep)
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("random must rotate across both strategies, saw %v", seen)
	}
}

// TestPortFactoryJunkWiredLive pins the wiring: wireDevPeer installs the
// hook on the device peer (both wire-up paths route through it), and a
// strategy switch needs NO re-wiring — the live consult serves the new
// strategy's junk from the next handshake on.
func TestPortFactoryJunkWiredLive(t *testing.T) {
	var buf bytes.Buffer
	n := junkStrategyNylon(t, &buf)
	f := strategyModeFactory(t, n, "alpha")

	peer, err := n.Device.NewPeer(device.NoisePublicKey(state.GenerateKey().Pubkey()))
	if err != nil {
		t.Fatalf("device peer: %v", err)
	}
	f.wireDevPeer(peer)

	// the hook is live: the consult names alpha and serves its spec
	spec, label, active := peer.JunkStatus()
	if !active {
		t.Fatal("the junk hook must be wired by wireDevPeer")
	}
	if label != "alpha" {
		t.Fatalf("label %q, want alpha", label)
	}
	if spec != (device.JunkSpec{Jc: 5, Jmin: 64, Jmax: 320, I: [5]string{"<b 0xc0ff>"}}) {
		t.Fatalf("alpha spec: %+v", spec)
	}

	// a rotation lands the connection on beta: the live consult serves
	// beta's (zero) spec without any re-wiring
	f.mu.Lock()
	f.currentStrategy = "beta"
	f.mu.Unlock()
	spec, label, _ = peer.JunkStatus()
	if label != "beta" {
		t.Fatalf("after the switch: label %q, want beta", label)
	}
	if spec != (device.JunkSpec{}) {
		t.Fatalf("beta is junkless — the hook must serve its zero spec, got %+v", spec)
	}
}

// TestCarryingStrategySwitchJournalsJunk pins the rotation journal: a
// strategy switch names the junk the new strategy speaks, so the journal
// shows the junk switching with the strategy.
func TestCarryingStrategySwitchJournalsJunk(t *testing.T) {
	var buf bytes.Buffer
	n := junkStrategyNylon(t, &buf)
	f := strategyModeFactory(t, n, "alpha")

	peer, err := n.Device.NewPeer(device.NoisePublicKey(state.GenerateKey().Pubkey()))
	if err != nil {
		t.Fatalf("device peer: %v", err)
	}
	f.mu.Lock()
	f.devPeer = peer
	f.rewireStrategy = "beta"
	f.mu.Unlock()

	f.reconcileLinks()

	out := buf.String()
	if !strings.Contains(out, "carrying strategy switched") {
		t.Fatalf("the switch journal line is missing:\n%s", out)
	}
	if !strings.Contains(out, "junk=none") {
		t.Fatalf("the switch journal must name beta's (junkless) spec:\n%s", out)
	}

	// the same switch onto alpha names alpha's spec (slog quotes values
	// containing spaces)
	buf.Reset()
	f.mu.Lock()
	f.rewireStrategy = "alpha"
	f.mu.Unlock()
	f.reconcileLinks()
	if got := buf.String(); !strings.Contains(got, `junk="jc=5 jmin=64 jmax=320 i1=<b 0xc0ff>"`) {
		t.Fatalf("the switch journal must name alpha's spec:\n%s", got)
	}
}

// junkFallbackNylon builds the hop-fixtures nylon with a configurable obf
// block and a router endpoint naming both strategies, so the node's used set
// is [alpha, beta].
func junkFallbackNylon(t *testing.T, obf *state.CentralObf, w *bytes.Buffer) *Nylon {
	t.Helper()
	n := newHopFixturesNylonWithLog(t, time.Hour, w)
	n.CentralCfg.Obf = obf
	n.CentralCfg.Routers = []state.RouterCfg{{
		NodeCfg:   state.NodeCfg{Id: "b"},
		Endpoints: []string{"192.168.1.2[alpha,beta]"},
	}}
	return n
}

// TestApplyObfDeviceIPCFallbackRendering pins the fallback table of the
// design (§3.3): the device knobs render the AGREED junk when every used
// strategy concurs, the obf-level DEFAULT junk when they disagree, and
// nothing at all without a default — and the "obf strategies applied"
// journal names the provider (the strategy, "defaults", "none"). The
// per-connection junk (the hook) serves the carrying strategy's own spec on
// top of whatever the knobs render.
func TestApplyObfDeviceIPCFallbackRendering(t *testing.T) {
	t.Run("agreed junk renders on the knobs", func(t *testing.T) {
		var buf bytes.Buffer
		n := junkFallbackNylon(t, &state.CentralObf{
			StrategyMode: state.StrategyModeRandom,
			Strategy: map[string]*state.ObfStrategy{
				"alpha": {Ports: "30000-30009", Jc: jptr(5), Jmin: jptr(64), Jmax: jptr(320)},
				"beta":  {Ports: "31000-31009"},
			},
		}, &buf)
		if err := n.applyObfDeviceIPC(); err != nil {
			t.Fatalf("applyObfDeviceIPC: %v", err)
		}
		if out := buf.String(); !strings.Contains(out, "junk=alpha") {
			t.Fatalf("the journal must name the agreeing strategy:\n%s", out)
		}
		dump, err := n.Device.IpcGet()
		if err != nil {
			t.Fatalf("IpcGet: %v", err)
		}
		for _, want := range []string{"jc=5\n", "jmin=64\n", "jmax=320\n"} {
			if !strings.Contains(dump, want) {
				t.Fatalf("the knobs must render the agreed junk; dump missing %q:\n%s", want, dump)
			}
		}
	})

	t.Run("disagreement falls back to the obf default junk", func(t *testing.T) {
		var buf bytes.Buffer
		n := junkFallbackNylon(t, &state.CentralObf{
			StrategyMode: state.StrategyModeRandom,
			Jc:           jptr(2),
			Jmin:         jptr(100),
			Jmax:         jptr(400),
			Strategy: map[string]*state.ObfStrategy{
				"alpha": {Ports: "30000-30009", Jc: jptr(5), Jmin: jptr(64), Jmax: jptr(320)},
				"beta":  {Ports: "31000-31009", Jc: jptr(1), Jmin: jptr(64), Jmax: jptr(320)},
			},
		}, &buf)
		if err := n.applyObfDeviceIPC(); err != nil {
			t.Fatalf("applyObfDeviceIPC: %v", err)
		}
		if out := buf.String(); !strings.Contains(out, "junk=defaults") {
			t.Fatalf("the journal must name the defaults fallback:\n%s", out)
		}
		dump, err := n.Device.IpcGet()
		if err != nil {
			t.Fatalf("IpcGet: %v", err)
		}
		for _, want := range []string{"jc=2\n", "jmin=100\n", "jmax=400\n"} {
			if !strings.Contains(dump, want) {
				t.Fatalf("the knobs must render the default junk; dump missing %q:\n%s", want, dump)
			}
		}
	})

	t.Run("disagreement without a default renders no junk", func(t *testing.T) {
		var buf bytes.Buffer
		n := junkFallbackNylon(t, &state.CentralObf{
			StrategyMode: state.StrategyModeRandom,
			Strategy: map[string]*state.ObfStrategy{
				"alpha": {Ports: "30000-30009", Jc: jptr(5), Jmin: jptr(64), Jmax: jptr(320)},
				"beta":  {Ports: "31000-31009", Jc: jptr(1), Jmin: jptr(64), Jmax: jptr(320)},
			},
		}, &buf)
		if err := n.applyObfDeviceIPC(); err != nil {
			t.Fatalf("applyObfDeviceIPC: %v", err)
		}
		if out := buf.String(); !strings.Contains(out, "junk=none") {
			t.Fatalf("the journal must name the empty fallback:\n%s", out)
		}
		dump, err := n.Device.IpcGet()
		if err != nil {
			t.Fatalf("IpcGet: %v", err)
		}
		if strings.Contains(dump, "jc=") {
			t.Fatalf("no fallback junk must render on the knobs:\n%s", dump)
		}
	})
}
